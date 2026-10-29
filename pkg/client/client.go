// Package client provides an HTTP client for the Swarf revocation service.
package client

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	jsg "github.com/alanshaw/dag-json-gen"
	"github.com/cenkalti/backoff/v5"
	ucancmd "github.com/fil-forge/libforge/commands/ucan"
	"github.com/fil-forge/swarf/internal/sse"
	"github.com/fil-forge/swarf/pkg/api"
	"github.com/fil-forge/swarf/pkg/store"
	"github.com/fil-forge/ucantone/client"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/execution/batch"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/ipfs/go-cid"
)

// Client publishes and retrieves revocation records from a Swarf service.
type Client struct {
	ServiceID  did.DID
	serviceURL url.URL
	executor   *client.HTTPClient
	httpClient *http.Client
}

// New creates a client for the Swarf service at serviceURL.
func New(serviceID did.DID, serviceURL url.URL, options ...Option) (*Client, error) {
	cfg := clientConfig{httpClient: http.DefaultClient}
	for _, option := range options {
		option(&cfg)
	}
	executor, err := client.NewHTTP(&serviceURL, client.WithHTTPClient(cfg.httpClient))
	if err != nil {
		return nil, fmt.Errorf("creating UCAN HTTP client: %w", err)
	}
	return &Client{
		ServiceID:  serviceID,
		serviceURL: serviceURL,
		executor:   executor,
		httpClient: cfg.httpClient,
	}, nil
}

// PublishOption configures a Publish call.
type PublishOption func(*publishConfig)

type publishConfig struct {
	witnessPath []ucan.Delegation
}

// WithWitnessPath sets the delegation witness path proving the revoker's
// authority over the revoked delegation. The path is ordered root first and
// leads to the revoked delegation, which does not need to be included. A
// witness path is required when the revoker is not the issuer of the revoked
// delegation.
func WithWitnessPath(path ...ucan.Delegation) PublishOption {
	return func(cfg *publishConfig) {
		cfg.witnessPath = path
	}
}

// Publish submits a /ucan/revoke invocation self-signed by revoker for the
// revoked delegation. The revoker must be the issuer of the revoked
// delegation, or an issuer of one of the delegations in the witness path
// provided with [WithWitnessPath].
func (c *Client) Publish(ctx context.Context, revoker ucan.Issuer, revoked ucan.Delegation, options ...PublishOption) error {
	if revoker == nil {
		return errors.New("revoker is required")
	}
	if revoked == nil {
		return errors.New("revoked delegation is required")
	}
	cfg := publishConfig{}
	for _, option := range options {
		option(&cfg)
	}
	path := cfg.witnessPath
	if len(path) > 0 && path[len(path)-1].Link() == revoked.Link() {
		path = path[:len(path)-1]
	}
	witnesses := append(slices.Clone(path), revoked)
	args := &ucancmd.RevokeArguments{Revoke: revoked.Link()}
	if len(path) > 0 {
		args.Path = make([]cid.Cid, len(witnesses))
		for i, delegation := range witnesses {
			args.Path[i] = delegation.Link()
		}
	}
	invocation, err := ucancmd.Revoke.Invoke(
		revoker,
		revoker.DID(),
		args,
		invocation.WithAudience(c.ServiceID),
		invocation.WithNoNonce(),
		invocation.WithNoExpiration(),
	)
	if err != nil {
		return fmt.Errorf("creating revoke invocation: %w", err)
	}
	response, err := c.executor.Execute(execution.NewRequest(ctx, invocation, execution.WithDelegations(witnesses...)))
	if err != nil {
		return fmt.Errorf("publishing revocation: %w", err)
	}
	if _, err := ucancmd.Revoke.Unpack(response.Receipt()); err != nil {
		return fmt.Errorf("unpacking revoke receipt: %w", err)
	}
	return nil
}

// PublishBatch submits one /ucan/revoke invocation per revoked delegation,
// all self-signed by revoker and sent in a single request. The revoker must be
// the issuer of every revoked delegation; no witness path is carried. Every
// invocation must succeed, otherwise the first failure is returned. A repeat of
// the same delegation is a duplicate the service records once.
func (c *Client) PublishBatch(ctx context.Context, revoker ucan.Issuer, revoked []ucan.Delegation) error {
	if revoker == nil {
		return errors.New("revoker is required")
	}
	if len(revoked) == 0 {
		return nil
	}
	invocations := make([]ucan.Invocation, 0, len(revoked))
	for _, d := range revoked {
		if d == nil {
			return errors.New("revoked delegation is required")
		}
		inv, err := ucancmd.Revoke.Invoke(
			revoker,
			revoker.DID(),
			&ucancmd.RevokeArguments{Revoke: d.Link()},
			invocation.WithAudience(c.ServiceID),
			invocation.WithNoNonce(),
			invocation.WithNoExpiration(),
		)
		if err != nil {
			return fmt.Errorf("creating revoke invocation: %w", err)
		}
		invocations = append(invocations, inv)
	}
	response, err := c.executor.ExecuteBatch(batch.NewRequest(ctx, invocations, batch.WithDelegations(revoked...)))
	if err != nil {
		return fmt.Errorf("publishing revocations: %w", err)
	}
	for i, inv := range invocations {
		receipt, ok := response.Receipt(inv.Task().Link())
		if !ok {
			return fmt.Errorf("no receipt for the revocation of %s", revoked[i].Link())
		}
		if _, err := ucancmd.Revoke.Unpack(receipt); err != nil {
			return fmt.Errorf("unpacking revoke receipt: %w", err)
		}
	}
	return nil
}

// Get retrieves the most recent revocation for delegation.
func (c *Client) Get(ctx context.Context, delegationCID cid.Cid) (store.RevocationRecord, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint("revocation", delegationCID.String()), nil)
	if err != nil {
		return store.RevocationRecord{}, fmt.Errorf("creating revocation request: %w", err)
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return store.RevocationRecord{}, fmt.Errorf("getting revocation: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return store.RevocationRecord{}, store.ErrNotFound
	}
	if response.StatusCode != http.StatusOK {
		return store.RevocationRecord{}, fmt.Errorf("getting revocation: unexpected status %s", response.Status)
	}
	var record api.Revocation
	if err := record.UnmarshalDagJSON(response.Body); err != nil {
		return store.RevocationRecord{}, fmt.Errorf("decoding revocation record: %w", err)
	}
	return decodeRecord(record)
}

// Cursor is a position in the revocation firehose, which the service sends
// with each revocation. Its form is the service's own and opaque: store one,
// and pass it back to StreamAfter to resume after that revocation.
type Cursor string

// Now is the cursor at the head of the firehose, as the service sees it when
// the stream opens.
const Now Cursor = "now"

// Event is a firehose revocation and the cursor that resumes the firehose
// after it.
type Event struct {
	Revocation api.FirehoseRevocation
	Cursor     Cursor
}

// Reconnect backoff bounds: the exponential backoff's initial interval and
// its cap (growth and jitter use the backoff package's defaults). The backoff
// resets whenever a connection is established, so it only grows while the
// service is unreachable.
const (
	streamMinBackoff = time.Second
	streamMaxBackoff = time.Minute
)

// errStreamStopped signals the stream consumer stopped iterating.
var errStreamStopped = errors.New("revocation stream stopped")

// ErrCursorRefused reports that the service refused a stream's cursor as one
// it cannot have issued, because it is ahead of the service's head: a cursor
// from before the service's database moved to another server, say. Resuming
// after it again cannot succeed.
var ErrCursorRefused = errors.New("revocation service refused the stream cursor")

// connectError reports a stream connection that was never established.
type connectError struct{ err error }

func (e connectError) Error() string { return e.err.Error() }
func (e connectError) Unwrap() error { return e.err }

// corruptError reports a stream payload that could not be decoded;
// reconnecting would only fetch it again.
type corruptError struct{ err error }

func (e corruptError) Error() string { return e.err.Error() }
func (e corruptError) Unwrap() error { return e.err }

// Stream yields firehose revocations recorded on or after from, or every
// revocation if from is zero, and remains open until ctx is canceled,
// reconnecting with capped exponential backoff when the stream is
// interrupted. A reconnect resumes after the last revocation the call
// delivered, so a call yields each revocation once, and never one recorded
// before from. Moving the service's database with a dump and restore, or
// with logical replication, voids that position, though: a call open across
// the move can then repeat or skip revocations, and has to be started over
// (see Swarf's README).
//
// Revocations do not reach the firehose in recorded_at order, so a new call
// from the timestamp of the last revocation a previous call delivered can miss
// revocations recorded earlier that reached the firehose later. To resume
// across calls, use StreamAfter.
func (c *Client) Stream(ctx context.Context, from time.Time) iter.Seq2[api.FirehoseRevocation, error] {
	return func(yield func(api.FirehoseRevocation, error) bool) {
		for event, err := range c.StreamEvents(ctx, from) {
			if !yield(event.Revocation, err) {
				return
			}
		}
	}
}

// StreamEvents is Stream, yielding each revocation with its cursor, so a
// consumer that starts with a time query can resume with StreamAfter.
func (c *Client) StreamEvents(ctx context.Context, from time.Time) iter.Seq2[Event, error] {
	position := "0"
	if !from.IsZero() {
		position = from.UTC().Format(time.RFC3339Nano)
	}
	return c.stream(ctx, c.endpoint("revocations", position))
}

// StreamAfter yields the firehose revocations after cursor, each with its own
// cursor, and remains open until ctx is canceled, reconnecting as Stream
// does. Pass the cursor of an Event a previous call yielded to resume after
// that revocation, or Now to start at the head of the firehose.
//
// A call yields each revocation once, and a call resuming after the cursor of
// the last revocation a consumer applied misses nothing. A consumer that
// stores its cursor less often than it applies revocations has some
// re-delivered when it resumes; dedupe those by Cause.
//
// The service refuses a cursor ahead of its head, which it cannot have
// issued, and the stream then ends with an error wrapping ErrCursorRefused.
// Not every cursor from before a dump and restore, or a logical replication,
// of the service's database is ahead of the head, though, so such a move still
// calls for resetting every consumer, a call open across the move included
// (see Swarf's README). Starting over from Now skips the revocations that
// reached the firehose after the consumer's last one; StreamEvents from a time
// well before that one's RecordedAt, or from zero, deduped by Cause, does not.
func (c *Client) StreamAfter(ctx context.Context, after Cursor) iter.Seq2[Event, error] {
	if after == "" {
		return func(yield func(Event, error) bool) {
			yield(Event{}, errors.New("cursor is required"))
		}
	}
	return c.stream(ctx, c.endpoint("revocations", "after", string(after)))
}

// stream follows the firehose at endpoint until ctx is canceled, reconnecting
// with capped exponential backoff when it is interrupted. Each reconnect sends
// the id of the last event the service sent as Last-Event-ID, so the service
// resumes after it, still serving only what endpoint selects. It ends with an
// error when the first connection fails or the service refuses the cursor.
func (c *Client) stream(ctx context.Context, endpoint string) iter.Seq2[Event, error] {
	return func(yield func(Event, error) bool) {
		var lastEventID Cursor
		connected := false
		bo := backoff.NewExponentialBackOff()
		bo.InitialInterval = streamMinBackoff
		bo.MaxInterval = streamMaxBackoff
		for {
			err := c.streamConn(ctx, endpoint, &lastEventID, func(event Event) bool {
				return yield(event, nil)
			})
			if errors.Is(err, errStreamStopped) {
				return
			}
			if ctx.Err() != nil {
				yield(Event{}, ctx.Err())
				return
			}
			if _, ok := errors.AsType[corruptError](err); ok {
				yield(Event{}, err)
				return
			}
			if _, ok := errors.AsType[connectError](err); ok {
				// Failing to connect at all is fatal, and so is a refused
				// cursor; failing to reconnect an established stream
				// otherwise is retried like any interruption.
				if !connected || errors.Is(err, ErrCursorRefused) {
					yield(Event{}, err)
					return
				}
			} else {
				connected = true
				bo.Reset()
			}

			select {
			case <-ctx.Done():
				yield(Event{}, ctx.Err())
				return
			case <-time.After(bo.NextBackOff()):
			}
		}
	}
}

// streamConn opens one SSE connection to endpoint, sending *lastEventID as
// Last-Event-ID if it is set, and emits its revocations. It leaves
// *lastEventID at the last event ID the service sent, if it sent one. It
// returns errStreamStopped when emit stops iteration, a connectError when no
// stream was established, a corruptError for a payload that is undecodable or
// larger than sse.MaxEventBytes, and nil when an established connection ended
// for any other reason.
func (c *Client) streamConn(ctx context.Context, endpoint string, lastEventID *Cursor, emit func(Event) bool) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return connectError{fmt.Errorf("creating revocation stream request: %w", err)}
	}
	request.Header.Set("Accept", "text/event-stream")
	if *lastEventID != "" {
		request.Header.Set("Last-Event-ID", string(*lastEventID))
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return connectError{fmt.Errorf("opening revocation stream: %w", err)}
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusConflict {
		return connectError{fmt.Errorf("opening revocation stream: %w (%s)", ErrCursorRefused, response.Status)}
	}
	if response.StatusCode != http.StatusOK {
		return connectError{fmt.Errorf("opening revocation stream: unexpected status %s", response.Status)}
	}

	events := sse.NewScanner(response.Body)
	// The last event ID can come from an event Scan does not report: the
	// service sends one with no data when a stream starts at Now.
	defer func() {
		if id := events.ID(); id != "" {
			*lastEventID = Cursor(id)
		}
	}()
	for events.Scan() {
		if events.Event() != "revocation" {
			continue
		}
		var value api.FirehoseRevocation
		if err := value.UnmarshalDagJSON(strings.NewReader(events.Data())); err != nil {
			return corruptError{fmt.Errorf("decoding streamed revocation: %w", err)}
		}
		if !emit(Event{Revocation: value, Cursor: Cursor(events.ID())}) {
			return errStreamStopped
		}
	}
	// A read error usually means the stream was interrupted, and the caller
	// reconnects. An oversized event is not that: it is still there at the same
	// cursor, so reconnecting hits it again forever -- the record is never
	// yielded and no error is ever returned, which presents as a hang rather
	// than a failure. Report it as corrupt so Stream surfaces it and stops.
	if err := events.Err(); errors.Is(err, sse.ErrEventTooLong) {
		return corruptError{fmt.Errorf("streamed revocation exceeds %d bytes", sse.MaxEventBytes)}
	}
	return nil
}

func (c *Client) endpoint(parts ...string) string {
	base := strings.TrimRight(c.serviceURL.String(), "/")
	escaped := make([]string, len(parts))
	for i, part := range parts {
		escaped[i] = url.PathEscape(part)
	}
	return base + "/" + strings.Join(escaped, "/")
}

func decodeRecord(value api.Revocation) (store.RevocationRecord, error) {
	cause, err := invocation.Decode(value.Cause)
	if err != nil {
		return store.RevocationRecord{}, fmt.Errorf("decoding revocation cause: %w", err)
	}
	path := make([]ucan.Delegation, len(value.Path))
	for i, bytes := range value.Path {
		path[i], err = delegation.Decode(bytes)
		if err != nil {
			return store.RevocationRecord{}, fmt.Errorf("decoding delegation at path index %d: %w", i, err)
		}
	}
	return store.RevocationRecord{
		Revoke:     value.Revoke,
		Cause:      cause,
		Path:       path,
		RecordedAt: jsg.DagJsonTime(value.RecordedAt).Time(),
	}, nil
}

type clientConfig struct {
	httpClient *http.Client
}

// Option configures a Client.
type Option func(*clientConfig)

// WithHTTPClient uses httpClient for retrieval and UCAN RPC requests.
func WithHTTPClient(httpClient *http.Client) Option {
	return func(cfg *clientConfig) {
		cfg.httpClient = httpClient
	}
}
