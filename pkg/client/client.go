// Package client provides an HTTP client for the Swarf revocation service.
package client

import (
	"bufio"
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
	principalcmd "github.com/fil-forge/libforge/commands/principal"
	ucancmd "github.com/fil-forge/libforge/commands/ucan"
	"github.com/fil-forge/swarf/pkg/api"
	"github.com/fil-forge/swarf/pkg/store"
	"github.com/fil-forge/ucantone/client"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/ipfs/go-cid"
)

// Client publishes and retrieves revocation records from a Swarf service.
type Client struct {
	ServiceID  did.DID
	serviceURL url.URL
	executor   execution.Executor
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

// Invalidate submits a /principal/invalidate invocation self-signed by
// issuer, recording that every proof a gateway cached for the principal's
// keys is void. Swarf accepts the command only from issuers in its publisher
// list, so issuer must be a service identity that list holds.
func (c *Client) Invalidate(ctx context.Context, issuer ucan.Issuer, tenant did.DID, principal string) error {
	if issuer == nil {
		return errors.New("issuer is required")
	}
	if !tenant.Defined() {
		return errors.New("tenant is required")
	}
	if principal == "" {
		return errors.New("principal is required")
	}
	// The nonce stays (a fresh random one per invocation): the service keys
	// its records by the invocation CID and consumers dedupe by it, so two
	// invalidations of the same principal must not share one. Without a
	// nonce, an expiry or an issued-at, the CID would be a pure function of
	// issuer, tenant and principal, and every repeat would be dropped.
	invalidation, err := principalcmd.Invalidate.Invoke(
		issuer,
		issuer.DID(),
		&principalcmd.InvalidateArguments{Tenant: tenant, Principal: principal},
		invocation.WithAudience(c.ServiceID),
		invocation.WithNoExpiration(),
	)
	if err != nil {
		return fmt.Errorf("creating invalidate invocation: %w", err)
	}
	response, err := c.executor.Execute(execution.NewRequest(ctx, invalidation))
	if err != nil {
		return fmt.Errorf("publishing principal invalidation: %w", err)
	}
	if _, err := principalcmd.Invalidate.Unpack(response.Receipt()); err != nil {
		return fmt.Errorf("unpacking invalidate receipt: %w", err)
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

// connectError reports a stream connection that was never established.
type connectError struct{ err error }

func (e connectError) Error() string { return e.err.Error() }
func (e connectError) Unwrap() error { return e.err }

// corruptError reports a stream payload that could not be decoded;
// reconnecting would only fetch it again.
type corruptError struct{ err error }

func (e corruptError) Error() string { return e.err.Error() }
func (e corruptError) Unwrap() error { return e.err }

// streamSettleWindow bounds how far behind the newest record a late record
// may be recorded. It matches the window the service settles its history
// over, so a cause delivered within it stays in the dedup set for as long as
// a reconnect could re-deliver it.
const streamSettleWindow = 10 * time.Second

// StreamEvents yields firehose events recorded on or after from and remains
// open until ctx is canceled, reconnecting with capped exponential backoff
// when the stream is interrupted.
// It tracks the newest timestamp it has delivered and, on reconnect, asks
// for records from one settle window before it, skipping causes it already
// delivered, so a single call yields each event once even when a record
// recorded inside the settle window arrives behind newer ones or lands while
// the connection is down. A new call resuming from the timestamp of the last
// event a previous call delivered still re-receives events recorded at
// exactly that time; dedupe those by cause CID.
func (c *Client) StreamEvents(ctx context.Context, from time.Time) iter.Seq2[api.FirehoseEvent, error] {
	return func(yield func(api.FirehoseEvent, error) bool) {
		// resume is the newest recorded time delivered so far and never moves
		// backwards: a late record must not send the next connection back to
		// a cursor whose newer records were already delivered. A reconnect
		// asks from one settle window before it (bounded by from), because a
		// record committed late inside that window may not have been served
		// yet when the connection dropped.
		resume := from
		// seen holds the recorded time of each delivered cause, so a
		// reconnect does not re-deliver them. Causes recorded before the
		// settle window behind resume can no longer be re-delivered and are
		// pruned.
		seen := map[cid.Cid]time.Time{}
		connected := false
		bo := backoff.NewExponentialBackOff()
		bo.InitialInterval = streamMinBackoff
		bo.MaxInterval = streamMaxBackoff
		for {
			since := resume
			if resume.After(from) {
				since = resume.Add(-streamSettleWindow)
				if since.Before(from) {
					since = from
				}
			}
			err := c.streamConn(ctx, since, func(event api.FirehoseEvent) bool {
				cause := event.Cause()
				if _, ok := seen[cause]; ok {
					return true
				}
				recordedAt := event.RecordedAt().Time()
				seen[cause] = recordedAt
				if recordedAt.After(resume) {
					resume = recordedAt
					horizon := resume.Add(-streamSettleWindow)
					for link, at := range seen {
						if at.Before(horizon) {
							delete(seen, link)
						}
					}
				}
				return yield(event, nil)
			})
			if errors.Is(err, errStreamStopped) {
				return
			}
			if ctx.Err() != nil {
				yield(api.FirehoseEvent{}, ctx.Err())
				return
			}
			if _, ok := errors.AsType[corruptError](err); ok {
				yield(api.FirehoseEvent{}, err)
				return
			}
			if _, ok := errors.AsType[connectError](err); ok {
				// Failing to connect at all is fatal; failing to reconnect
				// an established stream is retried like any interruption.
				if !connected {
					yield(api.FirehoseEvent{}, err)
					return
				}
			} else {
				connected = true
				bo.Reset()
			}

			select {
			case <-ctx.Done():
				yield(api.FirehoseEvent{}, ctx.Err())
				return
			case <-time.After(bo.NextBackOff()):
			}
		}
	}
}

// Stream yields the revocations of [Client.StreamEvents].
//
// Deprecated: use [Client.StreamEvents]. Stream drops principal events, so a
// consumer that must forget the proofs it cached for a principal's keys never
// learns of them.
func (c *Client) Stream(ctx context.Context, from time.Time) iter.Seq2[api.FirehoseRevocation, error] {
	return func(yield func(api.FirehoseRevocation, error) bool) {
		for event, err := range c.StreamEvents(ctx, from) {
			if err != nil {
				if !yield(api.FirehoseRevocation{}, err) {
					return
				}
				continue
			}
			if event.Revocation == nil {
				continue
			}
			if !yield(*event.Revocation, nil) {
				return
			}
		}
	}
}

// streamConn opens one SSE connection at from and emits its events. Events
// it does not know are skipped. It returns errStreamStopped when emit stops
// iteration, a connectError when no stream was established, a corruptError
// for an undecodable payload, and nil when an established connection ended
// for any other reason.
func (c *Client) streamConn(ctx context.Context, from time.Time, emit func(api.FirehoseEvent) bool) error {
	cursor := "0"
	if !from.IsZero() {
		cursor = from.UTC().Format(time.RFC3339Nano)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint("revocations", cursor), nil)
	if err != nil {
		return connectError{fmt.Errorf("creating revocation stream request: %w", err)}
	}
	request.Header.Set("Accept", "text/event-stream")
	response, err := c.httpClient.Do(request)
	if err != nil {
		return connectError{fmt.Errorf("opening revocation stream: %w", err)}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return connectError{fmt.Errorf("opening revocation stream: unexpected status %s", response.Status)}
	}

	scanner := bufio.NewScanner(response.Body)
	var event string
	var data []string
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if len(data) > 0 {
				payload := strings.Join(data, "\n")
				switch event {
				case string(store.EventKindRevocation):
					var value api.FirehoseRevocation
					if err := value.UnmarshalDagJSON(strings.NewReader(payload)); err != nil {
						return corruptError{fmt.Errorf("decoding streamed revocation: %w", err)}
					}
					if !emit(api.FirehoseEvent{Revocation: &value}) {
						return errStreamStopped
					}
				case string(store.EventKindPrincipalRevocation):
					var value api.FirehosePrincipalRevocation
					if err := value.UnmarshalDagJSON(strings.NewReader(payload)); err != nil {
						return corruptError{fmt.Errorf("decoding streamed principal invalidation: %w", err)}
					}
					if !emit(api.FirehoseEvent{PrincipalRevocation: &value}) {
						return errStreamStopped
					}
				}
			}
			event = ""
			data = nil
			continue
		}
		if value, ok := strings.CutPrefix(line, "event:"); ok {
			event = strings.TrimSpace(value)
		}
		if value, ok := strings.CutPrefix(line, "data:"); ok {
			data = append(data, strings.TrimPrefix(value, " "))
		}
	}
	// A read error means the stream was interrupted; the caller reconnects.
	_ = scanner.Err()
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
