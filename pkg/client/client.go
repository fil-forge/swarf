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

// Stream yields firehose revocations recorded on or after from and remains
// open until ctx is canceled, reconnecting with capped exponential backoff
// when the stream is interrupted.
// It resumes from the timestamp of the last record it delivered and skips
// records sharing that timestamp it already delivered, so a single call
// yields each revocation once. A new call resuming from the timestamp of the
// last record a previous call delivered still re-receives records recorded
// at exactly that time; dedupe those by cause CID.
func (c *Client) Stream(ctx context.Context, from time.Time) iter.Seq2[api.FirehoseRevocation, error] {
	return func(yield func(api.FirehoseRevocation, error) bool) {
		resume := from
		// seen holds the cause CIDs of delivered records recorded at exactly
		// resume, so reconnecting at resume does not re-deliver them.
		seen := map[cid.Cid]struct{}{}
		connected := false
		bo := backoff.NewExponentialBackOff()
		bo.InitialInterval = streamMinBackoff
		bo.MaxInterval = streamMaxBackoff
		for {
			err := c.streamConn(ctx, resume, func(record api.FirehoseRevocation) bool {
				recordedAt := record.RecordedAt.Time()
				if recordedAt.Equal(resume) {
					if _, ok := seen[record.Cause]; ok {
						return true
					}
				} else {
					resume = recordedAt
					clear(seen)
				}
				seen[record.Cause] = struct{}{}
				return yield(record, nil)
			})
			if errors.Is(err, errStreamStopped) {
				return
			}
			if ctx.Err() != nil {
				yield(api.FirehoseRevocation{}, ctx.Err())
				return
			}
			if _, ok := errors.AsType[corruptError](err); ok {
				yield(api.FirehoseRevocation{}, err)
				return
			}
			if _, ok := errors.AsType[connectError](err); ok {
				// Failing to connect at all is fatal; failing to reconnect
				// an established stream is retried like any interruption.
				if !connected {
					yield(api.FirehoseRevocation{}, err)
					return
				}
			} else {
				connected = true
				bo.Reset()
			}

			select {
			case <-ctx.Done():
				yield(api.FirehoseRevocation{}, ctx.Err())
				return
			case <-time.After(bo.NextBackOff()):
			}
		}
	}
}

// streamConn opens one SSE connection at from and emits its records. It
// returns errStreamStopped when emit stops iteration, a connectError when no
// stream was established, a corruptError for an undecodable payload, and nil
// when an established connection ended for any other reason.
func (c *Client) streamConn(ctx context.Context, from time.Time, emit func(api.FirehoseRevocation) bool) error {
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
			if event == "revocation" && len(data) > 0 {
				var value api.FirehoseRevocation
				if err := value.UnmarshalDagJSON(strings.NewReader(strings.Join(data, "\n"))); err != nil {
					return corruptError{fmt.Errorf("decoding streamed revocation: %w", err)}
				}
				if !emit(value) {
					return errStreamStopped
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
