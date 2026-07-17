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
	"strings"
	"time"

	jsg "github.com/alanshaw/dag-json-gen"
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
	Issuer     ucan.Issuer
	serviceURL url.URL
	executor   execution.Executor
	httpClient *http.Client
}

// New creates a client for the Swarf service at serviceURL.
func New(serviceID did.DID, serviceURL url.URL, issuer ucan.Issuer, options ...Option) (*Client, error) {
	if issuer == nil {
		return nil, errors.New("issuer is required")
	}
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
		Issuer:     issuer,
		serviceURL: serviceURL,
		executor:   executor,
		httpClient: cfg.httpClient,
	}, nil
}

// Publish submits a self-signed /ucan/revoke invocation for revoked using path
// as its delegation witness.
func (c *Client) Publish(ctx context.Context, revoked cid.Cid, path []ucan.Delegation) error {
	if len(path) == 0 {
		return errors.New("revocation path must contain the revoked delegation")
	}
	if path[len(path)-1].Link() != revoked {
		return errors.New("revocation path must end with the revoked delegation")
	}
	links := make([]cid.Cid, len(path))
	for i, delegation := range path {
		links[i] = delegation.Link()
	}
	invocation, err := ucancmd.Revoke.Invoke(
		c.Issuer,
		c.Issuer.DID(),
		&ucancmd.RevokeArguments{Revoke: revoked, Path: links},
		invocation.WithAudience(c.ServiceID),
		invocation.WithNoNonce(),
		invocation.WithNoExpiration(),
	)
	if err != nil {
		return fmt.Errorf("creating revoke invocation: %w", err)
	}
	response, err := c.executor.Execute(execution.NewRequest(ctx, invocation, execution.WithDelegations(path...)))
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

// Stream yields firehose revocations created after since until ctx is canceled.
func (c *Client) Stream(ctx context.Context, since time.Time) iter.Seq2[api.FirehoseRevocation, error] {
	return func(yield func(api.FirehoseRevocation, error) bool) {
		cursor := "0"
		if !since.IsZero() {
			cursor = since.Format(time.RFC3339Nano)
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint("revocations", cursor), nil)
		if err != nil {
			yield(api.FirehoseRevocation{}, fmt.Errorf("creating revocation stream request: %w", err))
			return
		}
		request.Header.Set("Accept", "text/event-stream")
		response, err := c.httpClient.Do(request)
		if err != nil {
			if ctx.Err() != nil {
				yield(api.FirehoseRevocation{}, ctx.Err())
			} else {
				yield(api.FirehoseRevocation{}, fmt.Errorf("opening revocation stream: %w", err))
			}
			return
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			yield(api.FirehoseRevocation{}, fmt.Errorf("opening revocation stream: unexpected status %s", response.Status))
			return
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
						yield(api.FirehoseRevocation{}, fmt.Errorf("decoding streamed revocation: %w", err))
						return
					}
					if !yield(value, nil) {
						return
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
		if err := scanner.Err(); err != nil {
			if ctx.Err() != nil {
				yield(api.FirehoseRevocation{}, ctx.Err())
			} else {
				yield(api.FirehoseRevocation{}, fmt.Errorf("reading revocation stream: %w", err))
			}
		}
	}
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
		Revoke:    value.Revoke,
		Cause:     cause,
		Path:      path,
		CreatedAt: jsg.DagJsonTime(value.CreatedAt).Time(),
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
