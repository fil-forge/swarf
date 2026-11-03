package fx

import (
	"context"
	"errors"
	"iter"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	ucancmd "github.com/fil-forge/libforge/commands/ucan"
	"github.com/fil-forge/libforge/identity"
	"github.com/fil-forge/swarf/pkg/api"
	"github.com/fil-forge/swarf/pkg/store"
	"github.com/fil-forge/swarf/pkg/store/memory"
	"github.com/fil-forge/ucantone/client"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/did/key"
	"github.com/fil-forge/ucantone/did/resolver"
	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/execution/batch"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/fil-forge/ucantone/validator"
	"github.com/ipfs/go-cid"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestEchoPublicRoutes(t *testing.T) {
	id, err := identity.New("", "")
	require.NoError(t, err)
	e := newEchoServer(id, server.NewHTTP(id), memory.New())

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	response := httptest.NewRecorder()
	e.ServeHTTP(response, request)
	require.Equal(t, http.StatusOK, response.Code)

	require.Contains(t, response.Body.String(), "swarf")

	request = httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Accept", "application/json")
	response = httptest.NewRecorder()
	e.ServeHTTP(response, request)
	require.Equal(t, http.StatusOK, response.Code)
	require.Contains(t, response.Body.String(), `"id"`)

	request = httptest.NewRequest(http.MethodGet, "/.well-known/did.json", nil)
	response = httptest.NewRecorder()
	e.ServeHTTP(response, request)
	require.Equal(t, http.StatusOK, response.Code)
}

// A handler panic must not escape to net/http, which drops the connection
// without ever writing a response.
func TestAHandlerPanicBecomesAServerError(t *testing.T) {
	id, err := identity.New("", "")
	require.NoError(t, err)
	e := newEchoServer(id, server.NewHTTP(id), memory.New())
	e.GET("/panic", func(echo.Context) error { panic("handler exploded") })

	response := httptest.NewRecorder()
	require.NotPanics(t, func() {
		e.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/panic", nil))
	})
	require.Equal(t, http.StatusInternalServerError, response.Code)
}

func TestParseFrom(t *testing.T) {
	from, err := parseFrom("0")
	require.NoError(t, err)
	require.True(t, from.IsZero())
	_, err = parseFrom("not-a-timestamp")
	require.Error(t, err)
}

func TestFirehoseRouteStreamsRecords(t *testing.T) {
	id, err := identity.New("", "")
	require.NoError(t, err)
	command, err := command.Parse("/test/revoke")
	require.NoError(t, err)
	revocation, err := invocation.Invoke(id, did.Undef, command, nil)
	require.NoError(t, err)
	witness, err := delegation.Delegate(id, did.Undef, id.DID(), command)
	require.NoError(t, err)
	recordedAt := time.Now().UTC().Round(0)
	source := &firehoseTestStore{
		record: store.RevocationRecord{Revoke: witness.Link(), Cause: revocation, Path: []ucan.Delegation{witness}, RecordedAt: recordedAt},
	}
	e := newEchoServer(id, server.NewHTTP(id), source)
	request := httptest.NewRequest(http.MethodGet, "/revocations/"+recordedAt.Format(time.RFC3339Nano), nil)
	response := httptest.NewRecorder()
	e.ServeHTTP(response, request)

	require.Equal(t, http.StatusOK, response.Code)
	require.Equal(t, "text/event-stream", response.Header().Get(echo.HeaderContentType))
	require.Contains(t, response.Body.String(), "event: revocation")
	require.Equal(t, recordedAt, source.from)
	data := strings.TrimSuffix(strings.TrimPrefix(response.Body.String(), "id: "+revocation.Link().String()+"\nevent: revocation\ndata: "), "\n\n")
	var event api.FirehoseRevocation
	require.NoError(t, event.UnmarshalDagJSON(strings.NewReader(data)))
	require.Equal(t, witness.Link(), event.Revoke)
	require.Equal(t, []cid.Cid{witness.Link()}, event.Path)
	require.Equal(t, revocation.Link(), event.Cause)
	require.True(t, event.RecordedAt.Time().Equal(recordedAt))
	require.NotContains(t, response.Body.String(), `"revocation"`)
}

// A store failure mid-stream has to reach whatever reports errors. The
// response commits 200 before the first record, so the status can never carry
// the failure -- the error the handler returns is the only thing an error
// handler or a request logger ever sees, and on nil a failed stream is
// indistinguishable from a clean one.
func TestFirehoseRouteReportsAStoreFailure(t *testing.T) {
	id, err := identity.New("", "")
	require.NoError(t, err)
	source := &firehoseTestStore{err: errors.New("getting revocations: connection refused")}
	e := newEchoServer(id, server.NewHTTP(id), source)
	logged := observeRequests(e)

	response := httptest.NewRecorder()
	e.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/revocations/0", nil))

	require.ErrorContains(t, logged().Error, "getting revocations: connection refused",
		"a store failure was invisible to the request logger")
	require.Equal(t, http.StatusOK, logged().Status,
		"the status is committed before the stream and cannot report this")
	require.Contains(t, response.Body.String(), "event: error",
		"the client must still be told")
}

// A canceled request is the consumer hanging up, not a failure, and must not
// be reported as one.
func TestFirehoseRouteDoesNotReportACanceledRequest(t *testing.T) {
	id, err := identity.New("", "")
	require.NoError(t, err)
	source := &firehoseTestStore{err: context.Canceled}
	e := newEchoServer(id, server.NewHTTP(id), source)
	logged := observeRequests(e)

	e.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/revocations/0", nil))

	require.NoError(t, logged().Error)
}

// observeRequests reports what request-logging middleware sees, which is what
// logs and metrics are built on.
func observeRequests(e *echo.Echo) func() middleware.RequestLoggerValues {
	var values middleware.RequestLoggerValues
	e.Use(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		LogStatus:   true,
		LogError:    true,
		HandleError: true,
		LogValuesFunc: func(_ echo.Context, v middleware.RequestLoggerValues) error {
			values = v
			return nil
		},
	}))
	return func() middleware.RequestLoggerValues { return values }
}

func TestRevocationRouteReturnsDAGJSON(t *testing.T) {
	id, err := identity.New("", "")
	require.NoError(t, err)
	command, err := command.Parse("/test/revoke")
	require.NoError(t, err)
	revocation, err := invocation.Invoke(id, did.Undef, command, nil)
	require.NoError(t, err)
	source := &firehoseTestStore{record: store.RevocationRecord{Revoke: revocation.Link(), Cause: revocation}}
	e := newEchoServer(id, server.NewHTTP(id), source)
	request := httptest.NewRequest(http.MethodGet, "/revocation/"+revocation.Link().String(), nil)
	response := httptest.NewRecorder()
	e.ServeHTTP(response, request)

	require.Equal(t, http.StatusOK, response.Code)
	require.Equal(t, "application/vnd.ipld.dag-json", response.Header().Get(echo.HeaderContentType))
	require.Equal(t, "public, max-age=31536000, immutable", response.Header().Get(echo.HeaderCacheControl))
	require.Contains(t, response.Body.String(), `"revoke"`)
	require.Contains(t, response.Body.String(), `"cause"`)
}

func TestRevokeRoute(t *testing.T) {
	service, err := identity.New("", "")
	require.NoError(t, err)
	alice, err := ed25519.GenerateIssuer()
	require.NoError(t, err)
	bob, err := ed25519.GenerateIssuer()
	require.NoError(t, err)
	carol, err := ed25519.GenerateIssuer()
	require.NoError(t, err)
	command, err := command.Parse("/test/invoke")
	require.NoError(t, err)
	root, err := delegation.Delegate(alice, bob.DID(), alice.DID(), command)
	require.NoError(t, err)
	target, err := delegation.Delegate(bob, carol.DID(), alice.DID(), command)
	require.NoError(t, err)

	revocations := memory.New()
	executor := newRevokeExecutor(t, service, revocations)

	publish := func(revoker ucan.Issuer, revoked cid.Cid, path []cid.Cid, witnesses ...ucan.Delegation) error {
		revocation, err := ucancmd.Revoke.Invoke(
			revoker,
			revoker.DID(),
			&ucancmd.RevokeArguments{Revoke: revoked, Path: path},
			invocation.WithAudience(service.DID()),
			invocation.WithNoExpiration(),
		)
		require.NoError(t, err)
		response, err := executor.Execute(execution.NewRequest(t.Context(), revocation, execution.WithDelegations(witnesses...)))
		if err != nil {
			return err
		}
		_, err = ucancmd.Revoke.Unpack(response.Receipt())
		return err
	}

	// bob issued target, so bob may revoke it directly without a witness path.
	require.NoError(t, publish(bob, target.Link(), nil, target))
	record, err := revocations.Get(t.Context(), target.Link())
	require.NoError(t, err)
	require.Len(t, record.Path, 1)
	require.Equal(t, target.Link(), record.Path[0].Link())

	// carol did not issue target, so a direct revocation is rejected.
	require.Error(t, publish(carol, target.Link(), nil, target))

	// The revoked delegation must be included in request metadata.
	require.Error(t, publish(bob, target.Link(), nil))

	// A witness path proves authority over a delegation the revoker did not issue.
	require.NoError(t, publish(alice, target.Link(), []cid.Cid{root.Link(), target.Link()}, root, target))
}

func TestRevokeRouteBatch(t *testing.T) {
	service, err := identity.New("", "")
	require.NoError(t, err)
	bob, err := ed25519.GenerateIssuer()
	require.NoError(t, err)
	carol, err := ed25519.GenerateIssuer()
	require.NoError(t, err)
	command, err := command.Parse("/test/invoke")
	require.NoError(t, err)

	const validCount = 5
	var delegations []ucan.Delegation
	var invocations []ucan.Invocation
	for range validCount {
		target, err := delegation.Delegate(bob, carol.DID(), bob.DID(), command)
		require.NoError(t, err)
		delegations = append(delegations, target)
		invocations = append(invocations, revokeInvocation(t, bob, service.DID(), target.Link()))
	}
	// carol did not issue the delegation she revokes, so her revocation is
	// rejected while the rest of the batch is stored.
	rejected := revokeInvocation(t, carol, service.DID(), delegations[0].Link())
	invocations = append(invocations, rejected)

	revocations := &countingStore{RevocationStore: memory.New()}
	executor := newRevokeExecutor(t, service, revocations)
	response, err := executor.ExecuteBatch(batch.NewRequest(t.Context(), invocations, batch.WithDelegations(delegations...)))
	require.NoError(t, err)

	t.Run("each valid revocation gets a success receipt", func(t *testing.T) {
		for _, inv := range invocations[:validCount] {
			receipt, ok := response.Receipt(inv.Task().Link())
			require.True(t, ok)
			_, err := ucancmd.Revoke.Unpack(receipt)
			require.NoError(t, err)
		}
	})

	t.Run("the invalid revocation gets an error receipt", func(t *testing.T) {
		receipt, ok := response.Receipt(rejected.Task().Link())
		require.True(t, ok)
		_, err := ucancmd.Revoke.Unpack(receipt)
		require.ErrorContains(t, err, "witness path required")
	})

	t.Run("the valid revocations are stored with one write", func(t *testing.T) {
		stored := make([]cid.Cid, 0, validCount)
		for _, batch := range revocations.batches {
			for _, revocation := range batch {
				stored = append(stored, revocation.Cause.Link())
			}
		}
		expected := make([]cid.Cid, 0, validCount)
		for _, inv := range invocations[:validCount] {
			expected = append(expected, inv.Link())
		}
		require.Equal(t, []int{validCount}, revocations.batchSizes())
		require.ElementsMatch(t, expected, stored)
	})
}

func TestRevokeRouteStoreFailure(t *testing.T) {
	service, err := identity.New("", "")
	require.NoError(t, err)
	bob, err := ed25519.GenerateIssuer()
	require.NoError(t, err)
	command, err := command.Parse("/test/invoke")
	require.NoError(t, err)
	target, err := delegation.Delegate(bob, bob.DID(), bob.DID(), command)
	require.NoError(t, err)

	revocations := &countingStore{RevocationStore: memory.New(), err: errors.New("database is down")}
	executor := newRevokeExecutor(t, service, revocations)
	inv := revokeInvocation(t, bob, service.DID(), target.Link())
	response, err := executor.Execute(execution.NewRequest(t.Context(), inv, execution.WithDelegations(target)))
	require.NoError(t, err)
	_, err = ucancmd.Revoke.Unpack(response.Receipt())
	require.ErrorContains(t, err, "storing revocations: database is down")
	// The receipt is short-lived, so the caller retries rather than caches it.
	require.NotNil(t, response.Receipt().Expiration())
}

// newRevokeExecutor returns a UCAN client whose requests are served in process
// by a server with the revoke route, storing revocations in revocations.
func newRevokeExecutor(t *testing.T, service identity.Identity, revocations store.RevocationStore) *client.HTTPClient {
	t.Helper()
	return newExecutor(t, newRevokeHandler(service, revocations))
}

func newRevokeHandler(service identity.Identity, revocations store.RevocationStore) *server.HTTPServer {
	didResolver := resolver.ByMethod{"key": key.Resolver}
	srv := server.NewHTTP(service, server.WithValidationOptions(validator.WithDIDResolver(didResolver)))
	srv.HandleRoute(revokeRoute(revocations, didResolver, zap.NewNop()))
	return srv
}

func newExecutor(t *testing.T, transport http.RoundTripper) *client.HTTPClient {
	t.Helper()
	serviceURL, err := url.Parse("http://swarf.test")
	require.NoError(t, err)
	executor, err := client.NewHTTP(serviceURL, client.WithHTTPClient(&http.Client{Transport: transport}))
	require.NoError(t, err)
	return executor
}

func revokeInvocation(t *testing.T, revoker ucan.Issuer, service did.DID, revoked cid.Cid) ucan.Invocation {
	t.Helper()
	inv, err := ucancmd.Revoke.Invoke(
		revoker,
		revoker.DID(),
		&ucancmd.RevokeArguments{Revoke: revoked},
		invocation.WithAudience(service),
		invocation.WithNoNonce(),
		invocation.WithNoExpiration(),
	)
	require.NoError(t, err)
	return inv
}

// countingStore records every AddBatch call, failing each with err when set.
type countingStore struct {
	store.RevocationStore
	err     error
	mu      sync.Mutex
	batches [][]store.Revocation
}

func (s *countingStore) AddBatch(ctx context.Context, revocations []store.Revocation) error {
	s.mu.Lock()
	s.batches = append(s.batches, revocations)
	s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	return s.RevocationStore.AddBatch(ctx, revocations)
}

func (s *countingStore) batchSizes() []int {
	s.mu.Lock()
	defer s.mu.Unlock()
	sizes := make([]int, len(s.batches))
	for i, batch := range s.batches {
		sizes[i] = len(batch)
	}
	return sizes
}

func TestValidateRevocationPath(t *testing.T) {
	alice, err := ed25519.GenerateIssuer()
	require.NoError(t, err)
	bob, err := ed25519.GenerateIssuer()
	require.NoError(t, err)
	carol, err := ed25519.GenerateIssuer()
	require.NoError(t, err)
	command, err := command.Parse("/test/invoke")
	require.NoError(t, err)
	root, err := delegation.Delegate(alice, bob.DID(), alice.DID(), command)
	require.NoError(t, err)
	child, err := delegation.Delegate(bob, carol.DID(), alice.DID(), command)
	require.NoError(t, err)
	resolver := resolver.ByMethod{"key": key.Resolver}

	require.NoError(t, validateRevocationPath(t.Context(), []ucan.Delegation{root, child}, resolver))

	powerline, err := delegation.Delegate(bob, carol.DID(), did.Undef, command)
	require.NoError(t, err)
	require.NoError(t, validateRevocationPath(t.Context(), []ucan.Delegation{root, powerline}, resolver))

	invalidRoot, err := delegation.Delegate(alice, bob.DID(), did.Undef, command)
	require.NoError(t, err)
	require.Error(t, validateRevocationPath(t.Context(), []ucan.Delegation{invalidRoot}, resolver))

	wrongSubject, err := delegation.Delegate(bob, carol.DID(), bob.DID(), command)
	require.NoError(t, err)
	require.Error(t, validateRevocationPath(t.Context(), []ucan.Delegation{root, wrongSubject}, resolver))

	expired, err := delegation.Delegate(
		alice,
		bob.DID(),
		alice.DID(),
		command,
		delegation.WithExpiration(ucan.UnixTimestamp(time.Now().Add(-time.Minute).Unix())),
	)
	require.NoError(t, err)
	require.Error(t, validateRevocationPath(t.Context(), []ucan.Delegation{expired}, resolver))
}

type firehoseTestStore struct {
	record store.RevocationRecord
	// err, when set, is yielded instead of record, as a store failing
	// mid-stream does.
	err  error
	from time.Time
}

func (s *firehoseTestStore) Add(context.Context, ucan.Invocation, []ucan.Delegation) error {
	return nil
}

func (s *firehoseTestStore) AddBatch(context.Context, []store.Revocation) error {
	return nil
}

func (s *firehoseTestStore) Get(context.Context, cid.Cid) (store.RevocationRecord, error) {
	return s.record, nil
}

func (s *firehoseTestStore) Stream(_ context.Context, from time.Time) iter.Seq2[store.RevocationRecord, error] {
	s.from = from
	return func(yield func(store.RevocationRecord, error) bool) {
		if s.err != nil {
			yield(store.RevocationRecord{}, s.err)
			return
		}
		yield(s.record, nil)
	}
}
