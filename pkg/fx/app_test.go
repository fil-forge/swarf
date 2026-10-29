package fx

import (
	"context"
	"errors"
	"iter"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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
		cursor: store.Cursor{Seq: 42, ID: revocation.Link().String()},
	}
	e := newEchoServer(id, server.NewHTTP(id), source)
	request := httptest.NewRequest(http.MethodGet, "/revocations/"+recordedAt.Format(time.RFC3339Nano), nil)
	response := httptest.NewRecorder()
	e.ServeHTTP(response, request)

	require.Equal(t, http.StatusOK, response.Code)
	require.Equal(t, "text/event-stream", response.Header().Get(echo.HeaderContentType))
	require.Contains(t, response.Body.String(), "event: revocation")
	require.Equal(t, recordedAt, source.from)
	require.Equal(t, store.Cursor{}, source.after)
	// The event's id is the record's cursor, not its cause.
	data := strings.TrimSuffix(strings.TrimPrefix(response.Body.String(), "id: 42-"+revocation.Link().String()+"\nevent: revocation\ndata: "), "\n\n")
	var event api.FirehoseRevocation
	require.NoError(t, event.UnmarshalDagJSON(strings.NewReader(data)))
	require.Equal(t, witness.Link(), event.Revoke)
	require.Equal(t, []cid.Cid{witness.Link()}, event.Path)
	require.Equal(t, revocation.Link(), event.Cause)
	require.True(t, event.RecordedAt.Time().Equal(recordedAt))
	require.NotContains(t, response.Body.String(), `"revocation"`)
}

// A reconnect to a time query resumes after the event it last received, and
// keeps the query's floor.
func TestFirehoseRouteResumesAfterLastEventID(t *testing.T) {
	id, err := identity.New("", "")
	require.NoError(t, err)
	from := time.Now().UTC().Round(0)

	for _, test := range []struct {
		name        string
		lastEventID string
		after       store.Cursor
	}{
		{name: "a cursor", lastEventID: "7-bafy", after: store.Cursor{Seq: 7, ID: "bafy"}},
		// An id from before ids were cursors, or a cursor ahead of the head,
		// which another database issued, starts the query over: records can
		// repeat, but none is skipped.
		{name: "not a cursor", lastEventID: "bafyreif5fzax7oygfafacvxq2ndhtkshz2av5m42hqeixea7giirdxe5dm", after: store.Cursor{}},
		{name: "ahead of the head", lastEventID: "10-bafy", after: store.Cursor{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := &firehoseTestStore{err: context.Canceled, head: store.Cursor{Seq: 9}}
			e := newEchoServer(id, server.NewHTTP(id), source)
			request := httptest.NewRequest(http.MethodGet, "/revocations/"+from.Format(time.RFC3339Nano), nil)
			request.Header.Set("Last-Event-ID", test.lastEventID)
			response := httptest.NewRecorder()
			e.ServeHTTP(response, request)

			require.Equal(t, http.StatusOK, response.Code)
			require.Equal(t, test.after, source.after)
			require.Equal(t, from, source.from)
		})
	}
}

func TestFirehoseAfterRoute(t *testing.T) {
	id, err := identity.New("", "")
	require.NoError(t, err)

	t.Run("resumes after the cursor", func(t *testing.T) {
		source := &firehoseTestStore{err: context.Canceled, head: store.Cursor{Seq: 9}}
		e := newEchoServer(id, server.NewHTTP(id), source)
		response := httptest.NewRecorder()
		e.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/revocations/after/7-bafy", nil))

		require.Equal(t, http.StatusOK, response.Code)
		require.Equal(t, "text/event-stream", response.Header().Get(echo.HeaderContentType))
		require.Equal(t, store.Cursor{Seq: 7, ID: "bafy"}, source.after)
		require.True(t, source.from.IsZero(), "a resumed stream has no time floor")
		require.Empty(t, response.Body.String())
	})

	t.Run("starts now at the store's head and sends it first", func(t *testing.T) {
		source := &firehoseTestStore{err: context.Canceled, head: store.Cursor{Seq: 9}}
		e := newEchoServer(id, server.NewHTTP(id), source)
		response := httptest.NewRecorder()
		e.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/revocations/after/now", nil))

		require.Equal(t, http.StatusOK, response.Code)
		require.Equal(t, store.Cursor{Seq: 9}, source.after)
		// An event with only an id, so a client reconnecting before the first
		// record resumes from this head.
		require.Equal(t, "id: 9\n\n", response.Body.String())
	})

	t.Run("a reconnect resumes after its last event", func(t *testing.T) {
		for _, path := range []string{"/revocations/after/7-bafy", "/revocations/after/now"} {
			source := &firehoseTestStore{err: context.Canceled, head: store.Cursor{Seq: 9}}
			e := newEchoServer(id, server.NewHTTP(id), source)
			request := httptest.NewRequest(http.MethodGet, path, nil)
			request.Header.Set("Last-Event-ID", "8-bafz")
			response := httptest.NewRecorder()
			e.ServeHTTP(response, request)

			require.Equal(t, http.StatusOK, response.Code, path)
			require.Equal(t, store.Cursor{Seq: 8, ID: "bafz"}, source.after, path)
			require.Empty(t, response.Body.String(), path)
		}
	})

	// The store changed since the stream began, so neither the head nor
	// :cursor, from the same stream, is a safe place to start.
	t.Run("refuses a Last-Event-ID ahead of the head", func(t *testing.T) {
		for _, path := range []string{"/revocations/after/7-bafy", "/revocations/after/now"} {
			source := &firehoseTestStore{head: store.Cursor{Seq: 9}}
			e := newEchoServer(id, server.NewHTTP(id), source)
			request := httptest.NewRequest(http.MethodGet, path, nil)
			request.Header.Set("Last-Event-ID", "10-bafz")
			response := httptest.NewRecorder()
			e.ServeHTTP(response, request)

			require.Equal(t, http.StatusConflict, response.Code, path)
		}
	})

	// Streaming after a cursor ahead of the head would skip every record up
	// to it.
	t.Run("refuses a cursor ahead of the head", func(t *testing.T) {
		for _, cursor := range []string{"10", "9-bafy"} {
			source := &firehoseTestStore{head: store.Cursor{Seq: 9}}
			e := newEchoServer(id, server.NewHTTP(id), source)
			response := httptest.NewRecorder()
			e.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/revocations/after/"+cursor, nil))
			require.Equal(t, http.StatusConflict, response.Code, cursor)
		}
	})

	t.Run("rejects a malformed cursor", func(t *testing.T) {
		for _, cursor := range []string{"bafy", "7-", "-bafy", "later"} {
			source := &firehoseTestStore{}
			e := newEchoServer(id, server.NewHTTP(id), source)
			response := httptest.NewRecorder()
			e.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/revocations/after/"+cursor, nil))
			require.Equal(t, http.StatusBadRequest, response.Code, cursor)
		}
	})
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
	didResolver := resolver.ByMethod{"key": key.Resolver}
	srv := server.NewHTTP(service, server.WithValidationOptions(validator.WithDIDResolver(didResolver)))
	route := revokeRoute(revocations, didResolver)
	srv.Handle(route.Command, route.Handler)
	serviceURL, err := url.Parse("http://swarf.test")
	require.NoError(t, err)
	executor, err := client.NewHTTP(serviceURL, client.WithHTTPClient(&http.Client{Transport: srv}))
	require.NoError(t, err)

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
	cursor store.Cursor
	head   store.Cursor
	// err, when set, is yielded instead of record, as a store failing
	// mid-stream does.
	err error
	// after and from are what the last Stream call asked for.
	after store.Cursor
	from  time.Time
}

func (s *firehoseTestStore) Add(context.Context, ucan.Invocation, []ucan.Delegation) error {
	return nil
}

func (s *firehoseTestStore) Get(context.Context, cid.Cid) (store.RevocationRecord, error) {
	return s.record, nil
}

func (s *firehoseTestStore) Head(context.Context) (store.Cursor, error) {
	return s.head, nil
}

func (s *firehoseTestStore) Stream(_ context.Context, after store.Cursor, from time.Time) iter.Seq2[store.StreamRecord, error] {
	s.after = after
	s.from = from
	return func(yield func(store.StreamRecord, error) bool) {
		if s.err != nil {
			yield(store.StreamRecord{}, s.err)
			return
		}
		yield(store.StreamRecord{RevocationRecord: s.record, Cursor: s.cursor}, nil)
	}
}
