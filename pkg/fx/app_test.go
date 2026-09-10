package fx

import (
	"bufio"
	"context"
	"iter"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	principalcmd "github.com/fil-forge/libforge/commands/principal"
	ucancmd "github.com/fil-forge/libforge/commands/ucan"
	"github.com/fil-forge/libforge/identity"
	"github.com/fil-forge/swarf/pkg/api"
	swarfclient "github.com/fil-forge/swarf/pkg/client"
	"github.com/fil-forge/swarf/pkg/config"
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

func TestFirehoseRouteStreamsPrincipalRevocationEvents(t *testing.T) {
	id, err := identity.New("", "")
	require.NoError(t, err)
	command, err := command.Parse("/test/invalidate")
	require.NoError(t, err)
	revocation, err := invocation.Invoke(id, did.Undef, command, nil)
	require.NoError(t, err)
	witness, err := delegation.Delegate(id, did.Undef, id.DID(), command)
	require.NoError(t, err)
	invalidation, err := invocation.Invoke(id, did.Undef, command, nil, invocation.WithNonce([]byte("principal")))
	require.NoError(t, err)
	tenant, err := did.Parse("did:plc:tenant")
	require.NoError(t, err)
	recordedAt := time.Now().UTC().Round(0)
	source := &firehoseTestStore{events: []store.Event{
		store.RevocationEvent(store.RevocationRecord{Revoke: witness.Link(), Cause: revocation, Path: []ucan.Delegation{witness}, RecordedAt: recordedAt}),
		store.PrincipalRevocationEvent(store.PrincipalRevocationRecord{Tenant: tenant, Principal: "alice", Cause: invalidation, RecordedAt: recordedAt.Add(time.Second)}),
	}}
	e := newEchoServer(id, server.NewHTTP(id), source)
	request := httptest.NewRequest(http.MethodGet, "/revocations/0", nil)
	response := httptest.NewRecorder()
	e.ServeHTTP(response, request)

	require.Equal(t, http.StatusOK, response.Code)
	frames := strings.Split(strings.TrimSuffix(response.Body.String(), "\n\n"), "\n\n")
	require.Len(t, frames, 2)

	// Events are written in stream order, each under its own kind.
	require.True(t, strings.HasPrefix(frames[0], "id: "+revocation.Link().String()+"\nevent: revocation\ndata: "))
	var revoked api.FirehoseRevocation
	require.NoError(t, revoked.UnmarshalDagJSON(strings.NewReader(strings.TrimPrefix(frames[0], "id: "+revocation.Link().String()+"\nevent: revocation\ndata: "))))
	require.Equal(t, witness.Link(), revoked.Revoke)

	prefix := "id: " + invalidation.Link().String() + "\nevent: principal\ndata: "
	require.True(t, strings.HasPrefix(frames[1], prefix), frames[1])
	var principal api.FirehosePrincipalRevocation
	require.NoError(t, principal.UnmarshalDagJSON(strings.NewReader(strings.TrimPrefix(frames[1], prefix))))
	require.Equal(t, tenant, principal.Tenant)
	require.Equal(t, "alice", principal.Principal)
	require.Equal(t, invalidation.Link(), principal.Cause)
	require.True(t, principal.RecordedAt.Time().Equal(recordedAt.Add(time.Second)))
	require.NotContains(t, frames[1], `"revoke"`)
	require.NotContains(t, frames[1], `"path"`)
}

func TestFirehoseRouteStreamsMemoryStoreEvents(t *testing.T) {
	id, err := identity.New("", "")
	require.NoError(t, err)
	command, err := command.Parse("/test/invalidate")
	require.NoError(t, err)
	revocation, err := invocation.Invoke(id, did.Undef, command, nil)
	require.NoError(t, err)
	witness, err := delegation.Delegate(id, did.Undef, id.DID(), command)
	require.NoError(t, err)
	invalidation, err := invocation.Invoke(id, did.Undef, command, nil, invocation.WithNonce([]byte("principal")))
	require.NoError(t, err)
	tenant, err := did.Parse("did:plc:tenant")
	require.NoError(t, err)

	records := memory.New()
	require.NoError(t, records.Add(t.Context(), revocation, []ucan.Delegation{witness}))
	require.NoError(t, records.AddPrincipalRevocation(t.Context(), invalidation, tenant, "alice"))

	srv := httptest.NewServer(newEchoServer(id, server.NewHTTP(id), records))
	defer srv.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/revocations/0", nil)
	require.NoError(t, err)
	response, err := http.DefaultClient.Do(request)
	require.NoError(t, err)
	defer response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode)
	require.Equal(t, "text/event-stream", response.Header.Get(echo.HeaderContentType))

	// The stream stays open, so read exactly the two frames the store holds
	// and then cancel the request.
	scanner := bufio.NewScanner(response.Body)
	var frames []map[string]string
	frame := map[string]string{}
	for len(frames) < 2 && scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			frames = append(frames, frame)
			frame = map[string]string{}
			continue
		}
		field, value, ok := strings.Cut(line, ": ")
		require.True(t, ok, line)
		frame[field] = value
	}
	require.NoError(t, scanner.Err())
	cancel()
	require.Len(t, frames, 2)

	require.Equal(t, "revocation", frames[0]["event"])
	require.Equal(t, revocation.Link().String(), frames[0]["id"])
	var revoked api.FirehoseRevocation
	require.NoError(t, revoked.UnmarshalDagJSON(strings.NewReader(frames[0]["data"])))
	require.Equal(t, witness.Link(), revoked.Revoke)
	require.Equal(t, revocation.Link(), revoked.Cause)

	require.Equal(t, "principal", frames[1]["event"])
	require.Equal(t, invalidation.Link().String(), frames[1]["id"])
	var principal api.FirehosePrincipalRevocation
	require.NoError(t, principal.UnmarshalDagJSON(strings.NewReader(frames[1]["data"])))
	require.Equal(t, tenant, principal.Tenant)
	require.Equal(t, "alice", principal.Principal)
	require.Equal(t, invalidation.Link(), principal.Cause)
	require.False(t, principal.RecordedAt.Time().Before(revoked.RecordedAt.Time()))
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

// firehoseTestStore is a fixed-content store. Get returns record; Stream
// yields events when set and otherwise record as a single revocation event,
// then ends.
type firehoseTestStore struct {
	record store.RevocationRecord
	events []store.Event
	from   time.Time
}

func (s *firehoseTestStore) Add(context.Context, ucan.Invocation, []ucan.Delegation) error {
	return nil
}

func (s *firehoseTestStore) AddPrincipalRevocation(context.Context, ucan.Invocation, did.DID, string) error {
	return nil
}

func (s *firehoseTestStore) Get(context.Context, cid.Cid) (store.RevocationRecord, error) {
	return s.record, nil
}

func (s *firehoseTestStore) Stream(_ context.Context, from time.Time) iter.Seq2[store.Event, error] {
	s.from = from
	return func(yield func(store.Event, error) bool) {
		if s.events == nil {
			yield(store.RevocationEvent(s.record), nil)
			return
		}
		for _, event := range s.events {
			if !yield(event, nil) {
				return
			}
		}
	}
}

func TestInvalidateRoute(t *testing.T) {
	service, err := identity.New("", "")
	require.NoError(t, err)
	hilt, err := ed25519.GenerateIssuer()
	require.NoError(t, err)
	stranger, err := ed25519.GenerateIssuer()
	require.NoError(t, err)
	tenant, err := did.Parse("did:plc:tenant")
	require.NoError(t, err)

	invalidate := func(records store.RevocationStore, publishers map[did.DID]struct{}, issuer ucan.Issuer) (cid.Cid, error) {
		didResolver := resolver.ByMethod{"key": key.Resolver}
		srv := server.NewHTTP(service, server.WithValidationOptions(validator.WithDIDResolver(didResolver)))
		route := invalidateRoute(records, publishers)
		srv.Handle(route.Command, route.Handler)
		serviceURL, err := url.Parse("http://swarf.test")
		require.NoError(t, err)
		executor, err := client.NewHTTP(serviceURL, client.WithHTTPClient(&http.Client{Transport: srv}))
		require.NoError(t, err)

		invalidation, err := principalcmd.Invalidate.Invoke(
			issuer,
			issuer.DID(),
			&principalcmd.InvalidateArguments{Tenant: tenant, Principal: "8f2c"},
			invocation.WithAudience(service.DID()),
			invocation.WithNoNonce(),
			invocation.WithNoExpiration(),
		)
		require.NoError(t, err)
		response, err := executor.Execute(execution.NewRequest(t.Context(), invalidation))
		if err != nil {
			return cid.Undef, err
		}
		if _, err := principalcmd.Invalidate.Unpack(response.Receipt()); err != nil {
			return cid.Undef, err
		}
		return invalidation.Link(), nil
	}

	// An allowlisted publisher self-signs the invalidation and it is stored.
	records := memory.New()
	publishers := map[did.DID]struct{}{hilt.DID(): {}}
	cause, err := invalidate(records, publishers, hilt)
	require.NoError(t, err)
	stored := principalRevocationRecords(t, records)
	require.Len(t, stored, 1)
	require.Equal(t, tenant, stored[0].Tenant)
	require.Equal(t, "8f2c", stored[0].Principal)
	require.Equal(t, cause, stored[0].Cause.Link())

	// Any other issuer is refused and nothing is stored.
	records = memory.New()
	_, err = invalidate(records, publishers, stranger)
	require.Error(t, err)
	require.Empty(t, principalRevocationRecords(t, records))

	// An empty publisher list refuses every invalidation.
	records = memory.New()
	_, err = invalidate(records, map[did.DID]struct{}{}, hilt)
	require.Error(t, err)
	require.Empty(t, principalRevocationRecords(t, records))

	// Two invalidations of the same principal through the client are two
	// records with distinct causes: the store keys records by the invocation
	// CID and consumers dedupe by it, so a repeat that shared the CID of the
	// first would never reach the firehose.
	records = memory.New()
	didResolver := resolver.ByMethod{"key": key.Resolver}
	srv := server.NewHTTP(service, server.WithValidationOptions(validator.WithDIDResolver(didResolver)))
	route := invalidateRoute(records, publishers)
	srv.Handle(route.Command, route.Handler)
	serviceURL, err := url.Parse("http://swarf.test")
	require.NoError(t, err)
	swarf, err := swarfclient.New(service.DID(), *serviceURL, swarfclient.WithHTTPClient(&http.Client{Transport: srv}))
	require.NoError(t, err)
	require.NoError(t, swarf.Invalidate(t.Context(), hilt, tenant, "8f2c"))
	require.NoError(t, swarf.Invalidate(t.Context(), hilt, tenant, "8f2c"))
	stored = principalRevocationRecords(t, records)
	require.Len(t, stored, 2)
	require.NotEqual(t, stored[0].Cause.Link(), stored[1].Cause.Link(), "each invalidation is its own record")
}

// principalRevocationRecords drains the principal revocation records the
// store holds.
func principalRevocationRecords(t *testing.T, records store.RevocationStore) []store.PrincipalRevocationRecord {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	var stored []store.PrincipalRevocationRecord
	for event, err := range records.Stream(ctx, time.Time{}) {
		if err != nil {
			break
		}
		if event.PrincipalRevocation != nil {
			stored = append(stored, *event.PrincipalRevocation)
		}
	}
	return stored
}

func TestNewPrincipalPublishers(t *testing.T) {
	publishers, err := newPrincipalPublishers(&config.Config{
		Principal: config.PrincipalConfig{Publishers: []string{"did:web:auth.example.com"}},
	}, zap.NewNop())
	require.NoError(t, err)
	publisher, err := did.Parse("did:web:auth.example.com")
	require.NoError(t, err)
	require.Contains(t, publishers, publisher)

	empty, err := newPrincipalPublishers(&config.Config{}, zap.NewNop())
	require.NoError(t, err)
	require.Empty(t, empty)

	_, err = newPrincipalPublishers(&config.Config{
		Principal: config.PrincipalConfig{Publishers: []string{"not-a-did"}},
	}, zap.NewNop())
	require.Error(t, err)
}
