package fx

import (
	"context"
	"iter"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fil-forge/libforge/identity"
	"github.com/fil-forge/swarf/pkg/api"
	"github.com/fil-forge/swarf/pkg/store"
	"github.com/fil-forge/swarf/pkg/store/memory"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/did/key"
	"github.com/fil-forge/ucantone/did/resolver"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/ipfs/go-cid"
	"github.com/labstack/echo/v4"
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

func TestParseSince(t *testing.T) {
	since, err := parseSince("0")
	require.NoError(t, err)
	require.True(t, since.IsZero())
	_, err = parseSince("not-a-timestamp")
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
	createdAt := time.Now().UTC().Round(0)
	source := &firehoseTestStore{
		record: store.RevocationRecord{Revoke: witness.Link(), Cause: revocation, Path: []ucan.Delegation{witness}, CreatedAt: createdAt},
	}
	e := newEchoServer(id, server.NewHTTP(id), source)
	request := httptest.NewRequest(http.MethodGet, "/revocations/"+createdAt.Format(time.RFC3339Nano), nil)
	response := httptest.NewRecorder()
	e.ServeHTTP(response, request)

	require.Equal(t, http.StatusOK, response.Code)
	require.Equal(t, "text/event-stream", response.Header().Get(echo.HeaderContentType))
	require.Contains(t, response.Body.String(), "event: revocation")
	require.Equal(t, createdAt, source.since)
	data := strings.TrimSuffix(strings.TrimPrefix(response.Body.String(), "id: "+revocation.Link().String()+"\nevent: revocation\ndata: "), "\n\n")
	var event api.FirehoseRevocation
	require.NoError(t, event.UnmarshalDagJSON(strings.NewReader(data)))
	require.Equal(t, witness.Link(), event.Revoke)
	require.Equal(t, []cid.Cid{witness.Link()}, event.Path)
	require.Equal(t, revocation.Link(), event.Cause)
	require.True(t, event.CreatedAt.Time().Equal(createdAt))
	require.NotContains(t, response.Body.String(), `"revocation"`)
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
	since  time.Time
}

func (s *firehoseTestStore) Add(context.Context, ucan.Invocation, []ucan.Delegation) error {
	return nil
}

func (s *firehoseTestStore) Get(context.Context, cid.Cid) (store.RevocationRecord, error) {
	return s.record, nil
}

func (s *firehoseTestStore) Stream(_ context.Context, since time.Time) iter.Seq2[store.RevocationRecord, error] {
	s.since = since
	return func(yield func(store.RevocationRecord, error) bool) {
		yield(s.record, nil)
	}
}
