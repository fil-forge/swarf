package client

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	jsg "github.com/alanshaw/dag-json-gen"
	ucancmd "github.com/fil-forge/libforge/commands/ucan"
	"github.com/fil-forge/libforge/identity"
	"github.com/fil-forge/swarf/pkg/api"
	"github.com/fil-forge/ucantone/binding"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/ipfs/go-cid"
	"github.com/stretchr/testify/require"
)

func TestPublish(t *testing.T) {
	service, err := ed25519.GenerateIssuer()
	require.NoError(t, err)
	alice, err := ed25519.GenerateIssuer()
	require.NoError(t, err)
	bob, err := ed25519.GenerateIssuer()
	require.NoError(t, err)
	carol, err := ed25519.GenerateIssuer()
	require.NoError(t, err)

	cmd, err := command.Parse("/test/invoke")
	require.NoError(t, err)
	// root: subject == issuer, delegating to bob, who re-delegates to carol.
	root, err := delegation.Delegate(alice, bob.DID(), alice.DID(), cmd)
	require.NoError(t, err)
	target, err := delegation.Delegate(bob, carol.DID(), alice.DID(), cmd)
	require.NoError(t, err)
	path := []ucan.Delegation{root, target}

	var gotIssuer did.DID
	var gotArgs *ucancmd.RevokeArguments
	var gotWitnesses []cid.Cid
	srv := server.NewHTTP(service)
	srv.Handle(ucancmd.Revoke.Command, ucancmd.Revoke.Handler(
		func(req *binding.Request[*ucancmd.RevokeArguments], res *binding.Response[*ucancmd.RevokeOK]) error {
			gotIssuer = req.Invocation().Issuer()
			gotArgs = req.Task().Arguments()
			for _, dlg := range req.Metadata().Delegations() {
				gotWitnesses = append(gotWitnesses, dlg.Link())
			}
			return res.SetSuccess(&ucancmd.RevokeOK{})
		}))

	serviceURL, err := url.Parse("http://swarf.test")
	require.NoError(t, err)
	client, err := New(service.DID(), *serviceURL, WithHTTPClient(&http.Client{Transport: srv}))
	require.NoError(t, err)

	// bob is an issuer in the path, so bob may revoke the delegation it issued.
	require.NoError(t, client.Publish(context.Background(), bob, target.Link(), path))
	require.Equal(t, bob.DID(), gotIssuer)
	require.Equal(t, target.Link(), gotArgs.Revoke)
	require.Equal(t, []cid.Cid{root.Link(), target.Link()}, gotArgs.Path)
	require.ElementsMatch(t, []cid.Cid{root.Link(), target.Link()}, gotWitnesses)

	t.Run("requires a revoker", func(t *testing.T) {
		err := client.Publish(context.Background(), nil, target.Link(), path)
		require.ErrorContains(t, err, "revoker is required")
	})

	t.Run("requires the revoked delegation last", func(t *testing.T) {
		err := client.Publish(context.Background(), bob, root.Link(), path)
		require.ErrorContains(t, err, "must end with the revoked delegation")
	})
}

func TestGetAndStream(t *testing.T) {
	issuer, err := identity.New("", "")
	require.NoError(t, err)
	command, err := command.Parse("/test/revoke")
	require.NoError(t, err)
	revocation, err := invocation.Invoke(issuer, did.Undef, command, nil)
	require.NoError(t, err)
	encoded, err := invocation.Encode(revocation)
	require.NoError(t, err)
	recordedAt := time.Now().UTC().Round(0)
	lookupValue := api.Revocation{
		Revoke:     revocation.Link(),
		Cause:      encoded,
		RecordedAt: jsg.DagJsonTime(recordedAt),
	}
	var lookupPayload bytes.Buffer
	require.NoError(t, lookupValue.MarshalDagJSON(&lookupPayload))
	streamValue := api.FirehoseRevocation{
		Revoke:     revocation.Link(),
		Path:       []cid.Cid{revocation.Link()},
		Cause:      revocation.Link(),
		RecordedAt: jsg.DagJsonTime(recordedAt),
	}
	var streamPayload bytes.Buffer
	require.NoError(t, streamValue.MarshalDagJSON(&streamPayload))
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/revocation/" + revocation.Link().String():
			writer.Header().Set("Content-Type", "application/vnd.ipld.dag-json")
			_, _ = writer.Write(lookupPayload.Bytes())
		case "/revocations/0":
			writer.Header().Set("Content-Type", "text/event-stream")
			_, _ = fmt.Fprintf(writer, "event: revocation\ndata: %s\n\n", streamPayload.String())
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	serviceURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	client, err := New(issuer.DID(), *serviceURL)
	require.NoError(t, err)

	record, err := client.Get(context.Background(), revocation.Link())
	require.NoError(t, err)
	require.Equal(t, revocation.Link(), record.Revoke)
	require.Equal(t, revocation.Link(), record.Cause.Link())
	require.True(t, record.RecordedAt.Equal(recordedAt))

	// The stream reconnects when a connection ends, so stop after the
	// expected record instead of draining the iterator.
	var streamed int
	for record, err := range client.Stream(context.Background(), time.Time{}) {
		require.NoError(t, err)
		require.Equal(t, revocation.Link(), record.Revoke)
		require.Equal(t, []cid.Cid{revocation.Link()}, record.Path)
		require.Equal(t, revocation.Link(), record.Cause)
		require.True(t, record.RecordedAt.Time().Equal(recordedAt))
		streamed++
		break
	}
	require.Equal(t, 1, streamed)
}

func TestStreamReconnectDedupes(t *testing.T) {
	first := time.Now().UTC().Truncate(time.Second)
	boundary := first.Add(time.Second)
	last := boundary.Add(time.Second)
	recordA := firehoseRecord(t, first)
	recordB := firehoseRecord(t, boundary)
	recordC := firehoseRecord(t, boundary)
	recordD := firehoseRecord(t, last)

	var mu sync.Mutex
	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mu.Lock()
		requests = append(requests, request.URL.Path)
		connection := len(requests)
		mu.Unlock()
		writer.Header().Set("Content-Type", "text/event-stream")
		switch connection {
		case 1:
			_, _ = io.WriteString(writer, sseEvent(t, recordA)+sseEvent(t, recordB))
		case 2:
			// The from cursor is inclusive: the record recorded at exactly
			// the resume timestamp is re-delivered alongside new ones.
			_, _ = io.WriteString(writer, sseEvent(t, recordB)+sseEvent(t, recordC)+sseEvent(t, recordD))
		default:
			<-request.Context().Done()
		}
	}))
	defer server.Close()

	service, err := ed25519.GenerateIssuer()
	require.NoError(t, err)
	serviceURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	client, err := New(service.DID(), *serviceURL)
	require.NoError(t, err)

	var received []cid.Cid
	for record, err := range client.Stream(context.Background(), time.Time{}) {
		require.NoError(t, err)
		received = append(received, record.Cause)
		if len(received) == 4 {
			break
		}
	}
	require.Equal(t, []cid.Cid{recordA.Cause, recordB.Cause, recordC.Cause, recordD.Cause}, received)

	mu.Lock()
	defer mu.Unlock()
	require.GreaterOrEqual(t, len(requests), 2)
	require.Equal(t, "/revocations/0", requests[0])
	require.Equal(t, "/revocations/"+boundary.Format(time.RFC3339Nano), requests[1])
}

func TestStreamReconnectCanceled(t *testing.T) {
	record := firehoseRecord(t, time.Now().UTC().Truncate(time.Second))
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(writer, sseEvent(t, record))
	}))
	defer server.Close()

	service, err := ed25519.GenerateIssuer()
	require.NoError(t, err)
	serviceURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	client, err := New(service.DID(), *serviceURL)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var errs []error
	for streamed, err := range client.Stream(ctx, time.Time{}) {
		if err != nil {
			errs = append(errs, err)
			continue
		}
		require.Equal(t, record.Cause, streamed.Cause)
		// Cancel while the client waits to reconnect.
		cancel()
	}
	require.Len(t, errs, 1)
	require.ErrorIs(t, errs[0], context.Canceled)
}

func firehoseRecord(t *testing.T, recordedAt time.Time) api.FirehoseRevocation {
	t.Helper()
	issuer, err := ed25519.GenerateIssuer()
	require.NoError(t, err)
	cmd, err := command.Parse("/test/revoke")
	require.NoError(t, err)
	revocation, err := invocation.Invoke(issuer, did.Undef, cmd, nil)
	require.NoError(t, err)
	return api.FirehoseRevocation{
		Revoke:     revocation.Link(),
		Path:       []cid.Cid{revocation.Link()},
		Cause:      revocation.Link(),
		RecordedAt: jsg.DagJsonTime(recordedAt),
	}
}

func sseEvent(t *testing.T, record api.FirehoseRevocation) string {
	t.Helper()
	var payload bytes.Buffer
	require.NoError(t, record.MarshalDagJSON(&payload))
	return fmt.Sprintf("event: revocation\ndata: %s\n\n", payload.String())
}
