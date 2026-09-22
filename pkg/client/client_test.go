package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	jsg "github.com/alanshaw/dag-json-gen"
	ucancmd "github.com/fil-forge/libforge/commands/ucan"
	"github.com/fil-forge/libforge/identity"
	"github.com/fil-forge/swarf/internal/sse"
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

	// alice is an issuer in the witness path, so alice may revoke the
	// delegation bob issued.
	require.NoError(t, client.Publish(context.Background(), alice, target, WithWitnessPath(root)))
	require.Equal(t, alice.DID(), gotIssuer)
	require.Equal(t, target.Link(), gotArgs.Revoke)
	require.Equal(t, []cid.Cid{root.Link(), target.Link()}, gotArgs.Path)
	require.ElementsMatch(t, []cid.Cid{root.Link(), target.Link()}, gotWitnesses)

	t.Run("omits the path without a witness path", func(t *testing.T) {
		gotArgs = nil
		gotWitnesses = nil
		// bob issued target, so bob may revoke it directly without a witness path.
		require.NoError(t, client.Publish(context.Background(), bob, target))
		require.Equal(t, target.Link(), gotArgs.Revoke)
		require.Empty(t, gotArgs.Path)
		require.Equal(t, []cid.Cid{target.Link()}, gotWitnesses)
	})

	t.Run("tolerates the revoked delegation ending the witness path", func(t *testing.T) {
		gotArgs = nil
		gotWitnesses = nil
		require.NoError(t, client.Publish(context.Background(), alice, target, WithWitnessPath(root, target)))
		require.Equal(t, []cid.Cid{root.Link(), target.Link()}, gotArgs.Path)
		require.ElementsMatch(t, []cid.Cid{root.Link(), target.Link()}, gotWitnesses)
	})

	t.Run("requires a revoker", func(t *testing.T) {
		err := client.Publish(context.Background(), nil, target)
		require.ErrorContains(t, err, "revoker is required")
	})

	t.Run("requires a revoked delegation", func(t *testing.T) {
		err := client.Publish(context.Background(), bob, nil)
		require.ErrorContains(t, err, "revoked delegation is required")
	})
}

func TestPublishBatch(t *testing.T) {
	service, err := ed25519.GenerateIssuer()
	require.NoError(t, err)
	alice, err := ed25519.GenerateIssuer()
	require.NoError(t, err)
	bob, err := ed25519.GenerateIssuer()
	require.NoError(t, err)

	cmd, err := command.Parse("/test/invoke")
	require.NoError(t, err)
	first, err := delegation.Delegate(alice, bob.DID(), alice.DID(), cmd)
	require.NoError(t, err)
	second, err := delegation.Delegate(alice, bob.DID(), alice.DID(), cmd)
	require.NoError(t, err)

	var requests int
	var revoked []cid.Cid
	srv := server.NewHTTP(service)
	srv.Handle(ucancmd.Revoke.Command, ucancmd.Revoke.Handler(
		func(req *binding.Request[*ucancmd.RevokeArguments], res *binding.Response[*ucancmd.RevokeOK]) error {
			revoked = append(revoked, req.Task().Arguments().Revoke)
			return res.SetSuccess(&ucancmd.RevokeOK{})
		}))
	transport := http.RoundTripper(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		requests++
		return srv.RoundTrip(r)
	}))

	serviceURL, err := url.Parse("http://swarf.test")
	require.NoError(t, err)
	client, err := New(service.DID(), *serviceURL, WithHTTPClient(&http.Client{Transport: transport}))
	require.NoError(t, err)

	require.NoError(t, client.PublishBatch(context.Background(), alice, []ucan.Delegation{first, second}))
	require.Equal(t, 1, requests, "one request carries every revocation")
	require.ElementsMatch(t, []cid.Cid{first.Link(), second.Link()}, revoked)

	t.Run("publishes nothing for no delegations", func(t *testing.T) {
		requests = 0
		require.NoError(t, client.PublishBatch(context.Background(), alice, nil))
		require.Equal(t, 0, requests)
	})

	t.Run("fails when a revocation is refused", func(t *testing.T) {
		refusing := server.NewHTTP(service)
		refusing.Handle(ucancmd.Revoke.Command, ucancmd.Revoke.Handler(
			func(req *binding.Request[*ucancmd.RevokeArguments], res *binding.Response[*ucancmd.RevokeOK]) error {
				if req.Task().Arguments().Revoke == second.Link() {
					return res.SetFailure(errors.New("refused"))
				}
				return res.SetSuccess(&ucancmd.RevokeOK{})
			}))
		client, err := New(service.DID(), *serviceURL, WithHTTPClient(&http.Client{Transport: refusing}))
		require.NoError(t, err)
		require.Error(t, client.PublishBatch(context.Background(), alice, []ucan.Delegation{first, second}))
	})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

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

// TestStreamLargeEvent covers the two halves of the 64 KiB scanner cap.
//
// A FirehoseRevocation carries a CID per delegation in the chain, so a long
// path pushes one SSE event past the default bufio.Scanner token limit. Before
// sse.Scanner raised the buffer, Scan stopped, ErrTooLong was discarded,
// streamConn returned nil, and Stream reconnected at the same cursor --
// forever, never yielding and never erroring. A hang, not a failure.
func TestStreamLargeEvent(t *testing.T) {
	issuer, err := identity.New("", "")
	require.NoError(t, err)
	cmd, err := command.Parse("/test/revoke")
	require.NoError(t, err)
	revocation, err := invocation.Invoke(issuer, did.Undef, cmd, nil)
	require.NoError(t, err)
	recordedAt := time.Now().UTC().Round(0)

	// ~2000 CIDs puts the encoded event well past 64 KiB and well under 4 MiB.
	path := make([]cid.Cid, 2000)
	for i := range path {
		path[i] = revocation.Link()
	}
	value := api.FirehoseRevocation{
		Revoke:     revocation.Link(),
		Path:       path,
		Cause:      revocation.Link(),
		RecordedAt: jsg.DagJsonTime(recordedAt),
	}
	var payload bytes.Buffer
	require.NoError(t, value.MarshalDagJSON(&payload))
	require.Greater(t, payload.Len(), 64*1024,
		"the fixture must exceed the default scanner cap or it tests nothing")

	t.Run("over the default cap is delivered", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = fmt.Fprintf(w, "event: revocation\ndata: %s\n\n", payload.String())
		}))
		defer server.Close()
		serviceURL, err := url.Parse(server.URL)
		require.NoError(t, err)
		client, err := New(issuer.DID(), *serviceURL)
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		var streamed int
		for record, err := range client.Stream(ctx, time.Time{}) {
			require.NoError(t, err)
			require.Len(t, record.Path, len(path))
			streamed++
			break
		}
		require.Equal(t, 1, streamed, "the oversized event was dropped")
	})

	t.Run("past sse.MaxEventBytes errors rather than hanging", func(t *testing.T) {
		huge := strings.Repeat("a", sse.MaxEventBytes+1)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = fmt.Fprintf(w, "event: revocation\ndata: %s\n\n", huge)
		}))
		defer server.Close()
		serviceURL, err := url.Parse(server.URL)
		require.NoError(t, err)
		client, err := New(issuer.DID(), *serviceURL)
		require.NoError(t, err)

		// Without the ErrTooLong branch this reconnects forever; the timeout
		// is what distinguishes "surfaced an error" from "hung".
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		var got error
		for _, err := range client.Stream(ctx, time.Time{}) {
			got = err
			break
		}
		require.Error(t, got)
		require.NotErrorIs(t, got, context.DeadlineExceeded,
			"the stream hung instead of reporting the oversized event")
	})

	// Same limit, reached the other way. bufio.Scanner can only cap a line, so
	// an event assembled from many small data lines slipped past the cap
	// entirely -- the consumer buffered it whole, however large it was.
	t.Run("past sse.MaxEventBytes across many data lines errors too", func(t *testing.T) {
		line := "data: " + strings.Repeat("a", 1024) + "\n"
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = fmt.Fprint(w, "event: revocation\n")
			for range 16 * 1024 {
				_, _ = fmt.Fprint(w, line)
			}
			_, _ = fmt.Fprint(w, "\n")
		}))
		defer server.Close()
		serviceURL, err := url.Parse(server.URL)
		require.NoError(t, err)
		client, err := New(issuer.DID(), *serviceURL)
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		var got error
		for _, err := range client.Stream(ctx, time.Time{}) {
			got = err
			break
		}
		require.Error(t, got)
		require.NotErrorIs(t, got, context.DeadlineExceeded,
			"the stream hung instead of reporting the oversized event")
		// Not merely "some error": without the bound this event is buffered
		// whole and then fails to decode, which would satisfy the assertion
		// above while the megabytes were still read into memory.
		require.ErrorContains(t, got, "exceeds",
			"the event was buffered and rejected by the decoder, not by the size bound")
	})
}
