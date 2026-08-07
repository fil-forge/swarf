package client

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
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

	var streamed int
	for record, err := range client.Stream(context.Background(), time.Time{}) {
		require.NoError(t, err)
		require.Equal(t, revocation.Link(), record.Revoke)
		require.Equal(t, []cid.Cid{revocation.Link()}, record.Path)
		require.Equal(t, revocation.Link(), record.Cause)
		require.True(t, record.RecordedAt.Time().Equal(recordedAt))
		streamed++
	}
	require.Equal(t, 1, streamed)
}
