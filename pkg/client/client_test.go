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
	"github.com/fil-forge/libforge/identity"
	"github.com/fil-forge/swarf/pkg/api"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/ipfs/go-cid"
	"github.com/stretchr/testify/require"
)

func TestGetAndStream(t *testing.T) {
	issuer, err := identity.New("", "")
	require.NoError(t, err)
	command, err := command.Parse("/test/revoke")
	require.NoError(t, err)
	revocation, err := invocation.Invoke(issuer, did.Undef, command, nil)
	require.NoError(t, err)
	encoded, err := invocation.Encode(revocation)
	require.NoError(t, err)
	createdAt := time.Now().UTC().Round(0)
	lookupValue := api.Revocation{
		Revoke:    revocation.Link(),
		Cause:     encoded,
		CreatedAt: jsg.DagJsonTime(createdAt),
	}
	var lookupPayload bytes.Buffer
	require.NoError(t, lookupValue.MarshalDagJSON(&lookupPayload))
	streamValue := api.FirehoseRevocation{
		Revoke:    revocation.Link(),
		Path:      []cid.Cid{revocation.Link()},
		Cause:     revocation.Link(),
		CreatedAt: jsg.DagJsonTime(createdAt),
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
	client, err := New(issuer.DID(), *serviceURL, issuer)
	require.NoError(t, err)

	record, err := client.Get(context.Background(), revocation.Link())
	require.NoError(t, err)
	require.Equal(t, revocation.Link(), record.Revoke)
	require.Equal(t, revocation.Link(), record.Cause.Link())
	require.True(t, record.CreatedAt.Equal(createdAt))

	var streamed int
	for record, err := range client.Stream(context.Background(), time.Time{}) {
		require.NoError(t, err)
		require.Equal(t, revocation.Link(), record.Revoke)
		require.Equal(t, []cid.Cid{revocation.Link()}, record.Path)
		require.Equal(t, revocation.Link(), record.Cause)
		require.True(t, record.CreatedAt.Time().Equal(createdAt))
		streamed++
	}
	require.Equal(t, 1, streamed)
}
