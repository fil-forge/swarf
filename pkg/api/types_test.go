package api_test

import (
	"bytes"
	"testing"
	"time"

	jsg "github.com/alanshaw/dag-json-gen"
	"github.com/fil-forge/swarf/pkg/api"
	"github.com/fil-forge/ucantone/did"
	"github.com/ipfs/go-cid"
	"github.com/stretchr/testify/require"
)

func TestFirehosePrincipalRevocationRoundTrip(t *testing.T) {
	tenant, err := did.Parse("did:plc:tenant")
	require.NoError(t, err)
	cause, err := cid.Decode("bafyreif5fzax7oygfafacvxq2ndhtkshz2av5m42hqeixea7giirdxe5dm")
	require.NoError(t, err)
	recordedAt := time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)
	value := api.FirehosePrincipalRevocation{
		Tenant:     tenant,
		Principal:  "8f2c",
		Cause:      cause,
		RecordedAt: jsg.DagJsonTime(recordedAt),
	}

	var data bytes.Buffer
	require.NoError(t, value.MarshalDagJSON(&data))
	require.JSONEq(t, `{
		"cause": {"/": "bafyreif5fzax7oygfafacvxq2ndhtkshz2av5m42hqeixea7giirdxe5dm"},
		"principal": "8f2c",
		"recorded_at": 1788948000000000000,
		"tenant": "did:plc:tenant"
	}`, data.String())

	var decoded api.FirehosePrincipalRevocation
	require.NoError(t, decoded.UnmarshalDagJSON(&data))
	require.Equal(t, tenant, decoded.Tenant)
	require.Equal(t, "8f2c", decoded.Principal)
	require.Equal(t, cause, decoded.Cause)
	require.True(t, decoded.RecordedAt.Time().Equal(recordedAt))
}

func TestFirehoseEvent(t *testing.T) {
	cause, err := cid.Decode("bafyreif5fzax7oygfafacvxq2ndhtkshz2av5m42hqeixea7giirdxe5dm")
	require.NoError(t, err)
	recordedAt := jsg.DagJsonTime(time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC))

	revocation := api.FirehoseEvent{Revocation: &api.FirehoseRevocation{Cause: cause, RecordedAt: recordedAt}}
	require.Equal(t, cause, revocation.Cause())
	require.Equal(t, recordedAt, revocation.RecordedAt())

	principal := api.FirehoseEvent{PrincipalRevocation: &api.FirehosePrincipalRevocation{Cause: cause, RecordedAt: recordedAt}}
	require.Equal(t, cause, principal.Cause())
	require.Equal(t, recordedAt, principal.RecordedAt())

	var empty api.FirehoseEvent
	require.Equal(t, cid.Undef, empty.Cause())
	require.True(t, empty.RecordedAt().Time().IsZero())
}
