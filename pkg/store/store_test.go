package store_test

import (
	"testing"
	"time"

	"github.com/fil-forge/swarf/pkg/store"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/stretchr/testify/require"
)

func TestRevocationEvent(t *testing.T) {
	cause := invoke(t)
	recordedAt := time.Now()
	event := store.RevocationEvent(store.RevocationRecord{Cause: cause, RecordedAt: recordedAt})

	require.Equal(t, store.EventKindRevocation, event.Kind)
	require.NotNil(t, event.Revocation)
	require.Nil(t, event.PrincipalRevocation)
	require.Equal(t, cause.Link(), event.Cause().Link())
	require.True(t, event.RecordedAt().Equal(recordedAt))
}

func TestPrincipalRevocationEvent(t *testing.T) {
	cause := invoke(t)
	recordedAt := time.Now()
	tenant, err := did.Parse("did:plc:tenant")
	require.NoError(t, err)
	event := store.PrincipalRevocationEvent(store.PrincipalRevocationRecord{Tenant: tenant, Principal: "alice", Cause: cause, RecordedAt: recordedAt})

	require.Equal(t, store.EventKindPrincipalRevocation, event.Kind)
	require.Nil(t, event.Revocation)
	require.NotNil(t, event.PrincipalRevocation)
	require.Equal(t, tenant, event.PrincipalRevocation.Tenant)
	require.Equal(t, "alice", event.PrincipalRevocation.Principal)
	require.Equal(t, cause.Link(), event.Cause().Link())
	require.True(t, event.RecordedAt().Equal(recordedAt))
}

func TestEmptyEvent(t *testing.T) {
	var event store.Event
	require.Nil(t, event.Cause())
	require.True(t, event.RecordedAt().IsZero())
}

func invoke(t *testing.T) *invocation.Invocation {
	t.Helper()
	issuer, err := ed25519.GenerateIssuer()
	require.NoError(t, err)
	cmd, err := command.Parse("/test/invoke")
	require.NoError(t, err)
	inv, err := invocation.Invoke(issuer, did.Undef, cmd, nil)
	require.NoError(t, err)
	return inv
}
