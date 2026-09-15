package memory

import (
	"context"
	"testing"
	"time"

	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/stretchr/testify/require"
)

// The clock must be read while the store lock is held: that is what keeps the
// sequence order equal to the time order under concurrent Adds. The test's
// clock proves it by failing to take the lock from inside the clock call.
func TestAddStampsRecordedAtUnderLock(t *testing.T) {
	s := New()
	stamp := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	calls := 0
	s.now = func() time.Time {
		calls++
		require.False(t, s.mu.TryLock(), "clock read outside the store lock")
		return stamp
	}

	issuer, err := ed25519.GenerateIssuer()
	require.NoError(t, err)
	revoked, err := delegation.Delegate(issuer, issuer.DID(), issuer.DID(), command.MustParse("/test"))
	require.NoError(t, err)
	revocation, err := invocation.Invoke(issuer, issuer.DID(), command.MustParse("/ucan/revoke"), nil)
	require.NoError(t, err)

	require.NoError(t, s.Add(context.Background(), revocation, []ucan.Delegation{revoked}))
	require.Equal(t, 1, calls)
	rec, err := s.Get(context.Background(), revoked.Link())
	require.NoError(t, err)
	require.True(t, rec.RecordedAt.Equal(stamp))
}
