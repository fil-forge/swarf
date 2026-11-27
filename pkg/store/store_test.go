package store_test

import (
	"testing"
	"time"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/delegation"

	"github.com/fil-forge/swarf/pkg/store"
	"github.com/stretchr/testify/require"
)

func TestCursorRoundTrips(t *testing.T) {
	for _, cursor := range []store.Cursor{{}, {Seq: 7}, {Seq: 1<<64 - 1}} {
		parsed, err := store.ParseCursor(cursor.String())
		require.NoError(t, err)
		require.Equal(t, cursor, parsed)
	}
}

func TestCursorString(t *testing.T) {
	require.Equal(t, "0", store.Cursor{}.String())
	require.Equal(t, "1734", store.Cursor{Seq: 1734}.String())
}

func TestParseCursorRejectsMalformedCursors(t *testing.T) {
	for _, value := range []string{
		"", "now", "-7", "+7", " 7", "7 ", "0x7", "1_000", "7.0", "bafy", "18446744073709551616",
		// The form a cursor took when it carried a record ID.
		"7-bafy", "7-",
	} {
		_, err := store.ParseCursor(value)
		require.Error(t, err, value)
	}
}

func TestCursorOrder(t *testing.T) {
	ordered := []store.Cursor{{}, {Seq: 1}, {Seq: 2}, {Seq: 1<<64 - 1}}
	for i := range ordered {
		require.Zero(t, ordered[i].Compare(ordered[i]))
		for j := i + 1; j < len(ordered); j++ {
			require.Negative(t, ordered[i].Compare(ordered[j]), "%v before %v", ordered[i], ordered[j])
			require.Positive(t, ordered[j].Compare(ordered[i]), "%v after %v", ordered[j], ordered[i])
		}
	}
}

func TestExpiration(t *testing.T) {
	issuer, err := ed25519.GenerateIssuer()
	require.NoError(t, err)
	cmd, err := command.Parse("/test/revoke")
	require.NoError(t, err)
	path := func(option delegation.Option) []ucan.Delegation {
		revoked, err := delegation.Delegate(issuer, issuer.DID(), did.Undef, cmd, option)
		require.NoError(t, err)
		return []ucan.Delegation{revoked}
	}

	require.Nil(t, store.Expiration(nil))
	require.Nil(t, store.Expiration(path(delegation.WithNoExpiration())))

	in := time.Now().Add(time.Hour).Truncate(time.Second)
	got := store.Expiration(path(delegation.WithExpiration(ucan.UnixTimestamp(in.Unix()))))
	require.NotNil(t, got)
	require.True(t, in.Equal(*got))

	// The last second of the year 9999 is kept, and anything after it counts
	// as never expiring.
	last := time.Date(9999, time.December, 31, 23, 59, 59, 0, time.UTC)
	got = store.Expiration(path(delegation.WithExpiration(ucan.UnixTimestamp(last.Unix()))))
	require.NotNil(t, got)
	require.True(t, last.Equal(*got))
	for _, exp := range []ucan.UnixTimestamp{ucan.UnixTimestamp(last.Unix() + 1), 1<<53 - 1, 1<<63 - 1} {
		require.Nil(t, store.Expiration(path(delegation.WithExpiration(exp))), exp)
	}
}
