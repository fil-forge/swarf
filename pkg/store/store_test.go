package store_test

import (
	"testing"

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
