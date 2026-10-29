package store_test

import (
	"testing"

	"github.com/fil-forge/swarf/pkg/store"
	"github.com/stretchr/testify/require"
)

func TestCursorRoundTrips(t *testing.T) {
	for _, cursor := range []store.Cursor{
		{},
		{Seq: 7},
		{Seq: 7, ID: "bafyreif5fzax7oygfafacvxq2ndhtkshz2av5m42hqeixea7giirdxe5dm"},
		{Seq: 1<<64 - 1, ID: "with-hyphens"},
	} {
		parsed, err := store.ParseCursor(cursor.String())
		require.NoError(t, err)
		require.Equal(t, cursor, parsed)
	}
}

func TestParseCursorRejectsMalformedCursors(t *testing.T) {
	for _, value := range []string{"", "now", "-7", "7-", "+7", "bafy", "18446744073709551616"} {
		_, err := store.ParseCursor(value)
		require.Error(t, err, value)
	}
}

func TestCursorOrder(t *testing.T) {
	ordered := []store.Cursor{{}, {ID: "a"}, {Seq: 1}, {Seq: 1, ID: "a"}, {Seq: 1, ID: "b"}, {Seq: 2}}
	for i := range ordered {
		require.Zero(t, ordered[i].Compare(ordered[i]))
		for j := i + 1; j < len(ordered); j++ {
			require.Negative(t, ordered[i].Compare(ordered[j]), "%v before %v", ordered[i], ordered[j])
			require.Positive(t, ordered[j].Compare(ordered[i]), "%v after %v", ordered[j], ordered[i])
		}
	}
}
