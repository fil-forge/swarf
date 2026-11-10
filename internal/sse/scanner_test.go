package sse_test

import (
	"strings"
	"testing"

	"github.com/fil-forge/swarf/internal/sse"
	"github.com/stretchr/testify/require"
)

type event struct {
	name string
	data string
}

func TestScannerReadsEvents(t *testing.T) {
	for _, test := range []struct {
		name   string
		stream string
		want   []event
	}{
		{
			name:   "one named event",
			stream: "event: revocation\ndata: {}\n\n",
			want:   []event{{name: "revocation", data: "{}"}},
		},
		{
			name:   "data lines are joined by newlines",
			stream: "event: revocation\ndata: one\ndata: two\n\n",
			want:   []event{{name: "revocation", data: "one\ntwo"}},
		},
		{
			name:   "other fields and comments are ignored",
			stream: ": keep-alive\nretry: 1000\nevent: revocation\ndata: {}\n\n",
			want:   []event{{name: "revocation", data: "{}"}},
		},
		{
			name:   "successive events",
			stream: "event: revocation\ndata: one\n\nevent: error\ndata: two\n\n",
			want:   []event{{name: "revocation", data: "one"}, {name: "error", data: "two"}},
		},
		{
			// Per the event stream format, an event with no data is not
			// dispatched -- and it must not reset the next event either.
			name:   "an event with no data is not reported",
			stream: "event: revocation\n\nevent: revocation\ndata: {}\n\n",
			want:   []event{{name: "revocation", data: "{}"}},
		},
		{
			name:   "data with no event name is reported unnamed",
			stream: "data: {}\n\n",
			want:   []event{{name: "", data: "{}"}},
		},
		{
			// A truncated stream: the caller reconnects rather than acting on
			// half an event.
			name:   "an unterminated event is not reported",
			stream: "event: revocation\ndata: {}\n",
			want:   nil,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			scanner := sse.NewScanner(strings.NewReader(test.stream))
			var got []event
			for scanner.Scan() {
				got = append(got, event{name: scanner.Event(), data: scanner.Data()})
			}
			require.NoError(t, scanner.Err())
			require.Equal(t, test.want, got)
		})
	}
}

// The last event ID follows the event stream format: an id field sets it when
// its event is dispatched, it carries over events that name none, and an
// event without data, which Scan does not report, still sets it.
func TestScannerReportsTheLastEventID(t *testing.T) {
	type idEvent struct {
		id   string
		data string
	}
	for _, test := range []struct {
		name   string
		stream string
		want   []idEvent
		// last is the last event ID once the stream ends.
		last string
	}{
		{
			name:   "an event's id",
			stream: "id: 1-a\nevent: revocation\ndata: one\n\nid: 2-b\nevent: revocation\ndata: two\n\n",
			want:   []idEvent{{id: "1-a", data: "one"}, {id: "2-b", data: "two"}},
			last:   "2-b",
		},
		{
			name:   "carried over an event that names none",
			stream: "id: 1-a\ndata: one\n\ndata: two\n\n",
			want:   []idEvent{{id: "1-a", data: "one"}, {id: "1-a", data: "two"}},
			last:   "1-a",
		},
		{
			name:   "set by an event without data",
			stream: "id: 7\n\ndata: one\n\nid: 8\n\n",
			want:   []idEvent{{id: "7", data: "one"}},
			last:   "8",
		},
		{
			name:   "not set by an unterminated event",
			stream: "id: 1-a\ndata: one\n\nid: 2-b\ndata: two\n",
			want:   []idEvent{{id: "1-a", data: "one"}},
			last:   "1-a",
		},
		{
			name:   "cleared by an empty id",
			stream: "id: 1-a\ndata: one\n\nid:\ndata: two\n\n",
			want:   []idEvent{{id: "1-a", data: "one"}, {id: "", data: "two"}},
			last:   "",
		},
		{
			name:   "an id holding NUL is ignored",
			stream: "id: 1-a\ndata: one\n\nid: 2\x00b\ndata: two\n\n",
			want:   []idEvent{{id: "1-a", data: "one"}, {id: "1-a", data: "two"}},
			last:   "1-a",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			scanner := sse.NewScanner(strings.NewReader(test.stream))
			var got []idEvent
			for scanner.Scan() {
				got = append(got, idEvent{id: scanner.ID(), data: scanner.Data()})
			}
			require.NoError(t, scanner.Err())
			require.Equal(t, test.want, got)
			require.Equal(t, test.last, scanner.ID())
		})
	}
}

func TestScannerRejectsAnOversizedEvent(t *testing.T) {
	stream := "event: revocation\ndata: " + strings.Repeat("a", sse.MaxEventBytes+1) + "\n\n"
	scanner := sse.NewScanner(strings.NewReader(stream))

	require.False(t, scanner.Scan())
	require.ErrorIs(t, scanner.Err(), sse.ErrEventTooLong,
		"an event past MaxEventBytes must be reported, not silently dropped")
}

// The limit is on the data, not on the line carrying it, so it lands in the
// same place whichever bound catches it.
func TestScannerLimitIsExactOnOneLine(t *testing.T) {
	for _, test := range []struct {
		name string
		size int
		want error
	}{
		{"exactly MaxEventBytes is read", sse.MaxEventBytes, nil},
		{"one byte past is rejected", sse.MaxEventBytes + 1, sse.ErrEventTooLong},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := strings.Repeat("a", test.size)
			scanner := sse.NewScanner(strings.NewReader("event: revocation\ndata: " + data + "\n\n"))

			require.Equal(t, test.want == nil, scanner.Scan())
			if test.want == nil {
				require.Len(t, scanner.Data(), test.size)
				require.NoError(t, scanner.Err())
			} else {
				require.ErrorIs(t, scanner.Err(), test.want)
			}
		})
	}
}

// The bound has to hold however the event is laid out. bufio.Scanner can only
// cap one line, so an event assembled from many small data lines used to have
// no bound at all: 16 MiB of 1 KiB lines scanned clean, four times over the
// limit the package documents.
func TestScannerRejectsAnOversizedEventSplitAcrossLines(t *testing.T) {
	line := "data: " + strings.Repeat("a", 1024) + "\n"
	stream := "event: revocation\n" + strings.Repeat(line, 16*1024) + "\n"
	scanner := sse.NewScanner(strings.NewReader(stream))

	require.False(t, scanner.Scan())
	require.ErrorIs(t, scanner.Err(), sse.ErrEventTooLong)
	require.Empty(t, scanner.Data(), "a rejected event must not be readable")
}

// Scanning stops at the first error, as bufio.Scanner does: an event the
// reader gave up on leaves the stream mid-event, so what follows is not
// events, and resyncing on the next blank line would report a fragment.
func TestScannerStaysStoppedAfterAnOversizedEvent(t *testing.T) {
	oversized := strings.Repeat("data: "+strings.Repeat("a", 1024)+"\n", 16*1024)
	scanner := sse.NewScanner(strings.NewReader(oversized + "\nevent: revocation\ndata: {}\n\n"))

	require.False(t, scanner.Scan())
	require.False(t, scanner.Scan(), "scanning resumed after giving up")
	require.ErrorIs(t, scanner.Err(), sse.ErrEventTooLong)
}

// The limit is on the joined data, so an event just under it still arrives
// however many lines carry it.
func TestScannerReadsAnEventJustUnderTheLimitAcrossLines(t *testing.T) {
	const lines = 1024
	// lines chunks joined by lines-1 newlines, one byte short of the limit.
	chunk := strings.Repeat("a", (sse.MaxEventBytes-(lines-1)-1)/lines)
	var stream strings.Builder
	stream.WriteString("event: revocation\n")
	for range lines {
		stream.WriteString("data: " + chunk + "\n")
	}
	stream.WriteString("\n")
	scanner := sse.NewScanner(strings.NewReader(stream.String()))

	require.True(t, scanner.Scan())
	require.NoError(t, scanner.Err())
	require.LessOrEqual(t, len(scanner.Data()), sse.MaxEventBytes)
	require.Equal(t, lines, strings.Count(scanner.Data(), "\n")+1)
}

func TestScannerReadsPastTheDefaultBufioLimit(t *testing.T) {
	// The whole reason this package exists: bufio.Scanner's own default caps a
	// token at 64 KiB, and a revocation with a long delegation path exceeds it.
	data := strings.Repeat("a", 512*1024)
	scanner := sse.NewScanner(strings.NewReader("event: revocation\ndata: " + data + "\n\n"))

	require.True(t, scanner.Scan())
	require.Equal(t, "revocation", scanner.Event())
	require.Equal(t, data, scanner.Data())
	require.NoError(t, scanner.Err())
}
