// Package sse reads server-sent event streams.
//
// It exists because the CLI and the client library both read swarf's
// revocation firehose, and an event stream whose events can be megabytes
// needs the same bounds in both.
package sse

import (
	"bufio"
	"errors"
	"io"
	"strings"
)

// ErrEventTooLong reports an event whose data exceeded MaxEventBytes.
var ErrEventTooLong = errors.New("sse: event too long")

// The size bounds a Scanner reads within. A revocation event carries a CID
// per delegation in the chain, so it runs well past bufio.Scanner's default
// 64 KiB cap; MaxEventBytes is where a Scanner gives up with ErrEventTooLong
// rather than growing without limit.
//
// Two bounds enforce the one limit. Scan caps the data it accumulates across
// an event's lines -- without which an event assembled from many small data
// lines has no bound at all -- and maxLineBytes caps a single line, which is
// all bufio.Scanner itself can do. maxLineBytes carries enough headroom for a
// field name that the accumulated bound is always the one that decides: a
// bufio token holds "data: " as well as the data, and bufio gives up at the
// buffer size rather than one byte past it, so an exact MaxEventBytes would
// reject an event of MaxEventBytes-7.
const (
	initialEventBytes = 64 * 1024
	MaxEventBytes     = 4 * 1024 * 1024
	maxLineBytes      = MaxEventBytes + 1024
)

// A Scanner reads events from a server-sent event stream. Successive calls to
// Scan advance to the next event, whose fields Event and Data then report,
// and ID reports the last event ID. Scanning stops at the end of the stream or
// at the first read error, which Err returns.
//
// Fields other than event, data, and id -- retry, comments -- are ignored, and
// an event carrying no data is not reported, though its id still sets the last
// event ID, which is what the event stream format calls for:
// https://html.spec.whatwg.org/multipage/server-sent-events.html#event-stream-interpretation
type Scanner struct {
	lines *bufio.Scanner
	event string
	data  string
	// id is the last event ID; idBuffer is the id field most recently read,
	// which becomes the last event ID when its event is dispatched.
	id       string
	idBuffer string
	err      error
}

// NewScanner returns a Scanner reading the event stream in r.
func NewScanner(r io.Reader) *Scanner {
	lines := bufio.NewScanner(r)
	lines.Buffer(make([]byte, initialEventBytes), maxLineBytes)
	return &Scanner{lines: lines}
}

// Scan advances to the next event, reporting whether there was one.
func (s *Scanner) Scan() bool {
	if s.err != nil {
		return false
	}
	var event string
	var data []string
	// size is what Data would return for the lines read so far: their lengths
	// plus the newlines joining them.
	size := 0
	for s.lines.Scan() {
		line := s.lines.Text()
		if line == "" {
			s.id = s.idBuffer
			if len(data) > 0 {
				s.event, s.data = event, strings.Join(data, "\n")
				return true
			}
			event = ""
			continue
		}
		if value, ok := strings.CutPrefix(line, "event:"); ok {
			event = strings.TrimSpace(value)
		}
		if value, ok := strings.CutPrefix(line, "id:"); ok && !strings.ContainsRune(value, 0) {
			s.idBuffer = strings.TrimPrefix(value, " ")
		}
		if value, ok := strings.CutPrefix(line, "data:"); ok {
			value = strings.TrimPrefix(value, " ")
			if len(data) > 0 {
				size++
			}
			size += len(value)
			if size > MaxEventBytes {
				// Give up where bufio.Scanner would, rather than buffering an
				// event the reader never bounded.
				s.err = ErrEventTooLong
				break
			}
			data = append(data, value)
		}
	}
	s.event, s.data = "", ""
	return false
}

// Event is the type of the event Scan read, empty if the event named none.
func (s *Scanner) Event() string { return s.event }

// Data is the data of the event Scan read, its data lines joined by newlines.
func (s *Scanner) Data() string { return s.data }

// ID is the last event ID: the id the stream most recently set, by the event
// Scan read or by an event without data before it. It is not cleared when an
// event names no id, and outlasts the end of the stream, so a client
// reconnecting can send it as Last-Event-ID.
func (s *Scanner) ID() string { return s.id }

// Err returns the first read error Scan met, if any. It is ErrEventTooLong
// when one event exceeded MaxEventBytes.
func (s *Scanner) Err() error {
	err := s.err
	if err == nil {
		err = s.lines.Err()
	}
	// A line past maxLineBytes is an event past MaxEventBytes by another
	// route; report the one error for both.
	if errors.Is(err, bufio.ErrTooLong) {
		return ErrEventTooLong
	}
	return err
}
