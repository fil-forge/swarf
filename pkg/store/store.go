package store

import (
	"cmp"
	"context"
	"fmt"
	"iter"
	"strconv"
	"strings"
	"time"

	"github.com/fil-forge/ucantone/errors"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/ipfs/go-cid"
)

const NotFoundErrorName = "NotFound"

var ErrNotFound = errors.New(NotFoundErrorName, "not found")

type RevocationRecord struct {
	// Revoke is the CID of the revoked delegation.
	Revoke cid.Cid
	// Path is the delegation chain from the root delegation to the
	// revoked delegation.
	Path []ucan.Delegation
	// Cause is the invocation that revoked the delegation.
	Cause ucan.Invocation
	// RecordedAt is the time when the revocation record was recorded. Note this
	// is not necessarily the time when the revocation was issued.
	RecordedAt time.Time
}

// Cursor is a position in the revocation stream. A stream yields records in
// cursor order, each with its own cursor, and a stream that starts after a
// cursor yields only the records ordered after it. Records are ordered by Seq
// and then by ID, and what those hold is up to the store, so a cursor means
// something only to the store that issued it. Outside Swarf a cursor travels
// as its String form, which is opaque.
//
// The zero Cursor is ordered before every record.
type Cursor struct {
	Seq uint64
	ID  string
}

// Compare returns -1, 0, or +1 as c is ordered before, at, or after other.
func (c Cursor) Compare(other Cursor) int {
	return cmp.Or(cmp.Compare(c.Seq, other.Seq), strings.Compare(c.ID, other.ID))
}

// String encodes c as Seq in decimal, followed by a hyphen and ID when ID is
// set.
func (c Cursor) String() string {
	seq := strconv.FormatUint(c.Seq, 10)
	if c.ID == "" {
		return seq
	}
	return seq + "-" + c.ID
}

// ParseCursor decodes a cursor from its String form.
func ParseCursor(s string) (Cursor, error) {
	seq, id, hasID := strings.Cut(s, "-")
	n, err := strconv.ParseUint(seq, 10, 64)
	if err != nil || (hasID && id == "") {
		return Cursor{}, fmt.Errorf("invalid cursor %q", s)
	}
	return Cursor{Seq: n, ID: id}, nil
}

// StreamRecord is a revocation record as a stream yields it.
type StreamRecord struct {
	RevocationRecord
	// Cursor is the record's position in the stream.
	Cursor Cursor
}

type RevocationStore interface {
	// Add adds a revocation record to the store. The path is the delegation chain
	// from the root delegation to the revoked delegation. The issuer of the
	// revocation must appear as a delegation issuer in the path.
	Add(ctx context.Context, revocation ucan.Invocation, path []ucan.Delegation) error
	// Get retrieves a revocation record from the store by revoked delegation CID.
	// If the record is not found, [ErrNotFound] is returned.
	Get(ctx context.Context, revoked cid.Cid) (RevocationRecord, error)
	// Head returns the cursor at the head of the stream: a stream after it
	// yields every record that reaches the stream from then on. It can also
	// yield records added shortly before Head was called that had not reached
	// the stream yet.
	Head(ctx context.Context) (Cursor, error)
	// Stream yields the records ordered after the after cursor and recorded on
	// or after from, in cursor order, and remains open until the context is
	// canceled. The zero cursor starts at the beginning of the stream, and the
	// zero time admits every record.
	//
	// A record reaches the stream only once no record can be added ahead of
	// it, so a stream started after the cursor of the last record another
	// stream yielded, with the same from, misses nothing.
	Stream(ctx context.Context, after Cursor, from time.Time) iter.Seq2[StreamRecord, error]
}
