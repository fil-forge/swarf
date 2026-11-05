package store

import (
	"cmp"
	"context"
	"fmt"
	"iter"
	"strconv"
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
// Seq order, each with its own cursor, and a stream that starts after a cursor
// yields only the records whose Seq is greater. The store numbers its records,
// so a cursor means something only to the store that issued it. Outside Swarf
// a cursor travels as its String form.
//
// The zero Cursor is ordered before every record.
type Cursor struct {
	Seq uint64
}

// Compare returns -1, 0, or +1 as c is ordered before, at, or after other.
func (c Cursor) Compare(other Cursor) int {
	return cmp.Compare(c.Seq, other.Seq)
}

// String encodes c as Seq in decimal.
func (c Cursor) String() string {
	return strconv.FormatUint(c.Seq, 10)
}

// ParseCursor decodes a cursor from its String form: a decimal number with no
// sign, in the range of a uint64.
func ParseCursor(s string) (Cursor, error) {
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return Cursor{}, fmt.Errorf("invalid cursor %q", s)
	}
	return Cursor{Seq: n}, nil
}

// StreamRecord is a revocation record as a stream yields it.
type StreamRecord struct {
	RevocationRecord
	// Cursor is the record's position in the stream.
	Cursor Cursor
}

// Revocation is a revocation to store with [RevocationStore.AddBatch].
type Revocation struct {
	// Cause is the invocation that revoked the delegation.
	Cause ucan.Invocation
	// Path is the delegation chain from the root delegation to the revoked
	// delegation.
	Path []ucan.Delegation
}

type RevocationStore interface {
	// Add adds a revocation record to the store. The path is the delegation chain
	// from the root delegation to the revoked delegation. The issuer of the
	// revocation must appear as a delegation issuer in the path.
	Add(ctx context.Context, revocation ucan.Invocation, path []ucan.Delegation) error
	// AddBatch adds several revocation records with a single write, as [Add]
	// does for one. A revocation already stored, or repeated within the batch,
	// is stored once and keeps its first record. The records the batch adds
	// share the same RecordedAt. When the write fails, none of them is stored.
	AddBatch(ctx context.Context, revocations []Revocation) error
	// Get retrieves a revocation record from the store by revoked delegation CID.
	// If the record is not found, [ErrNotFound] is returned.
	Get(ctx context.Context, revoked cid.Cid) (RevocationRecord, error)
	// Head returns the cursor at the head of the stream, that of the last
	// record to reach it, or the zero cursor when no record has. A stream
	// after it yields every record that reaches the stream from then on,
	// including any whose write was still in progress when Head was called.
	// Every cursor the store has issued is at or before its head.
	Head(ctx context.Context) (Cursor, error)
	// Stream yields the records after the after cursor, in cursor order, and
	// remains open until the context is canceled. The zero cursor starts at
	// the beginning of the stream.
	//
	// A record reaches the stream only once no record can be added ahead of
	// it, so a stream started after the cursor of the last record another
	// stream yielded misses nothing.
	Stream(ctx context.Context, after Cursor) iter.Seq2[StreamRecord, error]
}
