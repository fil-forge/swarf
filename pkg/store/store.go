package store

import (
	"context"
	"iter"
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
	// Stream streams all revocation records from the store and remains open until
	// the context is canceled. The from parameter filters records to those
	// recorded on or after the given time, so consumers resuming from the
	// timestamp of the last record they received do not miss records that share
	// it. If from is zero, all records are returned.
	Stream(ctx context.Context, from time.Time) iter.Seq2[RevocationRecord, error]
}
