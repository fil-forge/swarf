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

type RevocationStore interface {
	// Add stores one revocation record per path, all caused by the revocation
	// invocation, with a single write. Each path is the delegation chain from
	// the root delegation to a revoked delegation. The issuer of the revocation
	// must appear as a delegation issuer in every path.
	Add(ctx context.Context, revocation ucan.Invocation, paths [][]ucan.Delegation) error
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

// RecordKey identifies a revocation record. One invocation can revoke several
// delegations, so the cause alone does not identify a record.
type RecordKey struct {
	Cause  cid.Cid
	Revoke cid.Cid
}

// Key returns the key identifying the record.
func (r RevocationRecord) Key() RecordKey {
	return RecordKey{Cause: r.Cause.Link(), Revoke: r.Revoke}
}
