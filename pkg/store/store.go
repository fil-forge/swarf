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
	// CreatedAt is the time when the revocation record was created. Note this
	// is not necessarily the time when the revocation was issued.
	CreatedAt time.Time
}

type RevocationStore interface {
	// Add adds a revocation record to the store. The path is the delegation chain
	// from the root delegation to the revoked delegation. The issuer of the
	// revocation must appear as a delegation issuer in the path.
	Add(ctx context.Context, revocation ucan.Invocation, path []ucan.Delegation) error
	// Get retrieves a revocation record from the store. The delegation is the
	// revoked delegation. If the record is not found, [ErrNotFound] is returned.
	Get(ctx context.Context, delegation cid.Cid) (RevocationRecord, error)
	// Stream streams all revocation records from the store and remains open until
	// the context is canceled. The since parameter is used to filter records that
	// were added after the given time. If since is zero, all records are returned.
	Stream(ctx context.Context, since time.Time) iter.Seq2[RevocationRecord, error]
}
