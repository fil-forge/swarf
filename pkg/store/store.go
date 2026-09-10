package store

import (
	"context"
	"iter"
	"time"

	"github.com/fil-forge/ucantone/did"
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

// PrincipalRevocationRecord records that every proof cached for a principal's
// keys is void. It names the principal and no delegation.
type PrincipalRevocationRecord struct {
	// Tenant is the DID of the tenant the principal belongs to.
	Tenant did.DID
	// Principal is the principal's identifier, unique within the tenant.
	Principal string
	// Cause is the invocation that invalidated the principal.
	Cause ucan.Invocation
	// RecordedAt is the time when the record was recorded. Note this is not
	// necessarily the time when the invalidation was issued.
	RecordedAt time.Time
}

// EventKind names the kind of record an [Event] carries.
type EventKind string

const (
	// EventKindRevocation marks an event carrying a [RevocationRecord].
	EventKindRevocation EventKind = "revocation"
	// EventKindPrincipalRevocation marks an event carrying a
	// [PrincipalRevocationRecord].
	EventKindPrincipalRevocation EventKind = "principal"
)

// Event is one record streamed from the store. Exactly one of Revocation and
// PrincipalRevocation is set, as named by Kind.
type Event struct {
	Kind                EventKind
	Revocation          *RevocationRecord
	PrincipalRevocation *PrincipalRevocationRecord
}

// RevocationEvent wraps a revocation record as an [Event].
func RevocationEvent(record RevocationRecord) Event {
	return Event{Kind: EventKindRevocation, Revocation: &record}
}

// PrincipalRevocationEvent wraps a principal revocation record as an [Event].
func PrincipalRevocationEvent(record PrincipalRevocationRecord) Event {
	return Event{Kind: EventKindPrincipalRevocation, PrincipalRevocation: &record}
}

// Cause returns the invocation that caused the event's record, or nil when
// the event carries no record.
func (e Event) Cause() ucan.Invocation {
	switch {
	case e.Revocation != nil:
		return e.Revocation.Cause
	case e.PrincipalRevocation != nil:
		return e.PrincipalRevocation.Cause
	default:
		return nil
	}
}

// RecordedAt returns the time the event's record was recorded, or the zero
// time when the event carries no record.
func (e Event) RecordedAt() time.Time {
	switch {
	case e.Revocation != nil:
		return e.Revocation.RecordedAt
	case e.PrincipalRevocation != nil:
		return e.PrincipalRevocation.RecordedAt
	default:
		return time.Time{}
	}
}

type RevocationStore interface {
	// Add adds a revocation record to the store. The path is the delegation chain
	// from the root delegation to the revoked delegation. The issuer of the
	// revocation must appear as a delegation issuer in the path.
	Add(ctx context.Context, revocation ucan.Invocation, path []ucan.Delegation) error
	// Get retrieves a revocation record from the store by revoked delegation CID.
	// If the record is not found, [ErrNotFound] is returned.
	Get(ctx context.Context, revoked cid.Cid) (RevocationRecord, error)
	// Stream streams all records from the store as events and remains open
	// until the context is canceled. The from parameter filters records to those
	// recorded on or after the given time, so consumers resuming from the
	// timestamp of the last record they received do not miss records that share
	// it. If from is zero, all records are returned.
	Stream(ctx context.Context, from time.Time) iter.Seq2[Event, error]
}
