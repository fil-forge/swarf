// Package api defines the DAG-JSON records returned by Swarf.
package api

import (
	jsg "github.com/alanshaw/dag-json-gen"
	"github.com/fil-forge/ucantone/did"
	"github.com/ipfs/go-cid"
)

// Revocation is the serialized representation returned by revocation lookup
// requests.
type Revocation struct {
	Revoke     cid.Cid         `dagjsongen:"revoke"`
	Path       [][]byte        `dagjsongen:"path"`
	Cause      []byte          `dagjsongen:"cause"`
	RecordedAt jsg.DagJsonTime `dagjsongen:"recorded_at"`
}

// FirehoseRevocation is the compact representation emitted by the revocation
// firehose.
type FirehoseRevocation struct {
	Revoke     cid.Cid         `dagjsongen:"revoke"`
	Path       []cid.Cid       `dagjsongen:"path"`
	Cause      cid.Cid         `dagjsongen:"cause"`
	RecordedAt jsg.DagJsonTime `dagjsongen:"recorded_at"`
}

// FirehosePrincipalRevocation is the representation of a principal
// invalidation emitted by the firehose. It names the principal whose cached
// proofs are void and no delegation.
type FirehosePrincipalRevocation struct {
	Tenant     did.DID         `dagjsongen:"tenant"`
	Principal  string          `dagjsongen:"principal"`
	Cause      cid.Cid         `dagjsongen:"cause"`
	RecordedAt jsg.DagJsonTime `dagjsongen:"recorded_at"`
}

// FirehoseEvent is one event read from the firehose. Exactly one of
// Revocation and Principal is set, matching the SSE event name.
type FirehoseEvent struct {
	Revocation          *FirehoseRevocation
	PrincipalRevocation *FirehosePrincipalRevocation
}

// Cause returns the CID of the invocation that caused the event, or the
// undefined CID when the event carries no record.
func (e FirehoseEvent) Cause() cid.Cid {
	switch {
	case e.Revocation != nil:
		return e.Revocation.Cause
	case e.PrincipalRevocation != nil:
		return e.PrincipalRevocation.Cause
	default:
		return cid.Undef
	}
}

// RecordedAt returns the time the event's record was recorded, or the zero
// time when the event carries no record.
func (e FirehoseEvent) RecordedAt() jsg.DagJsonTime {
	switch {
	case e.Revocation != nil:
		return e.Revocation.RecordedAt
	case e.PrincipalRevocation != nil:
		return e.PrincipalRevocation.RecordedAt
	default:
		return jsg.DagJsonTime{}
	}
}
