// Package api defines the DAG-JSON records returned by Swarf.
package api

import (
	jsg "github.com/alanshaw/dag-json-gen"
	"github.com/ipfs/go-cid"
)

// Revocation is the serialized representation returned by revocation lookup
// requests.
type Revocation struct {
	Revoke    cid.Cid         `dagjsongen:"revoke"`
	Path      [][]byte        `dagjsongen:"path"`
	Cause     []byte          `dagjsongen:"cause"`
	CreatedAt jsg.DagJsonTime `dagjsongen:"created_at"`
}

// FirehoseRevocation is the compact representation emitted by the revocation
// firehose.
type FirehoseRevocation struct {
	Revoke    cid.Cid         `dagjsongen:"revoke"`
	Path      []cid.Cid       `dagjsongen:"path"`
	Cause     cid.Cid         `dagjsongen:"cause"`
	CreatedAt jsg.DagJsonTime `dagjsongen:"created_at"`
}
