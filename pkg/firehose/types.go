// Package firehose defines the DAG-JSON records emitted by the revocation firehose.
package firehose

import jsg "github.com/alanshaw/dag-json-gen"

// Record is the serialized representation of a revocation record.
type Record struct {
	Revocation []byte          `dagjsongen:"revocation"`
	Path       [][]byte        `dagjsongen:"path"`
	CreatedAt  jsg.DagJsonTime `dagjsongen:"created_at"`
}
