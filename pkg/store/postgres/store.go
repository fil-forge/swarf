// Package postgres provides a PostgreSQL-backed revocation store.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"time"

	"github.com/fil-forge/swarf/pkg/store"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/ipfs/go-cid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const streamPollInterval = time.Second

// Store persists revocation records in PostgreSQL.
type Store struct {
	pool *pgxpool.Pool
}

// New creates a revocation store backed by pool.
func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

var _ store.RevocationStore = (*Store)(nil)

// Add stores revocation and its witness path.
func (s *Store) Add(ctx context.Context, revocation ucan.Invocation, path []ucan.Delegation) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(path) == 0 {
		return errors.New("revocation path must contain the revoked delegation")
	}

	revocationBytes, err := invocation.Encode(revocation)
	if err != nil {
		return fmt.Errorf("encoding revocation: %w", err)
	}
	pathWitness := make([][]byte, len(path))
	for i, dlg := range path {
		pathWitness[i], err = delegation.Encode(dlg)
		if err != nil {
			return fmt.Errorf("encoding delegation at path index %d: %w", i, err)
		}
	}

	_, err = s.pool.Exec(
		ctx,
		`INSERT INTO revocation (id, cause, revoked_delegation, path_witness)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (id) DO NOTHING`,
		revocation.Link().String(),
		revocationBytes,
		path[len(path)-1].Link().String(),
		pathWitness,
	)
	if err != nil {
		return fmt.Errorf("storing revocation: %w", err)
	}
	return nil
}

// Get retrieves the most recently stored revocation record for a delegation.
func (s *Store) Get(ctx context.Context, revoked cid.Cid) (store.RevocationRecord, error) {
	row := s.pool.QueryRow(
		ctx,
		`SELECT cause, revoked_delegation, path_witness, recorded_at
		 FROM revocation
		 WHERE revoked_delegation = $1
		 ORDER BY recorded_at DESC, id DESC
		 LIMIT 1`,
		revoked.String(),
	)
	var causeBytes []byte
	var revoke string
	var pathWitness [][]byte
	var recordedAt time.Time
	err := row.Scan(&causeBytes, &revoke, &pathWitness, &recordedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.RevocationRecord{}, store.ErrNotFound
	}
	if err != nil {
		return store.RevocationRecord{}, fmt.Errorf("getting revocation: %w", err)
	}
	record, err := decodeRecord(causeBytes, revoke, pathWitness, recordedAt)
	if err != nil {
		return store.RevocationRecord{}, fmt.Errorf("decoding revocation: %w", err)
	}
	return record, nil
}

// Head returns the cursor at the transaction horizon, which Stream describes.
// Rows at or above it, including any whose transactions committed but that
// have not reached the stream, are after it.
func (s *Store) Head(ctx context.Context) (store.Cursor, error) {
	var horizon uint64
	if err := s.pool.QueryRow(ctx, `SELECT pg_snapshot_xmin(pg_current_snapshot())`).Scan(&horizon); err != nil {
		return store.Cursor{}, fmt.Errorf("reading transaction horizon: %w", err)
	}
	return store.Cursor{Seq: horizon}, nil
}

// Stream yields matching revocation records and remains open until ctx is
// canceled. A record's cursor is the ID of the transaction that inserted it
// and the record's id.
//
// Rows become visible out of recorded_at order: recorded_at is the inserting
// transaction's start time, and a transaction that started first can commit
// last. So the stream is ordered by the inserting transaction's ID instead,
// and each poll reads only rows below the transaction horizon, the oldest
// transaction ID still running. Every transaction below the horizon has
// finished, and any other transaction has or will get an ID at or above it,
// so once a row is below the horizon no row can appear ahead of it, and each
// poll resumes strictly after the last row yielded.
//
// The trade-off is that the horizon is cluster-wide: a transaction that holds
// a transaction ID and stays open, such as a long-running one or a session
// idle in transaction, holds the horizon back and delays the stream until it
// ends, whichever database it runs in. A transaction gets an ID when it first
// writes or locks rows; one that only reads holds none and does not.
//
// Transaction IDs are also the cluster's own: a row copied to another cluster
// keeps its ID, but new rows there get that cluster's. README.md says what
// moving the database involves.
func (s *Store) Stream(ctx context.Context, after store.Cursor, from time.Time) iter.Seq2[store.StreamRecord, error] {
	return func(yield func(store.StreamRecord, error) bool) {
		ticker := time.NewTicker(streamPollInterval)
		defer ticker.Stop()

		for {
			if err := ctx.Err(); err != nil {
				yield(store.StreamRecord{}, err)
				return
			}

			for rec, err := range s.recordsAfter(ctx, after, from) {
				if err != nil {
					yield(store.StreamRecord{}, err)
					return
				}
				if !yield(rec, nil) {
					return
				}
				after = rec.Cursor
			}

			select {
			case <-ctx.Done():
				yield(store.StreamRecord{}, ctx.Err())
				return
			case <-ticker.C:
			}
		}
	}
}

func (s *Store) recordsAfter(ctx context.Context, after store.Cursor, from time.Time) iter.Seq2[store.StreamRecord, error] {
	return func(yield func(store.StreamRecord, error) bool) {
		// pg_current_snapshot is the statement's own snapshot, so every row
		// below its horizon is visible to this query. id is ordered bytewise,
		// as store.Cursor orders it, whatever the database's collation. The
		// zero from predates every record, so an unbounded stream matches
		// everything.
		rows, err := s.pool.Query(
			ctx,
			`SELECT transaction_id, id, cause, revoked_delegation, path_witness, recorded_at
			 FROM revocation
			 WHERE (transaction_id, id COLLATE "C") > ($1, $2)
			   AND transaction_id < pg_snapshot_xmin(pg_current_snapshot())
			   AND recorded_at >= $3
			 ORDER BY transaction_id, id COLLATE "C"`,
			after.Seq,
			after.ID,
			from,
		)
		if err != nil {
			yield(store.StreamRecord{}, fmt.Errorf("querying revocations: %w", err))
			return
		}
		defer rows.Close()

		for rows.Next() {
			var cursor store.Cursor
			var causeBytes []byte
			var revoke string
			var pathWitness [][]byte
			var recordedAt time.Time
			if err := rows.Scan(&cursor.Seq, &cursor.ID, &causeBytes, &revoke, &pathWitness, &recordedAt); err != nil {
				yield(store.StreamRecord{}, fmt.Errorf("scanning revocation: %w", err))
				return
			}
			record, err := decodeRecord(causeBytes, revoke, pathWitness, recordedAt)
			if err != nil {
				yield(store.StreamRecord{}, fmt.Errorf("decoding revocation: %w", err))
				return
			}
			if !yield(store.StreamRecord{RevocationRecord: record, Cursor: cursor}, nil) {
				return
			}
		}
		if err := rows.Err(); err != nil {
			yield(store.StreamRecord{}, fmt.Errorf("iterating revocations: %w", err))
		}
	}
}

func decodeRecord(causeBytes []byte, revoke string, pathWitness [][]byte, recordedAt time.Time) (store.RevocationRecord, error) {
	cause, err := invocation.Decode(causeBytes)
	if err != nil {
		return store.RevocationRecord{}, fmt.Errorf("decoding revocation cause: %w", err)
	}
	revokeLink, err := cid.Decode(revoke)
	if err != nil {
		return store.RevocationRecord{}, fmt.Errorf("decoding revoked delegation CID: %w", err)
	}
	path := make([]ucan.Delegation, len(pathWitness))
	for i, witness := range pathWitness {
		path[i], err = delegation.Decode(witness)
		if err != nil {
			return store.RevocationRecord{}, fmt.Errorf("decoding delegation at path index %d: %w", i, err)
		}
	}
	return store.RevocationRecord{
		Revoke:     revokeLink,
		Cause:      cause,
		Path:       path,
		RecordedAt: recordedAt,
	}, nil
}
