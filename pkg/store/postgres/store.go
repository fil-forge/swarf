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

// streamSettleWindow bounds how long an insert may take between its
// recorded_at (NOW() at transaction start) and its row becoming visible.
// History older than this window is settled: no new rows can appear there.
const streamSettleWindow = 10 * time.Second

// Store persists revocation records in PostgreSQL.
type Store struct {
	pool *pgxpool.Pool
}

// New creates a revocation store backed by pool.
func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

var _ store.RevocationStore = (*Store)(nil)

// Add stores one revocation record per path, all caused by revocation, with a
// single statement. The statement stores the invocation once, in
// revocation_cause, and each record links to it.
func (s *Store) Add(ctx context.Context, revocation ucan.Invocation, paths [][]ucan.Delegation) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(paths) == 0 {
		return errors.New("at least one revocation path is required")
	}

	revocationBytes, err := invocation.Encode(revocation)
	if err != nil {
		return fmt.Errorf("encoding revocation: %w", err)
	}
	// A Postgres array cannot hold rows of different lengths, so the paths go
	// in as one flat list of delegations plus the bounds of each path in it.
	// Postgres arrays are 1-based and their slices include both bounds.
	var witnesses [][]byte
	revoked := make([]string, len(paths))
	pathStarts := make([]int32, len(paths))
	pathEnds := make([]int32, len(paths))
	for i, path := range paths {
		if len(path) == 0 {
			return fmt.Errorf("revocation path %d must contain the revoked delegation", i)
		}
		pathStarts[i] = int32(len(witnesses) + 1)
		for j, dlg := range path {
			witness, err := delegation.Encode(dlg)
			if err != nil {
				return fmt.Errorf("encoding delegation at index %d of revocation path %d: %w", j, i, err)
			}
			witnesses = append(witnesses, witness)
		}
		pathEnds[i] = int32(len(witnesses))
		revoked[i] = path[len(path)-1].Link().String()
	}

	_, err = s.pool.Exec(
		ctx,
		`WITH cause AS (
		   INSERT INTO revocation_cause (id, invocation)
		   VALUES ($1, $2)
		   ON CONFLICT (id) DO NOTHING
		 )
		 INSERT INTO revocation (cause_id, revoked_delegation, path_witness)
		 SELECT $1, revoked.delegation, ($3::bytea[])[revoked.path_start:revoked.path_end]
		 FROM unnest($4::text[], $5::int[], $6::int[]) AS revoked (delegation, path_start, path_end)
		 ON CONFLICT (cause_id, revoked_delegation) DO NOTHING`,
		revocation.Link().String(),
		revocationBytes,
		witnesses,
		revoked,
		pathStarts,
		pathEnds,
	)
	if err != nil {
		return fmt.Errorf("storing revocations: %w", err)
	}
	return nil
}

// Get retrieves the most recently stored revocation record for a delegation.
func (s *Store) Get(ctx context.Context, revoked cid.Cid) (store.RevocationRecord, error) {
	row := s.pool.QueryRow(
		ctx,
		`SELECT revocation_cause.invocation, revoked_delegation, path_witness, recorded_at
		 FROM revocation
		 JOIN revocation_cause ON revocation_cause.id = revocation.cause_id
		 WHERE revoked_delegation = $1
		 ORDER BY recorded_at DESC, cause_id DESC
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

// Stream returns matching revocation records and remains open until ctx is canceled.
func (s *Store) Stream(ctx context.Context, from time.Time) iter.Seq2[store.RevocationRecord, error] {
	return func(yield func(store.RevocationRecord, error) bool) {
		ticker := time.NewTicker(streamPollInterval)
		defer ticker.Stop()

		// cursor is the low-water mark of each poll. It starts at from and
		// only advances through settled history, because rows can become
		// visible out of recorded_at order: ids are CIDs (not monotonic) and
		// recorded_at is the insert transaction's start time, so a concurrent
		// insert can commit a row at or before timestamps already streamed.
		// Rows re-read from the unsettled window are deduped by seen, keyed
		// by cause and revoked delegation with recorded_at kept for pruning.
		cursor := from
		seen := map[store.RecordKey]time.Time{}
		for {
			if err := ctx.Err(); err != nil {
				yield(store.RevocationRecord{}, err)
				return
			}

			// The horizon is read before the rows so it never overtakes them.
			var dbNow time.Time
			if err := s.pool.QueryRow(ctx, `SELECT now()`).Scan(&dbNow); err != nil {
				yield(store.RevocationRecord{}, fmt.Errorf("reading database clock: %w", err))
				return
			}
			for rec, err := range s.recordsFrom(ctx, cursor) {
				if err != nil {
					yield(store.RevocationRecord{}, err)
					return
				}
				key := rec.Key()
				if _, ok := seen[key]; ok {
					continue
				}
				if !yield(rec, nil) {
					return
				}
				seen[key] = rec.RecordedAt
			}
			if horizon := dbNow.Add(-streamSettleWindow); horizon.After(cursor) {
				cursor = horizon
				for key, recordedAt := range seen {
					if recordedAt.Before(cursor) {
						delete(seen, key)
					}
				}
			}

			select {
			case <-ctx.Done():
				yield(store.RevocationRecord{}, ctx.Err())
				return
			case <-ticker.C:
			}
		}
	}
}

func (s *Store) recordsFrom(ctx context.Context, cursor time.Time) iter.Seq2[store.RevocationRecord, error] {
	return func(yield func(store.RevocationRecord, error) bool) {
		// The query is inclusive at the cursor: each poll re-reads the
		// unsettled window and Stream skips rows it already yielded. The
		// zero cursor predates every record, so an unbounded stream matches
		// everything.
		rows, err := s.pool.Query(
			ctx,
			`SELECT revocation_cause.invocation, revoked_delegation, path_witness, recorded_at
			 FROM revocation
			 JOIN revocation_cause ON revocation_cause.id = revocation.cause_id
			 WHERE recorded_at >= $1
			 ORDER BY recorded_at, cause_id, revoked_delegation`,
			cursor,
		)
		if err != nil {
			yield(store.RevocationRecord{}, fmt.Errorf("querying revocations: %w", err))
			return
		}
		defer rows.Close()

		for rows.Next() {
			var causeBytes []byte
			var revoke string
			var pathWitness [][]byte
			var recordedAt time.Time
			if err := rows.Scan(&causeBytes, &revoke, &pathWitness, &recordedAt); err != nil {
				yield(store.RevocationRecord{}, fmt.Errorf("scanning revocation: %w", err))
				return
			}
			record, err := decodeRecord(causeBytes, revoke, pathWitness, recordedAt)
			if err != nil {
				yield(store.RevocationRecord{}, fmt.Errorf("decoding revocation: %w", err))
				return
			}
			if !yield(record, nil) {
				return
			}
		}
		if err := rows.Err(); err != nil {
			yield(store.RevocationRecord{}, fmt.Errorf("iterating revocations: %w", err))
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
