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

// Add stores revocation and its witness path.
func (s *Store) Add(ctx context.Context, revocation ucan.Invocation, path []ucan.Delegation) error {
	return s.AddBatch(ctx, []store.Revocation{{Cause: revocation, Path: path}})
}

// AddBatch stores revocations and their witness paths with one INSERT
// statement. A revocation repeated in the batch is stored once.
func (s *Store) AddBatch(ctx context.Context, revocations []store.Revocation) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(revocations) == 0 {
		return nil
	}

	// path_witness holds a bytea[] per row, and Postgres arrays cannot be
	// ragged, so every row's witnesses travel in one flat array and each row
	// takes its slice of it, bounded by 1-based path_start and path_end.
	ids := make([]string, 0, len(revocations))
	causes := make([][]byte, 0, len(revocations))
	revoked := make([]string, 0, len(revocations))
	pathStarts := make([]int32, 0, len(revocations))
	pathEnds := make([]int32, 0, len(revocations))
	var witnesses [][]byte
	added := make(map[cid.Cid]struct{}, len(revocations))
	for i, revocation := range revocations {
		if len(revocation.Path) == 0 {
			return fmt.Errorf("revocation at batch index %d: revocation path must contain the revoked delegation", i)
		}
		link := revocation.Cause.Link()
		if _, ok := added[link]; ok {
			continue
		}
		added[link] = struct{}{}

		causeBytes, err := invocation.Encode(revocation.Cause)
		if err != nil {
			return fmt.Errorf("encoding revocation at batch index %d: %w", i, err)
		}
		ids = append(ids, link.String())
		causes = append(causes, causeBytes)
		revoked = append(revoked, revocation.Path[len(revocation.Path)-1].Link().String())
		pathStarts = append(pathStarts, int32(len(witnesses)+1))
		for j, dlg := range revocation.Path {
			witness, err := delegation.Encode(dlg)
			if err != nil {
				return fmt.Errorf("encoding delegation at path index %d of revocation at batch index %d: %w", j, i, err)
			}
			witnesses = append(witnesses, witness)
		}
		pathEnds = append(pathEnds, int32(len(witnesses)))
	}

	_, err := s.pool.Exec(
		ctx,
		`INSERT INTO revocation (id, cause, revoked_delegation, path_witness)
		 SELECT r.id, r.cause, r.revoked_delegation, ($4::bytea[])[r.path_start:r.path_end]
		 FROM unnest($1::text[], $2::bytea[], $3::text[], $5::int[], $6::int[])
		   AS r(id, cause, revoked_delegation, path_start, path_end)
		 ON CONFLICT (id) DO NOTHING`,
		ids,
		causes,
		revoked,
		witnesses,
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
		// by cause link with recorded_at kept for pruning.
		cursor := from
		seen := map[cid.Cid]time.Time{}
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
				link := rec.Cause.Link()
				if _, ok := seen[link]; ok {
					continue
				}
				if !yield(rec, nil) {
					return
				}
				seen[link] = rec.RecordedAt
			}
			if horizon := dbNow.Add(-streamSettleWindow); horizon.After(cursor) {
				cursor = horizon
				for link, recordedAt := range seen {
					if recordedAt.Before(cursor) {
						delete(seen, link)
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
			`SELECT cause, revoked_delegation, path_witness, recorded_at
			 FROM revocation
			 WHERE recorded_at >= $1
			 ORDER BY recorded_at, id`,
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
