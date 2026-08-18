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
