// Package postgres provides a PostgreSQL-backed revocation store.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"math"
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

// writeLockKey is the key of the transaction-scoped advisory lock that
// serializes revocation writes. seq comes from an identity column, which hands
// out numbers when a row is inserted, not when it commits, so two writers
// running at once could commit in the opposite order to their numbers, and a
// stream that had already passed the later number would never yield the
// earlier one. A writer that takes this lock before inserting gets its numbers
// only after the previous writer has committed or rolled back, so seq order is
// commit order. Every writer must take it; AddBatch is the only one.
const writeLockKey int64 = 0x7377617266726576 // "swarfrev" in ASCII

// writeIdleTimeout ends a write's database session if the write goes idle
// inside its transaction for this long. A write holds the write lock across
// round trips to Swarf, so a Swarf host that dies or loses its network
// mid-write would otherwise keep the lock, and block every other write, until
// Postgres noticed the dead connection, which can take hours. A write is idle
// only between its statements, for a round trip.
const writeIdleTimeout = "30s"

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
// statement, in a transaction that holds the write lock (see writeLockKey). A
// revocation repeated in the batch is stored once.
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

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning revocation write: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SET LOCAL idle_in_transaction_session_timeout = '`+writeIdleTimeout+`'`); err != nil {
		return fmt.Errorf("bounding the revocation write's idle time: %w", err)
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, writeLockKey); err != nil {
		return fmt.Errorf("taking the revocation write lock: %w", err)
	}
	_, err = tx.Exec(
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
	// Readers see the commit before the lock is released, so no row can
	// appear behind one a stream has already yielded.
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing revocations: %w", err)
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
		 ORDER BY seq DESC
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

// Head returns the cursor of the highest seq stored, or the zero cursor when
// the table is empty. A write in progress when Head is read holds the write
// lock, so every number it takes is higher than any committed row's, and its
// rows are after the head.
func (s *Store) Head(ctx context.Context) (store.Cursor, error) {
	var head int64
	if err := s.pool.QueryRow(ctx, `SELECT coalesce(max(seq), 0) FROM revocation`).Scan(&head); err != nil {
		return store.Cursor{}, fmt.Errorf("reading the revocation stream head: %w", err)
	}
	return store.Cursor{Seq: uint64(head)}, nil
}

// Stream yields the revocation records after the after cursor, in seq order,
// and remains open until ctx is canceled, polling for new rows. A record's
// cursor is its seq.
//
// seq order is commit order (see writeLockKey), so once a row is visible no
// row with a lower seq can become visible later, and each poll resumes
// strictly after the last row yielded. Numbers lost to a rolled-back or
// conflicting insert leave gaps that are never filled.
func (s *Store) Stream(ctx context.Context, after store.Cursor) iter.Seq2[store.StreamRecord, error] {
	return func(yield func(store.StreamRecord, error) bool) {
		ticker := time.NewTicker(streamPollInterval)
		defer ticker.Stop()

		for {
			if err := ctx.Err(); err != nil {
				yield(store.StreamRecord{}, err)
				return
			}

			for rec, err := range s.recordsAfter(ctx, after) {
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

func (s *Store) recordsAfter(ctx context.Context, after store.Cursor) iter.Seq2[store.StreamRecord, error] {
	return func(yield func(store.StreamRecord, error) bool) {
		if after.Seq > math.MaxInt64 {
			// seq is a BIGINT, so no row is after this cursor.
			return
		}
		rows, err := s.pool.Query(
			ctx,
			`SELECT seq, cause, revoked_delegation, path_witness, recorded_at
			 FROM revocation
			 WHERE seq > $1
			 ORDER BY seq`,
			int64(after.Seq),
		)
		if err != nil {
			yield(store.StreamRecord{}, fmt.Errorf("querying revocations: %w", err))
			return
		}
		defer rows.Close()

		for rows.Next() {
			var seq int64
			var causeBytes []byte
			var revoke string
			var pathWitness [][]byte
			var recordedAt time.Time
			if err := rows.Scan(&seq, &causeBytes, &revoke, &pathWitness, &recordedAt); err != nil {
				yield(store.StreamRecord{}, fmt.Errorf("scanning revocation: %w", err))
				return
			}
			record, err := decodeRecord(causeBytes, revoke, pathWitness, recordedAt)
			if err != nil {
				yield(store.StreamRecord{}, fmt.Errorf("decoding revocation: %w", err))
				return
			}
			if !yield(store.StreamRecord{RevocationRecord: record, Cursor: store.Cursor{Seq: uint64(seq)}}, nil) {
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
