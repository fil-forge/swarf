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

// Stream returns matching revocation records and remains open until ctx is canceled.
func (s *Store) Stream(ctx context.Context, from time.Time) iter.Seq2[store.RevocationRecord, error] {
	return func(yield func(store.RevocationRecord, error) bool) {
		ticker := time.NewTicker(streamPollInterval)
		defer ticker.Stop()

		// lastID is the id column of the most recently yielded row, so
		// polling resumes strictly after it rather than re-yielding records
		// that share its recorded_at timestamp.
		var lastID string
		for {
			if err := ctx.Err(); err != nil {
				yield(store.RevocationRecord{}, err)
				return
			}
			for rec, err := range s.recordsFrom(ctx, from, lastID) {
				if err != nil {
					yield(store.RevocationRecord{}, err)
					return
				}
				if !yield(rec.RevocationRecord, nil) {
					return
				}
				from = rec.RecordedAt
				lastID = rec.id
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

// streamRecord pairs a revocation record with the id column of its row, so
// Stream can advance its cursor from the stored id.
type streamRecord struct {
	store.RevocationRecord
	id string
}

func (s *Store) recordsFrom(ctx context.Context, from time.Time, lastID string) iter.Seq2[streamRecord, error] {
	return func(yield func(streamRecord, error) bool) {
		// The (recorded_at, id) cursor resumes strictly after the last
		// yielded record, but stays inclusive of from until something has
		// been yielded: every id sorts after the empty string, so with
		// lastID == "" the filter degenerates to recorded_at >= from. The
		// zero from predates every record, so an unbounded stream matches
		// everything.
		rows, err := s.pool.Query(
			ctx,
			`SELECT id, cause, revoked_delegation, path_witness, recorded_at
			 FROM revocation
			 WHERE recorded_at > $1 OR (recorded_at = $1 AND id > $2)
			 ORDER BY recorded_at, id`,
			from,
			lastID,
		)
		if err != nil {
			yield(streamRecord{}, fmt.Errorf("querying revocations: %w", err))
			return
		}
		defer rows.Close()

		for rows.Next() {
			var id string
			var causeBytes []byte
			var revoke string
			var pathWitness [][]byte
			var recordedAt time.Time
			if err := rows.Scan(&id, &causeBytes, &revoke, &pathWitness, &recordedAt); err != nil {
				yield(streamRecord{}, fmt.Errorf("scanning revocation: %w", err))
				return
			}
			record, err := decodeRecord(causeBytes, revoke, pathWitness, recordedAt)
			if err != nil {
				yield(streamRecord{}, fmt.Errorf("decoding revocation: %w", err))
				return
			}
			if !yield(streamRecord{RevocationRecord: record, id: id}, nil) {
				return
			}
		}
		if err := rows.Err(); err != nil {
			yield(streamRecord{}, fmt.Errorf("iterating revocations: %w", err))
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
