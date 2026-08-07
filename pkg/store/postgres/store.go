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

// Add stores revocation and its delegation path.
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

// Get retrieves the most recently stored revocation record for delegation.
func (s *Store) Get(ctx context.Context, delegationCID cid.Cid) (store.RevocationRecord, error) {
	row := s.pool.QueryRow(
		ctx,
		`SELECT cause, revoked_delegation, path_witness, recorded_at
		 FROM revocation
		 WHERE revoked_delegation = $1
		 ORDER BY recorded_at DESC, id DESC
		 LIMIT 1`,
		delegationCID.String(),
	)
	record, err := ScanRecord(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.RevocationRecord{}, store.ErrNotFound
	}
	if err != nil {
		return store.RevocationRecord{}, fmt.Errorf("getting revocation: %w", err)
	}
	return record, nil
}

// Stream returns matching revocation records and remains open until ctx is canceled.
func (s *Store) Stream(ctx context.Context, from time.Time) iter.Seq2[store.RevocationRecord, error] {
	return func(yield func(store.RevocationRecord, error) bool) {
		ticker := time.NewTicker(streamPollInterval)
		defer ticker.Stop()

		// lastID is the id of the most recently yielded record, so polling
		// resumes strictly after it rather than re-yielding records that share
		// its recorded_at timestamp.
		var lastID string
		for {
			if err := ctx.Err(); err != nil {
				yield(store.RevocationRecord{}, err)
				return
			}
			for record, err := range s.recordsFrom(ctx, from, lastID) {
				if err != nil {
					yield(store.RevocationRecord{}, err)
					return
				}
				if !yield(record, nil) {
					return
				}
				from = record.RecordedAt
				lastID = record.Cause.Link().String()
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

func (s *Store) recordsFrom(ctx context.Context, from time.Time, lastID string) iter.Seq2[store.RevocationRecord, error] {
	return func(yield func(store.RevocationRecord, error) bool) {
		var fromArg, lastIDArg any
		if !from.IsZero() {
			fromArg = from
		}
		if lastID != "" {
			lastIDArg = lastID
		}
		// The from filter is inclusive so consumers resuming from the
		// timestamp of the last record they received do not miss records that
		// share it. Once a record has been yielded, the (recorded_at, id)
		// cursor resumes strictly after it.
		rows, err := s.pool.Query(
			ctx,
			`SELECT cause, revoked_delegation, path_witness, recorded_at
			 FROM revocation
			 WHERE ($1::timestamptz IS NULL)
			    OR ($2::text IS NULL AND recorded_at >= $1)
			    OR (recorded_at > $1 OR (recorded_at = $1 AND id > $2))
			 ORDER BY recorded_at, id`,
			fromArg,
			lastIDArg,
		)
		if err != nil {
			yield(store.RevocationRecord{}, fmt.Errorf("querying revocations: %w", err))
			return
		}
		defer rows.Close()

		for rows.Next() {
			record, err := ScanRecord(rows)
			if err != nil {
				yield(store.RevocationRecord{}, fmt.Errorf("scanning revocation: %w", err))
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

func ScanRecord(row pgx.Row) (store.RevocationRecord, error) {
	var causeBytes []byte
	var revoke string
	var pathWitness [][]byte
	var recordedAt time.Time
	if err := row.Scan(&causeBytes, &revoke, &pathWitness, &recordedAt); err != nil {
		return store.RevocationRecord{}, err
	}

	cause, err := invocation.Decode(causeBytes)
	if err != nil {
		return store.RevocationRecord{}, fmt.Errorf("decoding revocation cause: %w", err)
	}
	revokeCID, err := cid.Decode(revoke)
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
		Revoke:     revokeCID,
		Cause:      cause,
		Path:       path,
		RecordedAt: recordedAt,
	}, nil
}
