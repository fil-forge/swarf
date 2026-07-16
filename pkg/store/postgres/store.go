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
		`INSERT INTO revocation (id, revocation, revoked_delegation, path_witness)
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
		`SELECT revocation, path_witness, created_at
		 FROM revocation
		 WHERE revoked_delegation = $1
		 ORDER BY created_at DESC, id DESC
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
func (s *Store) Stream(ctx context.Context, since time.Time) iter.Seq2[store.RevocationRecord, error] {
	return func(yield func(store.RevocationRecord, error) bool) {
		ticker := time.NewTicker(streamPollInterval)
		defer ticker.Stop()

		for {
			if err := ctx.Err(); err != nil {
				yield(store.RevocationRecord{}, err)
				return
			}
			for record, err := range s.recordsSince(ctx, since) {
				if err != nil {
					yield(store.RevocationRecord{}, err)
					return
				}
				if !yield(record, nil) {
					return
				}
				since = record.CreatedAt
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

func (s *Store) recordsSince(ctx context.Context, since time.Time) iter.Seq2[store.RevocationRecord, error] {
	return func(yield func(store.RevocationRecord, error) bool) {
		var sinceArg any
		if !since.IsZero() {
			sinceArg = since
		}
		rows, err := s.pool.Query(
			ctx,
			`SELECT revocation, path_witness, created_at
			 FROM revocation
			 WHERE ($1::timestamptz IS NULL OR created_at > $1)
			 ORDER BY created_at, id`,
			sinceArg,
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
	var revocationBytes []byte
	var pathWitness [][]byte
	var createdAt time.Time
	if err := row.Scan(&revocationBytes, &pathWitness, &createdAt); err != nil {
		return store.RevocationRecord{}, err
	}

	revocation, err := invocation.Decode(revocationBytes)
	if err != nil {
		return store.RevocationRecord{}, fmt.Errorf("decoding revocation: %w", err)
	}
	path := make([]ucan.Delegation, len(pathWitness))
	for i, witness := range pathWitness {
		path[i], err = delegation.Decode(witness)
		if err != nil {
			return store.RevocationRecord{}, fmt.Errorf("decoding delegation at path index %d: %w", i, err)
		}
	}
	return store.RevocationRecord{
		Revocation: revocation,
		Path:       path,
		CreatedAt:  createdAt,
	}, nil
}
