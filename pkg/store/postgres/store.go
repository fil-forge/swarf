// Package postgres provides a PostgreSQL-backed revocation store.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"time"

	"github.com/fil-forge/swarf/pkg/store"
	"github.com/fil-forge/ucantone/did"
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

// Store persists revocation and principal invalidation records in PostgreSQL.
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

// AddPrincipalRevocation stores a principal invalidation.
func (s *Store) AddPrincipalRevocation(ctx context.Context, invalidation ucan.Invocation, tenant did.DID, principal string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !tenant.Defined() {
		return errors.New("principal invalidation tenant must be defined")
	}
	if principal == "" {
		return errors.New("principal invalidation principal must not be empty")
	}

	invalidationBytes, err := invocation.Encode(invalidation)
	if err != nil {
		return fmt.Errorf("encoding invalidation: %w", err)
	}

	_, err = s.pool.Exec(
		ctx,
		`INSERT INTO principal_invalidation (id, cause, tenant, principal)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (id) DO NOTHING`,
		invalidation.Link().String(),
		invalidationBytes,
		tenant.String(),
		principal,
	)
	if err != nil {
		return fmt.Errorf("storing principal invalidation: %w", err)
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

// Stream returns matching records as events and remains open until ctx is canceled.
func (s *Store) Stream(ctx context.Context, from time.Time) iter.Seq2[store.Event, error] {
	return func(yield func(store.Event, error) bool) {
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
				yield(store.Event{}, err)
				return
			}

			// The horizon is read before the rows so it never overtakes them.
			var dbNow time.Time
			if err := s.pool.QueryRow(ctx, `SELECT now()`).Scan(&dbNow); err != nil {
				yield(store.Event{}, fmt.Errorf("reading database clock: %w", err))
				return
			}
			for rec, err := range s.recordsFrom(ctx, cursor) {
				if err != nil {
					yield(store.Event{}, err)
					return
				}
				link := rec.Cause().Link()
				if _, ok := seen[link]; ok {
					continue
				}
				// Read before yielding: the consumer may retain and mutate
				// the event it is handed.
				recordedAt := rec.RecordedAt()
				if !yield(rec, nil) {
					return
				}
				seen[link] = recordedAt
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
				yield(store.Event{}, ctx.Err())
				return
			case <-ticker.C:
			}
		}
	}
}

func (s *Store) recordsFrom(ctx context.Context, cursor time.Time) iter.Seq2[store.Event, error] {
	return func(yield func(store.Event, error) bool) {
		// The query is inclusive at the cursor: each poll re-reads the
		// unsettled window and Stream skips rows it already yielded. The
		// zero cursor predates every record, so an unbounded stream matches
		// everything. Both record kinds are read in one query so they share
		// one ordering, and the columns one kind lacks are NULL.
		rows, err := s.pool.Query(
			ctx,
			`SELECT kind, cause, revoked_delegation, path_witness, tenant, principal, recorded_at
			 FROM (
			   SELECT 'revocation' AS kind, id, cause, revoked_delegation, path_witness,
			          NULL::TEXT AS tenant, NULL::TEXT AS principal, recorded_at
			   FROM revocation
			   WHERE recorded_at >= $1
			   UNION ALL
			   SELECT 'principal' AS kind, id, cause, NULL::TEXT AS revoked_delegation, NULL::BYTEA[] AS path_witness,
			          tenant, principal, recorded_at
			   FROM principal_invalidation
			   WHERE recorded_at >= $1
			 ) AS record
			 ORDER BY recorded_at, id`,
			cursor,
		)
		if err != nil {
			yield(store.Event{}, fmt.Errorf("querying records: %w", err))
			return
		}
		defer rows.Close()

		for rows.Next() {
			var kind string
			var causeBytes []byte
			var revoke, tenant, principal *string
			var pathWitness [][]byte
			var recordedAt time.Time
			if err := rows.Scan(&kind, &causeBytes, &revoke, &pathWitness, &tenant, &principal, &recordedAt); err != nil {
				yield(store.Event{}, fmt.Errorf("scanning record: %w", err))
				return
			}
			var event store.Event
			switch store.EventKind(kind) {
			case store.EventKindRevocation:
				if revoke == nil {
					yield(store.Event{}, errors.New("decoding revocation: revoked delegation is null"))
					return
				}
				record, err := decodeRecord(causeBytes, *revoke, pathWitness, recordedAt)
				if err != nil {
					yield(store.Event{}, fmt.Errorf("decoding revocation: %w", err))
					return
				}
				event = store.RevocationEvent(record)
			case store.EventKindPrincipalRevocation:
				if tenant == nil || principal == nil {
					yield(store.Event{}, errors.New("decoding principal invalidation: tenant or principal is null"))
					return
				}
				record, err := decodePrincipalRevocationRecord(causeBytes, *tenant, *principal, recordedAt)
				if err != nil {
					yield(store.Event{}, fmt.Errorf("decoding principal invalidation: %w", err))
					return
				}
				event = store.PrincipalRevocationEvent(record)
			default:
				yield(store.Event{}, fmt.Errorf("unknown record kind %q", kind))
				return
			}
			if !yield(event, nil) {
				return
			}
		}
		if err := rows.Err(); err != nil {
			yield(store.Event{}, fmt.Errorf("iterating records: %w", err))
		}
	}
}

func decodePrincipalRevocationRecord(causeBytes []byte, tenant, principal string, recordedAt time.Time) (store.PrincipalRevocationRecord, error) {
	cause, err := invocation.Decode(causeBytes)
	if err != nil {
		return store.PrincipalRevocationRecord{}, fmt.Errorf("decoding invalidation cause: %w", err)
	}
	tenantDID, err := did.Parse(tenant)
	if err != nil {
		return store.PrincipalRevocationRecord{}, fmt.Errorf("decoding tenant DID: %w", err)
	}
	return store.PrincipalRevocationRecord{
		Tenant:     tenantDID,
		Principal:  principal,
		Cause:      cause,
		RecordedAt: recordedAt,
	}, nil
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
