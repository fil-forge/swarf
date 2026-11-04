package postgres_test

import (
	"context"
	"fmt"
	"iter"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fil-forge/swarf/internal/testutil"
	"github.com/fil-forge/swarf/pkg/store"
	"github.com/fil-forge/swarf/pkg/store/postgres"
	"github.com/fil-forge/swarf/pkg/store/postgres/migrations"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/ipfs/go-cid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.uber.org/zap"
)

func TestPostgresRevocationStoreGet(t *testing.T) {
	s, _ := newTestStore(t)
	revocation, path := revocationPath(t)

	add(t, s, revocation, path)

	record, err := s.Get(context.Background(), path[len(path)-1].Link())
	require.NoError(t, err)
	require.Equal(t, path[len(path)-1].Link(), record.Revoke)
	require.Equal(t, revocation.Link(), record.Cause.Link())
	require.Len(t, record.Path, len(path))
	require.Equal(t, path[0].Link(), record.Path[0].Link())
	require.False(t, record.RecordedAt.IsZero())
}

func TestPostgresRevocationStoreGetNotFound(t *testing.T) {
	s, _ := newTestStore(t)
	_, path := revocationPath(t)

	_, err := s.Get(context.Background(), path[0].Link())
	require.ErrorIs(t, err, store.ErrNotFound)
}

func TestPostgresRevocationStoreStream(t *testing.T) {
	s, _ := newTestStore(t)
	firstRevocation, firstPath := revocationPath(t)
	add(t, s, firstRevocation, firstPath)
	first, err := s.Get(context.Background(), firstPath[len(firstPath)-1].Link())
	require.NoError(t, err)

	secondRevocation, secondPath := revocationPath(t)
	add(t, s, secondRevocation, secondPath)

	ctx, cancel := context.WithCancel(context.Background())
	records, done := collectStream(s.Stream(ctx, store.Cursor{}, time.Time{}))
	require.Equal(t, firstRevocation.Link(), (<-records).Cause.Link())
	require.Equal(t, secondRevocation.Link(), (<-records).Cause.Link())

	thirdRevocation, thirdPath := revocationPath(t)
	add(t, s, thirdRevocation, thirdPath)
	require.Equal(t, thirdRevocation.Link(), (<-records).Cause.Link())
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)

	// The from filter is inclusive: the record recorded at exactly from is
	// re-delivered.
	filteredCtx, filteredCancel := context.WithCancel(context.Background())
	filtered, filteredDone := collectStream(s.Stream(filteredCtx, store.Cursor{}, first.RecordedAt))
	require.Equal(t, firstRevocation.Link(), (<-filtered).Cause.Link())
	require.Equal(t, secondRevocation.Link(), (<-filtered).Cause.Link())
	require.Equal(t, thirdRevocation.Link(), (<-filtered).Cause.Link())
	filteredCancel()
	require.ErrorIs(t, <-filteredDone, context.Canceled)
}

func TestPostgresRevocationStoreStreamSameTimestamp(t *testing.T) {
	s, pool := newTestStore(t)
	recordedAt := time.Now().UTC().Truncate(time.Microsecond)

	firstRevocation, firstPath := revocationPath(t)
	insertAt(t, pool, firstRevocation, firstPath, recordedAt)
	secondRevocation, secondPath := revocationPath(t)
	insertAt(t, pool, secondRevocation, secondPath, recordedAt)

	ctx, cancel := context.WithCancel(context.Background())
	records, done := collectStream(s.Stream(ctx, store.Cursor{}, recordedAt))

	// Records sharing recorded_at are ordered by id, so delivery order is not
	// deterministic: both must arrive, exactly once each.
	delivered := map[string]int{}
	delivered[(<-records).Cause.Link().String()]++
	delivered[(<-records).Cause.Link().String()]++
	require.Equal(t, 1, delivered[firstRevocation.Link().String()])
	require.Equal(t, 1, delivered[secondRevocation.Link().String()])

	// Hold the stream open past a poll interval: records sharing the from
	// timestamp must not be re-delivered.
	select {
	case record := <-records:
		require.Failf(t, "stream re-delivered a record", "cause: %s", record.Cause.Link())
	case <-time.After(2 * time.Second):
	}
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
}

func TestPostgresRevocationStoreStreamLateArrivals(t *testing.T) {
	s, pool := newTestStore(t)
	recordedAt := time.Now().UTC().Truncate(time.Microsecond)

	firstRevocation, firstPath := revocationPath(t)
	insertAt(t, pool, firstRevocation, firstPath, recordedAt)

	ctx, cancel := context.WithCancel(context.Background())
	records, done := collectStream(s.Stream(ctx, store.Cursor{}, time.Time{}))
	require.Equal(t, firstRevocation.Link(), (<-records).Cause.Link())

	// A row can commit with a recorded_at the stream has already passed:
	// sharing the first record's, or earlier. Both must still be delivered,
	// exactly once each.
	sameTsRevocation, sameTsPath := revocationPath(t)
	insertAt(t, pool, sameTsRevocation, sameTsPath, recordedAt)
	earlierRevocation, earlierPath := revocationPath(t)
	insertAt(t, pool, earlierRevocation, earlierPath, recordedAt.Add(-time.Second))

	delivered := map[string]int{}
	delivered[(<-records).Cause.Link().String()]++
	delivered[(<-records).Cause.Link().String()]++
	require.Equal(t, 1, delivered[sameTsRevocation.Link().String()])
	require.Equal(t, 1, delivered[earlierRevocation.Link().String()])

	// Hold the stream open past a poll interval: nothing is re-delivered.
	select {
	case record := <-records:
		require.Failf(t, "stream re-delivered a record", "cause: %s", record.Cause.Link())
	case <-time.After(2 * time.Second):
	}
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
}

func TestPostgresRevocationStoreStreamAfterCursor(t *testing.T) {
	s, _ := newTestStore(t)
	firstRevocation, firstPath := revocationPath(t)
	add(t, s, firstRevocation, firstPath)
	secondRevocation, secondPath := revocationPath(t)
	add(t, s, secondRevocation, secondPath)

	ctx, cancel := context.WithCancel(context.Background())
	records, done := collectStream(s.Stream(ctx, store.Cursor{}, time.Time{}))
	first := <-records
	require.Equal(t, firstRevocation.Link(), first.Cause.Link())
	require.Equal(t, firstRevocation.Link().String(), first.Cursor.ID)
	second := <-records
	require.Equal(t, secondRevocation.Link(), second.Cause.Link())
	require.Positive(t, second.Cursor.Compare(first.Cursor))
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)

	// Every cursor the store issues is at or before its head, which is how
	// Swarf tells a cursor another store issued.
	head, err := s.Head(context.Background())
	require.NoError(t, err)
	require.LessOrEqual(t, second.Cursor.Compare(head), 0)

	// A stream after the first record's cursor starts at the second, and
	// carries on with records added later.
	resumedCtx, resumedCancel := context.WithCancel(context.Background())
	resumed, resumedDone := collectStream(s.Stream(resumedCtx, first.Cursor, time.Time{}))
	require.Equal(t, secondRevocation.Link(), (<-resumed).Cause.Link())
	thirdRevocation, thirdPath := revocationPath(t)
	add(t, s, thirdRevocation, thirdPath)
	require.Equal(t, thirdRevocation.Link(), (<-resumed).Cause.Link())
	resumedCancel()
	require.ErrorIs(t, <-resumedDone, context.Canceled)
}

func TestPostgresRevocationStoreStreamAfterHead(t *testing.T) {
	s, pool := newTestStore(t)
	ctx := context.Background()
	committedRevocation, committedPath := revocationPath(t)
	add(t, s, committedRevocation, committedPath)

	// An insert still in progress when Head is read is after the head.
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	inFlightRevocation, inFlightPath := revocationPath(t)
	insert(t, tx, inFlightRevocation, inFlightPath)

	head, err := s.Head(ctx)
	require.NoError(t, err)
	streamCtx, cancel := context.WithCancel(ctx)
	records, done := collectStream(s.Stream(streamCtx, head, time.Time{}))

	require.NoError(t, tx.Commit(ctx))
	require.Equal(t, inFlightRevocation.Link(), (<-records).Cause.Link())
	laterRevocation, laterPath := revocationPath(t)
	add(t, s, laterRevocation, laterPath)
	require.Equal(t, laterRevocation.Link(), (<-records).Cause.Link())

	// The record committed before Head was read is not delivered.
	select {
	case record := <-records:
		require.Failf(t, "stream delivered a record from before its head", "cause: %s", record.Cause.Link())
	case <-time.After(2 * time.Second):
	}
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
}

// recorded_at is the time an insert's transaction started, so a transaction
// that started first can commit after one that started later. A consumer that
// resumed from the recorded_at of the last record it received therefore
// missed such a row on every reconnect. The stream holds later rows back
// until the earlier transaction ends, so a resumed stream delivers it.
func TestPostgresRevocationStoreStreamWaitsForOpenTransactions(t *testing.T) {
	s, pool := newTestStore(t)
	ctx := context.Background()
	firstRevocation, firstPath := revocationPath(t)
	add(t, s, firstRevocation, firstPath)

	streamCtx, cancel := context.WithCancel(ctx)
	records, done := collectStream(s.Stream(streamCtx, store.Cursor{}, time.Time{}))
	first := <-records
	require.Equal(t, firstRevocation.Link(), first.Cause.Link())

	// The slow insert's transaction starts first and stays open while the
	// fast insert commits.
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	slowRevocation, slowPath := revocationPath(t)
	insert(t, tx, slowRevocation, slowPath)
	fastRevocation, fastPath := revocationPath(t)
	add(t, s, fastRevocation, fastPath)

	// Delivering the fast record now would let a consumer resume past the
	// slow one.
	select {
	case record := <-records:
		require.Failf(t, "stream delivered a record ahead of an open transaction", "cause: %s", record.Cause.Link())
	case <-time.After(2 * time.Second):
	}
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)

	require.NoError(t, tx.Commit(ctx))
	slow, err := s.Get(ctx, slowPath[len(slowPath)-1].Link())
	require.NoError(t, err)
	fast, err := s.Get(ctx, fastPath[len(fastPath)-1].Link())
	require.NoError(t, err)
	require.True(t, slow.RecordedAt.Before(fast.RecordedAt), "the slow record must be recorded first")

	// Resumed after the last record the first stream delivered, the stream
	// delivers the slow record, then the fast one.
	resumedCtx, resumedCancel := context.WithCancel(ctx)
	resumed, resumedDone := collectStream(s.Stream(resumedCtx, first.Cursor, time.Time{}))
	require.Equal(t, slowRevocation.Link(), (<-resumed).Cause.Link())
	require.Equal(t, fastRevocation.Link(), (<-resumed).Cause.Link())
	resumedCancel()
	require.ErrorIs(t, <-resumedDone, context.Canceled)

	// A time query from the fast record's recorded_at never returns the slow
	// record, recorded before it, whether it starts afresh or resumes after a
	// cursor the slow record follows.
	for _, after := range []store.Cursor{{}, first.Cursor} {
		timedCtx, timedCancel := context.WithCancel(ctx)
		timed, timedDone := collectStream(s.Stream(timedCtx, after, fast.RecordedAt))
		require.Equal(t, fastRevocation.Link(), (<-timed).Cause.Link())
		select {
		case record := <-timed:
			require.Failf(t, "time query delivered a record from before its floor", "cause: %s", record.Cause.Link())
		case <-time.After(2 * time.Second):
		}
		timedCancel()
		require.ErrorIs(t, <-timedDone, context.Canceled)
	}
}

// Rows stored before the transaction ID column existed share one transaction
// ID that streams before every later row.
func TestPostgresRevocationStoreStreamsRowsFromBeforeTransactionIDs(t *testing.T) {
	pool := newTestPool(t)
	ctx := t.Context()
	db := stdlib.OpenDBFromPool(pool)
	t.Cleanup(func() { _ = db.Close() })
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.UpToContext(ctx, db, "sql", 1))
	legacyRevocation, legacyPath := revocationPath(t)
	insert(t, pool, legacyRevocation, legacyPath)
	require.NoError(t, migrations.Up(ctx, pool, zap.NewNop()))
	s := postgres.New(pool)

	newRevocation, newPath := revocationPath(t)
	add(t, s, newRevocation, newPath)

	streamCtx, cancel := context.WithCancel(ctx)
	records, done := collectStream(s.Stream(streamCtx, store.Cursor{}, time.Time{}))
	legacy := <-records
	require.Equal(t, legacyRevocation.Link(), legacy.Cause.Link())
	require.Zero(t, legacy.Cursor.Seq)
	require.Equal(t, newRevocation.Link(), (<-records).Cause.Link())
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)

	resumedCtx, resumedCancel := context.WithCancel(ctx)
	resumed, resumedDone := collectStream(s.Stream(resumedCtx, legacy.Cursor, time.Time{}))
	require.Equal(t, newRevocation.Link(), (<-resumed).Cause.Link())
	resumedCancel()
	require.ErrorIs(t, <-resumedDone, context.Canceled)
}

func TestPostgresRevocationStoreStreamBroadcasts(t *testing.T) {
	s, _ := newTestStore(t)
	firstRevocation, firstPath := revocationPath(t)
	add(t, s, firstRevocation, firstPath)

	firstCtx, firstCancel := context.WithCancel(context.Background())
	firstRecords, firstDone := collectStream(s.Stream(firstCtx, store.Cursor{}, time.Time{}))
	secondCtx, secondCancel := context.WithCancel(context.Background())
	secondRecords, secondDone := collectStream(s.Stream(secondCtx, store.Cursor{}, time.Time{}))
	<-firstRecords
	<-secondRecords

	revocation, path := revocationPath(t)
	add(t, s, revocation, path)
	require.Equal(t, revocation.Link(), (<-firstRecords).Cause.Link())
	require.Equal(t, revocation.Link(), (<-secondRecords).Cause.Link())

	firstCancel()
	secondCancel()
	require.ErrorIs(t, <-firstDone, context.Canceled)
	require.ErrorIs(t, <-secondDone, context.Canceled)
}

func TestPostgresRevocationStoreStreamCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	for _, err := range postgres.New(nil).Stream(ctx, store.Cursor{}, time.Time{}) {
		require.ErrorIs(t, err, context.Canceled)
		return
	}
	require.Fail(t, "Stream did not return context.Canceled")
}

func TestPostgresRevocationStoreAddRejectsInvalidPath(t *testing.T) {
	err := postgres.New(nil).Add(context.Background(), nil, nil)
	require.Error(t, err)
}

func TestPostgresRevocationStoreAddBatch(t *testing.T) {
	s, _ := newTestStore(t)
	// Paths of different lengths check that each row gets its own slice of
	// the witnesses sent for the whole batch.
	batch := []store.Revocation{
		revocationWithPathLength(t, 1),
		revocationWithPathLength(t, 3),
		revocationWithPathLength(t, 2),
	}
	require.NoError(t, s.AddBatch(context.Background(), batch))

	first, err := s.Get(context.Background(), revokedLink(batch[0]))
	require.NoError(t, err)

	for i, revocation := range batch {
		t.Run(fmt.Sprintf("stores revocation %d with its own path and the shared timestamp", i), func(t *testing.T) {
			record, err := s.Get(context.Background(), revokedLink(revocation))
			require.NoError(t, err)
			require.Equal(t, storedRevocation{
				Revoke:     revokedLink(revocation),
				Cause:      revocation.Cause.Link(),
				Path:       pathLinks(revocation.Path),
				RecordedAt: first.RecordedAt,
			}, storedRevocation{
				Revoke:     record.Revoke,
				Cause:      record.Cause.Link(),
				Path:       pathLinks(record.Path),
				RecordedAt: record.RecordedAt,
			})
		})
	}
}

func TestPostgresRevocationStoreAddBatchIssuesOneInsert(t *testing.T) {
	tracer := &statementTracer{}
	s, _ := newTestStore(t, func(cfg *pgxpool.Config) { cfg.ConnConfig.Tracer = tracer })
	batch := make([]store.Revocation, 50)
	for i := range batch {
		batch[i] = revocationWithPathLength(t, 1)
	}
	tracer.reset()

	require.NoError(t, s.AddBatch(context.Background(), batch))
	require.Equal(t, 1, tracer.count("INSERT"))
}

func TestPostgresRevocationStoreAddBatchDuplicates(t *testing.T) {
	s, _ := newTestStore(t)
	stored := revocationWithPathLength(t, 1)
	add(t, s, stored.Cause, stored.Path)
	repeated := revocationWithPathLength(t, 1)

	// A revocation repeated within the batch, and one already stored, are
	// each stored once.
	require.NoError(t, s.AddBatch(context.Background(), []store.Revocation{stored, repeated, repeated}))
	_, err := s.Get(context.Background(), revokedLink(repeated))
	require.NoError(t, err)
}

func TestPostgresRevocationStoreAddBatchRejectsInvalidPath(t *testing.T) {
	batch := []store.Revocation{revocationWithPathLength(t, 1), {Cause: revocationWithPathLength(t, 1).Cause}}
	err := postgres.New(nil).AddBatch(context.Background(), batch)
	require.ErrorContains(t, err, "batch index 1")
}

func TestPostgresRevocationStoreStreamBatch(t *testing.T) {
	s, _ := newTestStore(t)
	batch := make([]store.Revocation, 5)
	for i := range batch {
		batch[i] = revocationWithPathLength(t, 1)
	}
	require.NoError(t, s.AddBatch(context.Background(), batch))

	ctx, cancel := context.WithCancel(context.Background())
	records, done := collectStream(s.Stream(ctx, store.Cursor{}, time.Time{}))

	// Every record of the batch shares recorded_at: each must arrive exactly
	// once, in any order.
	delivered := map[string]int{}
	for range batch {
		delivered[(<-records).Cause.Link().String()]++
	}
	expected := map[string]int{}
	for _, revocation := range batch {
		expected[revocation.Cause.Link().String()] = 1
	}
	require.Equal(t, expected, delivered)

	// Hold the stream open past a poll interval: nothing is re-delivered.
	select {
	case record := <-records:
		require.Failf(t, "stream re-delivered a record", "cause: %s", record.Cause.Link())
	case <-time.After(2 * time.Second):
	}
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
}

// TestPostgresRevocationStoreStreamAfterCursorMidBatch resumes a stream after
// a record in the middle of a batch. A batch's rows share their transaction ID
// and recorded_at, so only the cursor's ID orders them.
func TestPostgresRevocationStoreStreamAfterCursorMidBatch(t *testing.T) {
	s, _ := newTestStore(t)
	batch := make([]store.Revocation, 5)
	for i := range batch {
		batch[i] = revocationWithPathLength(t, 1)
	}
	require.NoError(t, s.AddBatch(context.Background(), batch))

	ctx, cancel := context.WithCancel(context.Background())
	records, done := collectStream(s.Stream(ctx, store.Cursor{}, time.Time{}))
	streamed := make([]store.StreamRecord, len(batch))
	for i := range streamed {
		streamed[i] = <-records
	}
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
	for _, record := range streamed[1:] {
		require.Equal(t, streamed[0].Cursor.Seq, record.Cursor.Seq, "a batch's rows share their transaction ID")
	}

	resumedCtx, resumedCancel := context.WithCancel(context.Background())
	resumed, resumedDone := collectStream(s.Stream(resumedCtx, streamed[2].Cursor, time.Time{}))
	for _, want := range streamed[3:] {
		require.Equal(t, want.Cause.Link(), (<-resumed).Cause.Link())
	}
	// Hold the stream open past a poll interval: nothing else arrives.
	select {
	case record := <-resumed:
		require.Failf(t, "stream after a mid-batch cursor yielded an extra record", "cause: %s", record.Cause.Link())
	case <-time.After(2 * time.Second):
	}
	resumedCancel()
	require.ErrorIs(t, <-resumedDone, context.Canceled)
}

func newTestStore(t *testing.T, configure ...func(*pgxpool.Config)) (*postgres.Store, *pgxpool.Pool) {
	t.Helper()
	pool := newTestPool(t, configure...)
	require.NoError(t, migrations.Up(t.Context(), pool, zap.NewNop()))
	return postgres.New(pool), pool
}

// newTestPool returns a pool on an empty database, before any migration,
// with configure applied to its config.
func newTestPool(t *testing.T, configure ...func(*pgxpool.Config)) *pgxpool.Pool {
	t.Helper()
	if testing.Short() {
		t.Skip("postgres store test requires Docker")
	}
	if testutil.IsRunningInCI(t) && runtime.GOOS == "linux" {
		if !testutil.IsDockerAvailable(t) {
			t.Fatalf("docker is expected in CI linux testing environments, but wasn't found")
		}
	}
	if !testutil.IsDockerAvailable(t) {
		t.SkipNow()
	}
	ctx := t.Context()
	container, err := tcpostgres.Run(ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase("swarf"),
		tcpostgres.WithUsername("swarf"),
		tcpostgres.WithPassword("swarf"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	require.NoError(t, err)
	testcontainers.CleanupContainer(t, container)
	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)
	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	for _, fn := range configure {
		fn(cfg)
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool
}

func add(t *testing.T, s store.RevocationStore, revocation ucan.Invocation, path []ucan.Delegation) {
	t.Helper()
	require.NoError(t, s.Add(context.Background(), revocation, path))
}

// execer is what a pool and a transaction both run statements through.
type execer interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
}

// insert stores a revocation record like Add, but through db, which can be a
// transaction the caller holds open, and naming only the columns the first
// migration created.
func insert(t *testing.T, db execer, revocation ucan.Invocation, path []ucan.Delegation) {
	t.Helper()
	revocationBytes, err := invocation.Encode(revocation)
	require.NoError(t, err)
	pathWitness := make([][]byte, len(path))
	for i, dlg := range path {
		pathWitness[i], err = delegation.Encode(dlg)
		require.NoError(t, err)
	}
	_, err = db.Exec(
		context.Background(),
		`INSERT INTO revocation (id, cause, revoked_delegation, path_witness)
		 VALUES ($1, $2, $3, $4)`,
		revocation.Link().String(),
		revocationBytes,
		path[len(path)-1].Link().String(),
		pathWitness,
	)
	require.NoError(t, err)
}

// insertAt stores a revocation record like Add, but with an explicit
// recorded_at instead of the column default.
func insertAt(t *testing.T, pool *pgxpool.Pool, revocation ucan.Invocation, path []ucan.Delegation, recordedAt time.Time) {
	t.Helper()
	revocationBytes, err := invocation.Encode(revocation)
	require.NoError(t, err)
	pathWitness := make([][]byte, len(path))
	for i, dlg := range path {
		pathWitness[i], err = delegation.Encode(dlg)
		require.NoError(t, err)
	}
	_, err = pool.Exec(
		context.Background(),
		`INSERT INTO revocation (id, cause, revoked_delegation, path_witness, recorded_at)
		 VALUES ($1, $2, $3, $4, $5)`,
		revocation.Link().String(),
		revocationBytes,
		path[len(path)-1].Link().String(),
		pathWitness,
		recordedAt,
	)
	require.NoError(t, err)
}

func collectStream(stream iter.Seq2[store.StreamRecord, error]) (<-chan store.StreamRecord, <-chan error) {
	records := make(chan store.StreamRecord)
	done := make(chan error, 1)
	go func() {
		for record, err := range stream {
			if err != nil {
				done <- err
				return
			}
			records <- record
		}
		done <- nil
	}()
	return records, done
}

func revocationPath(t *testing.T) (ucan.Invocation, []ucan.Delegation) {
	t.Helper()

	issuer, err := ed25519.GenerateIssuer()
	require.NoError(t, err)
	cmd, err := command.Parse("/test/revoke")
	require.NoError(t, err)
	delegation, err := delegation.Delegate(issuer, issuer.DID(), did.Undef, cmd)
	require.NoError(t, err)
	revocation, err := invocation.Invoke(issuer, did.Undef, cmd, nil)
	require.NoError(t, err)
	return revocation, []ucan.Delegation{delegation}
}

// revocationWithPathLength returns a revocation whose path holds length
// delegations. The store does not validate the chain, so the delegations are
// unrelated.
func revocationWithPathLength(t *testing.T, length int) store.Revocation {
	t.Helper()
	revocation, path := revocationPath(t)
	for len(path) < length {
		_, more := revocationPath(t)
		path = append(more, path...)
	}
	return store.Revocation{Cause: revocation, Path: path}
}

func revokedLink(revocation store.Revocation) cid.Cid {
	return revocation.Path[len(revocation.Path)-1].Link()
}

func pathLinks(path []ucan.Delegation) []cid.Cid {
	links := make([]cid.Cid, len(path))
	for i, dlg := range path {
		links[i] = dlg.Link()
	}
	return links
}

// storedRevocation is the comparable part of a [store.RevocationRecord].
type storedRevocation struct {
	Revoke     cid.Cid
	Cause      cid.Cid
	Path       []cid.Cid
	RecordedAt time.Time
}

// statementTracer records the SQL of every query run through the pool.
type statementTracer struct {
	mu  sync.Mutex
	sql []string
}

func (s *statementTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sql = append(s.sql, data.SQL)
	return ctx
}

func (s *statementTracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func (s *statementTracer) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sql = nil
}

// count returns how many recorded statements start with keyword.
func (s *statementTracer) count(keyword string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, sql := range s.sql {
		if strings.HasPrefix(strings.TrimSpace(sql), keyword) {
			n++
		}
	}
	return n
}
