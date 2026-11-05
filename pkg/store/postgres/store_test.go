package postgres_test

import (
	"cmp"
	"context"
	"fmt"
	"iter"
	"runtime"
	"slices"
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
	secondRevocation, secondPath := revocationPath(t)
	add(t, s, secondRevocation, secondPath)

	ctx, cancel := context.WithCancel(context.Background())
	records, done := collectStream(ctx, s.Stream(ctx, store.Cursor{}))
	require.Equal(t, firstRevocation.Link(), (<-records).Cause.Link())
	require.Equal(t, secondRevocation.Link(), (<-records).Cause.Link())

	thirdRevocation, thirdPath := revocationPath(t)
	add(t, s, thirdRevocation, thirdPath)
	require.Equal(t, thirdRevocation.Link(), (<-records).Cause.Link())
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
}

// The stream is ordered by seq, not recorded_at, so a row that commits with a
// recorded_at the stream has already passed, sharing the last record's or
// earlier, is still delivered, exactly once.
func TestPostgresRevocationStoreStreamLateArrivals(t *testing.T) {
	s, pool := newTestStore(t)
	recordedAt := time.Now().UTC().Truncate(time.Microsecond)

	firstRevocation, firstPath := revocationPath(t)
	insertAt(t, pool, firstRevocation, firstPath, recordedAt)

	ctx, cancel := context.WithCancel(context.Background())
	records, done := collectStream(ctx, s.Stream(ctx, store.Cursor{}))
	require.Equal(t, firstRevocation.Link(), (<-records).Cause.Link())

	sameTsRevocation, sameTsPath := revocationPath(t)
	insertAt(t, pool, sameTsRevocation, sameTsPath, recordedAt)
	earlierRevocation, earlierPath := revocationPath(t)
	insertAt(t, pool, earlierRevocation, earlierPath, recordedAt.Add(-time.Second))

	require.Equal(t, sameTsRevocation.Link(), (<-records).Cause.Link())
	require.Equal(t, earlierRevocation.Link(), (<-records).Cause.Link())

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
	records, done := collectStream(ctx, s.Stream(ctx, store.Cursor{}))
	first := <-records
	require.Equal(t, firstRevocation.Link(), first.Cause.Link())
	require.Equal(t, store.Cursor{Seq: 1}, first.Cursor)
	second := <-records
	require.Equal(t, secondRevocation.Link(), second.Cause.Link())
	require.Equal(t, store.Cursor{Seq: 2}, second.Cursor)
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
	resumed, resumedDone := collectStream(resumedCtx, s.Stream(resumedCtx, first.Cursor))
	require.Equal(t, secondRevocation.Link(), (<-resumed).Cause.Link())
	thirdRevocation, thirdPath := revocationPath(t)
	add(t, s, thirdRevocation, thirdPath)
	require.Equal(t, thirdRevocation.Link(), (<-resumed).Cause.Link())
	resumedCancel()
	require.ErrorIs(t, <-resumedDone, context.Canceled)
}

func TestPostgresRevocationStoreHead(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	head, err := s.Head(ctx)
	require.NoError(t, err)
	require.Equal(t, store.Cursor{}, head, "an empty store's head is the zero cursor")

	batch := []store.Revocation{revocationWithPathLength(t, 1), revocationWithPathLength(t, 1), revocationWithPathLength(t, 1)}
	require.NoError(t, s.AddBatch(ctx, batch))
	streamed := streamN(t, s, store.Cursor{}, len(batch))
	head, err = s.Head(ctx)
	require.NoError(t, err)
	require.Equal(t, streamed[len(streamed)-1].Cursor, head, "the head is the highest seq")

	// A batch that stores nothing new can still use up numbers, leaving a gap
	// in seq. The head stays at the highest stored seq, and the next record
	// streams after it.
	require.NoError(t, s.AddBatch(ctx, batch[:1]))
	next := revocationWithPathLength(t, 1)
	require.NoError(t, s.AddBatch(ctx, []store.Revocation{next}))
	after := streamN(t, s, head, 1)
	require.Equal(t, next.Cause.Link(), after[0].Cause.Link())
	head, err = s.Head(ctx)
	require.NoError(t, err)
	require.Equal(t, after[0].Cursor, head)
}

func TestPostgresRevocationStoreStreamAfterHead(t *testing.T) {
	s, pool := newTestStore(t)
	ctx := context.Background()
	committedRevocation, committedPath := revocationPath(t)
	add(t, s, committedRevocation, committedPath)

	// A write still in progress when Head is read is after the head.
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	inFlightRevocation, inFlightPath := revocationPath(t)
	insertLocked(t, tx, inFlightRevocation, inFlightPath)

	head, err := s.Head(ctx)
	require.NoError(t, err)
	streamCtx, cancel := context.WithCancel(ctx)
	records, done := collectStream(streamCtx, s.Stream(streamCtx, head))

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

// seq is handed out at insert, not at commit, so without the write lock a
// writer that inserted first could commit after one that inserted later, and
// a stream that had yielded the later row would never yield the earlier one.
// The lock makes the second writer wait until the first has committed before
// it takes its numbers.
func TestPostgresRevocationStoreWritesInCommitOrder(t *testing.T) {
	s, pool := newTestStore(t)
	ctx := context.Background()
	firstRevocation, firstPath := revocationPath(t)
	add(t, s, firstRevocation, firstPath)

	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	records, done := collectStream(streamCtx, s.Stream(streamCtx, store.Cursor{}))
	first := <-records
	require.Equal(t, firstRevocation.Link(), first.Cause.Link())

	// The slow writer takes the lock and inserts, and stays open.
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	slowRevocation, slowPath := revocationPath(t)
	insertLocked(t, tx, slowRevocation, slowPath)

	// The fast writer waits for the lock without drawing a number: a number
	// drawn before the lock could be lower than one a writer that commits
	// first drew.
	lastDrawn := func() int64 {
		var n int64
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT pg_sequence_last_value(pg_get_serial_sequence('revocation', 'seq')::regclass)`,
		).Scan(&n))
		return n
	}
	drawn := lastDrawn()
	fast := revocationWithPathLength(t, 1)
	added := make(chan error, 1)
	go func() { added <- s.AddBatch(ctx, []store.Revocation{fast}) }()
	require.Eventually(t, func() bool {
		var waiting int
		err := pool.QueryRow(ctx,
			`SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND NOT granted`,
		).Scan(&waiting)
		return err == nil && waiting == 1
	}, 10*time.Second, 10*time.Millisecond, "AddBatch did not wait for the write lock")
	require.Equal(t, drawn, lastDrawn(), "AddBatch drew a number before taking the write lock")

	// Hold past a poll interval: the fast write is still blocked, and the
	// stream yields neither record.
	select {
	case err := <-added:
		require.Failf(t, "AddBatch did not wait for the write lock", "err: %v", err)
	case record := <-records:
		require.Failf(t, "stream yielded a record before its write committed", "cause: %s", record.Cause.Link())
	case <-time.After(2 * time.Second):
	}

	require.NoError(t, tx.Commit(ctx))
	require.NoError(t, <-added)

	// Both arrive, in the order they committed.
	slow := <-records
	require.Equal(t, slowRevocation.Link(), slow.Cause.Link())
	fastRecord := <-records
	require.Equal(t, fast.Cause.Link(), fastRecord.Cause.Link())
	require.Positive(t, fastRecord.Cursor.Compare(slow.Cursor))
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
}

// Migration 00002 numbers the rows already stored in (recorded_at, id) order,
// with id ordered bytewise, and rows added afterwards are numbered after them.
func TestPostgresRevocationStoreNumbersRowsFromBeforeSeq(t *testing.T) {
	pool := newTestPool(t)
	ctx := t.Context()
	db := stdlib.OpenDBFromPool(pool)
	t.Cleanup(func() { _ = db.Close() })
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.UpToContext(ctx, db, "sql", 1))

	// Insert in an order that matches neither recorded_at nor id, two rows
	// sharing a recorded_at so that id breaks the tie.
	base := time.Now().UTC().Truncate(time.Microsecond)
	type legacyRow struct {
		revocation ucan.Invocation
		recordedAt time.Time
	}
	var legacy []legacyRow
	for _, offset := range []time.Duration{3 * time.Second, 0, time.Second, time.Second, 2 * time.Second} {
		revocation, path := revocationPath(t)
		insertAt(t, pool, revocation, path, base.Add(offset))
		legacy = append(legacy, legacyRow{revocation: revocation, recordedAt: base.Add(offset)})
	}
	require.NoError(t, migrations.Up(ctx, pool, zap.NewNop()))
	s := postgres.New(pool)

	slices.SortFunc(legacy, func(a, b legacyRow) int {
		return cmp.Or(a.recordedAt.Compare(b.recordedAt), strings.Compare(a.revocation.Link().String(), b.revocation.Link().String()))
	})
	streamed := streamN(t, s, store.Cursor{}, len(legacy))
	for i, row := range legacy {
		require.Equal(t, row.revocation.Link(), streamed[i].Cause.Link(), "row %d", i)
		require.Equal(t, store.Cursor{Seq: uint64(i + 1)}, streamed[i].Cursor, "row %d", i)
	}

	newRevocation, newPath := revocationPath(t)
	add(t, s, newRevocation, newPath)
	resumed := streamN(t, s, streamed[len(streamed)-1].Cursor, 1)
	require.Equal(t, newRevocation.Link(), resumed[0].Cause.Link())
	require.Equal(t, store.Cursor{Seq: uint64(len(legacy) + 1)}, resumed[0].Cursor)
}

// A table with no rows when migration 00002 runs numbers from 1.
func TestPostgresRevocationStoreNumbersFromOne(t *testing.T) {
	s, _ := newTestStore(t)
	revocation, path := revocationPath(t)
	add(t, s, revocation, path)
	streamed := streamN(t, s, store.Cursor{}, 1)
	require.Equal(t, store.Cursor{Seq: 1}, streamed[0].Cursor)
}

func TestPostgresRevocationStoreStreamBroadcasts(t *testing.T) {
	s, _ := newTestStore(t)
	firstRevocation, firstPath := revocationPath(t)
	add(t, s, firstRevocation, firstPath)

	firstCtx, firstCancel := context.WithCancel(context.Background())
	firstRecords, firstDone := collectStream(firstCtx, s.Stream(firstCtx, store.Cursor{}))
	secondCtx, secondCancel := context.WithCancel(context.Background())
	secondRecords, secondDone := collectStream(secondCtx, s.Stream(secondCtx, store.Cursor{}))
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

	for _, err := range postgres.New(nil).Stream(ctx, store.Cursor{}) {
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
	require.Equal(t, 1, tracer.count("SELECT pg_advisory_xact_lock"), "the write takes the write lock")
	require.Equal(t, 1, tracer.count("SET LOCAL idle_in_transaction_session_timeout"), "the write bounds how long it holds the lock while idle")
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
	records, done := collectStream(ctx, s.Stream(ctx, store.Cursor{}))

	// Every record of the batch shares recorded_at: each must arrive exactly
	// once. The order of a batch's rows is the order the INSERT numbered them
	// in, which SQL leaves open.
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
// a record in the middle of a batch. A batch's rows share recorded_at, but
// each has a seq of its own.
func TestPostgresRevocationStoreStreamAfterCursorMidBatch(t *testing.T) {
	s, _ := newTestStore(t)
	batch := make([]store.Revocation, 5)
	for i := range batch {
		batch[i] = revocationWithPathLength(t, 1)
	}
	require.NoError(t, s.AddBatch(context.Background(), batch))

	ctx, cancel := context.WithCancel(context.Background())
	records, done := collectStream(ctx, s.Stream(ctx, store.Cursor{}))
	streamed := make([]store.StreamRecord, len(batch))
	for i := range streamed {
		streamed[i] = <-records
	}
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
	for i, record := range streamed {
		require.Equal(t, store.Cursor{Seq: streamed[0].Cursor.Seq + uint64(i)}, record.Cursor, "a batch's rows get consecutive seqs")
	}

	resumedCtx, resumedCancel := context.WithCancel(context.Background())
	resumed, resumedDone := collectStream(resumedCtx, s.Stream(resumedCtx, streamed[2].Cursor))
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

// insertLocked takes the write lock in tx, as AddBatch does, and inserts a
// revocation record through it. The lock is held until tx ends.
func insertLocked(t *testing.T, tx pgx.Tx, revocation ucan.Invocation, path []ucan.Delegation) {
	t.Helper()
	_, err := tx.Exec(context.Background(), `SELECT pg_advisory_xact_lock($1)`, postgres.WriteLockKey)
	require.NoError(t, err)
	insert(t, tx, revocation, path)
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

// streamN returns the first n records a stream after the after cursor yields.
func streamN(t *testing.T, s store.RevocationStore, after store.Cursor, n int) []store.StreamRecord {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	records, done := collectStream(ctx, s.Stream(ctx, after))
	streamed := make([]store.StreamRecord, 0, n)
	for len(streamed) < n {
		select {
		case record := <-records:
			streamed = append(streamed, record)
		case err := <-done:
			require.FailNow(t, "stream ended early", "err: %v", err)
		case <-time.After(10 * time.Second):
			require.FailNow(t, "timed out waiting for streamed records", "got %d of %d", len(streamed), n)
		}
	}
	cancel()
	for {
		select {
		case <-records:
		case err := <-done:
			require.ErrorIs(t, err, context.Canceled)
			return streamed
		}
	}
}

// collectStream runs stream, sending its records on the first channel and
// its end on the second. It stops when ctx is canceled even if nobody is
// receiving, so that a stream does not keep its connection out of the pool
// past a failed test.
func collectStream(ctx context.Context, stream iter.Seq2[store.StreamRecord, error]) (<-chan store.StreamRecord, <-chan error) {
	records := make(chan store.StreamRecord)
	done := make(chan error, 1)
	go func() {
		for record, err := range stream {
			if err != nil {
				done <- err
				return
			}
			select {
			case records <- record:
			case <-ctx.Done():
				done <- ctx.Err()
				return
			}
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
