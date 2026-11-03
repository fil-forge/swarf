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
	"github.com/jackc/pgx/v5/pgxpool"
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
	records, done := collectStream(s.Stream(ctx, time.Time{}))
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
	filtered, filteredDone := collectStream(s.Stream(filteredCtx, first.RecordedAt))
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
	records, done := collectStream(s.Stream(ctx, recordedAt))

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
	records, done := collectStream(s.Stream(ctx, time.Time{}))
	require.Equal(t, firstRevocation.Link(), (<-records).Cause.Link())

	// A concurrent insert can commit a row at a timestamp the stream has
	// already passed: sharing the first record's recorded_at, or earlier.
	// Both must still be delivered, in either order, exactly once each.
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

func TestPostgresRevocationStoreStreamBroadcasts(t *testing.T) {
	s, _ := newTestStore(t)
	firstRevocation, firstPath := revocationPath(t)
	add(t, s, firstRevocation, firstPath)

	firstCtx, firstCancel := context.WithCancel(context.Background())
	firstRecords, firstDone := collectStream(s.Stream(firstCtx, time.Time{}))
	secondCtx, secondCancel := context.WithCancel(context.Background())
	secondRecords, secondDone := collectStream(s.Stream(secondCtx, time.Time{}))
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

	for _, err := range postgres.New(nil).Stream(ctx, time.Time{}) {
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
	records, done := collectStream(s.Stream(ctx, time.Time{}))

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

func newTestStore(t *testing.T, configure ...func(*pgxpool.Config)) (*postgres.Store, *pgxpool.Pool) {
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
	require.NoError(t, migrations.Up(ctx, pool, zap.NewNop()))
	return postgres.New(pool), pool
}

func add(t *testing.T, s store.RevocationStore, revocation ucan.Invocation, path []ucan.Delegation) {
	t.Helper()
	require.NoError(t, s.Add(context.Background(), revocation, path))
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

func collectStream(stream iter.Seq2[store.RevocationRecord, error]) (<-chan store.RevocationRecord, <-chan error) {
	records := make(chan store.RevocationRecord)
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
