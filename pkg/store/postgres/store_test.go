package postgres_test

import (
	"context"
	"iter"
	"runtime"
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

func TestPostgresRevocationStoreAddBatch(t *testing.T) {
	s, _ := newTestStore(t)
	revocation, paths := revocationBatch(t)

	require.NoError(t, s.Add(t.Context(), revocation, paths))

	expected := make([]recordSummary, len(paths))
	stored := make([]recordSummary, len(paths))
	for i, path := range paths {
		expected[i] = summarizePath(revocation, path)
		record, err := s.Get(t.Context(), path[len(path)-1].Link())
		require.NoError(t, err)
		stored[i] = summarizeRecord(record)
	}
	require.Equal(t, expected, stored)
}

func TestPostgresRevocationStoreAddBatchAgainStoresNothingNew(t *testing.T) {
	s, pool := newTestStore(t)
	revocation, paths := revocationBatch(t)
	require.NoError(t, s.Add(t.Context(), revocation, paths))

	require.NoError(t, s.Add(t.Context(), revocation, paths))

	var causes, records int
	require.NoError(t, pool.QueryRow(t.Context(),
		`SELECT (SELECT count(*) FROM revocation_cause), (SELECT count(*) FROM revocation)`,
	).Scan(&causes, &records))
	require.Equal(t, []int{1, len(paths)}, []int{causes, records})
}

func TestPostgresRevocationStoreStreamDeliversEachRecordOfABatchOnce(t *testing.T) {
	s, _ := newTestStore(t)
	revocation, paths := revocationBatch(t)
	require.NoError(t, s.Add(t.Context(), revocation, paths))

	// The records of a batch share their cause and recorded_at. Collecting
	// across two polls catches both a record skipped as a duplicate of its
	// siblings and a record delivered again by the second poll.
	ctx, cancel := context.WithCancel(t.Context())
	records, done := collectStream(s.Stream(ctx, time.Time{}))
	var delivered []cid.Cid
	timeout := time.After(2500 * time.Millisecond)
collect:
	for {
		select {
		case record := <-records:
			delivered = append(delivered, record.Revoke)
		case <-timeout:
			break collect
		}
	}
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)

	expected := make([]cid.Cid, len(paths))
	for i, path := range paths {
		expected[i] = path[len(path)-1].Link()
	}
	require.ElementsMatch(t, expected, delivered)
}

func TestPostgresMigrationMovesCausesToTheirOwnTable(t *testing.T) {
	pool := newTestPool(t)
	db := stdlib.OpenDBFromPool(pool)
	t.Cleanup(func() { _ = db.Close() })
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.UpToContext(t.Context(), db, "sql", 1))

	// A row written before revocation_cause existed, with the invocation in
	// its own cause column.
	revocation, path := revocationPath(t)
	revocationBytes, err := invocation.Encode(revocation)
	require.NoError(t, err)
	witness, err := delegation.Encode(path[0])
	require.NoError(t, err)
	_, err = pool.Exec(t.Context(),
		`INSERT INTO revocation (id, cause, revoked_delegation, path_witness) VALUES ($1, $2, $3, $4)`,
		revocation.Link().String(), revocationBytes, path[0].Link().String(), [][]byte{witness},
	)
	require.NoError(t, err)

	require.NoError(t, migrations.Up(t.Context(), pool, zap.NewNop()))

	record, err := postgres.New(pool).Get(t.Context(), path[0].Link())
	require.NoError(t, err)
	require.Equal(t, summarizePath(revocation, path), summarizeRecord(record))
}

func TestPostgresRevocationStoreAddRejectsInvalidPath(t *testing.T) {
	err := postgres.New(nil).Add(context.Background(), nil, nil)
	require.Error(t, err)
}

func newTestStore(t *testing.T) (*postgres.Store, *pgxpool.Pool) {
	t.Helper()
	pool := newTestPool(t)
	require.NoError(t, migrations.Up(t.Context(), pool, zap.NewNop()))
	return postgres.New(pool), pool
}

// newTestPool connects to a new, empty Postgres database.
func newTestPool(t *testing.T) *pgxpool.Pool {
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
	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool
}

func add(t *testing.T, s store.RevocationStore, revocation ucan.Invocation, path []ucan.Delegation) {
	t.Helper()
	require.NoError(t, s.Add(context.Background(), revocation, [][]ucan.Delegation{path}))
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
		`INSERT INTO revocation_cause (id, invocation) VALUES ($1, $2)`,
		revocation.Link().String(),
		revocationBytes,
	)
	require.NoError(t, err)
	_, err = pool.Exec(
		context.Background(),
		`INSERT INTO revocation (cause_id, revoked_delegation, path_witness, recorded_at)
		 VALUES ($1, $2, $3, $4)`,
		revocation.Link().String(),
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

// revocationBatch returns an invocation revoking three delegations: two
// directly and one through a witness path of two delegations.
func revocationBatch(t *testing.T) (ucan.Invocation, [][]ucan.Delegation) {
	t.Helper()

	alice, err := ed25519.GenerateIssuer()
	require.NoError(t, err)
	bob, err := ed25519.GenerateIssuer()
	require.NoError(t, err)
	cmd, err := command.Parse("/test/revoke")
	require.NoError(t, err)
	delegate := func(issuer ucan.Issuer, audience did.DID) ucan.Delegation {
		dlg, err := delegation.Delegate(issuer, audience, alice.DID(), cmd)
		require.NoError(t, err)
		return dlg
	}
	root := delegate(alice, bob.DID())
	paths := [][]ucan.Delegation{
		{delegate(alice, alice.DID())},
		{root, delegate(bob, alice.DID())},
		{delegate(alice, bob.DID())},
	}
	revocation, err := invocation.Invoke(alice, did.Undef, cmd, nil)
	require.NoError(t, err)
	return revocation, paths
}

// recordSummary is the part of a revocation record a test compares.
type recordSummary struct {
	Revoke cid.Cid
	Cause  cid.Cid
	Path   []cid.Cid
}

func summarizeRecord(record store.RevocationRecord) recordSummary {
	return summarizePath(record.Cause, record.Path)
}

func summarizePath(revocation ucan.Invocation, path []ucan.Delegation) recordSummary {
	links := make([]cid.Cid, len(path))
	for i, dlg := range path {
		links[i] = dlg.Link()
	}
	return recordSummary{Revoke: links[len(links)-1], Cause: revocation.Link(), Path: links}
}
