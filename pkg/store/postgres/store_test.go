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
	require.Equal(t, firstRevocation.Link(), (<-records).Cause().Link())
	require.Equal(t, secondRevocation.Link(), (<-records).Cause().Link())

	thirdRevocation, thirdPath := revocationPath(t)
	add(t, s, thirdRevocation, thirdPath)
	require.Equal(t, thirdRevocation.Link(), (<-records).Cause().Link())
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)

	// The from filter is inclusive: the record recorded at exactly from is
	// re-delivered.
	filteredCtx, filteredCancel := context.WithCancel(context.Background())
	filtered, filteredDone := collectStream(s.Stream(filteredCtx, first.RecordedAt))
	require.Equal(t, firstRevocation.Link(), (<-filtered).Cause().Link())
	require.Equal(t, secondRevocation.Link(), (<-filtered).Cause().Link())
	require.Equal(t, thirdRevocation.Link(), (<-filtered).Cause().Link())
	filteredCancel()
	require.ErrorIs(t, <-filteredDone, context.Canceled)
}

func TestPostgresRevocationStoreStreamEvents(t *testing.T) {
	s, _ := newTestStore(t)
	revocation, path := revocationPath(t)
	add(t, s, revocation, path)

	ctx, cancel := context.WithCancel(context.Background())
	events, done := collectStream(s.Stream(ctx, time.Time{}))
	event := <-events
	require.Equal(t, store.EventKindRevocation, event.Kind)
	require.Nil(t, event.PrincipalRevocation)
	require.NotNil(t, event.Revocation)
	require.Equal(t, path[len(path)-1].Link(), event.Revocation.Revoke)
	require.Equal(t, revocation.Link(), event.Revocation.Cause.Link())
	require.Len(t, event.Revocation.Path, len(path))
	require.False(t, event.Revocation.RecordedAt.IsZero())
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
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
	delivered[(<-records).Cause().Link().String()]++
	delivered[(<-records).Cause().Link().String()]++
	require.Equal(t, 1, delivered[firstRevocation.Link().String()])
	require.Equal(t, 1, delivered[secondRevocation.Link().String()])

	// Hold the stream open past a poll interval: records sharing the from
	// timestamp must not be re-delivered.
	select {
	case record := <-records:
		require.Failf(t, "stream re-delivered a record", "cause: %s", record.Cause().Link())
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
	require.Equal(t, firstRevocation.Link(), (<-records).Cause().Link())

	// A concurrent insert can commit a row at a timestamp the stream has
	// already passed: sharing the first record's recorded_at, or earlier.
	// Both must still be delivered, in either order, exactly once each.
	sameTsRevocation, sameTsPath := revocationPath(t)
	insertAt(t, pool, sameTsRevocation, sameTsPath, recordedAt)
	earlierRevocation, earlierPath := revocationPath(t)
	insertAt(t, pool, earlierRevocation, earlierPath, recordedAt.Add(-time.Second))

	delivered := map[string]int{}
	delivered[(<-records).Cause().Link().String()]++
	delivered[(<-records).Cause().Link().String()]++
	require.Equal(t, 1, delivered[sameTsRevocation.Link().String()])
	require.Equal(t, 1, delivered[earlierRevocation.Link().String()])

	// Hold the stream open past a poll interval: nothing is re-delivered.
	select {
	case record := <-records:
		require.Failf(t, "stream re-delivered a record", "cause: %s", record.Cause().Link())
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
	require.Equal(t, revocation.Link(), (<-firstRecords).Cause().Link())
	require.Equal(t, revocation.Link(), (<-secondRecords).Cause().Link())

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

func newTestStore(t *testing.T) (*postgres.Store, *pgxpool.Pool) {
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

func collectStream(stream iter.Seq2[store.Event, error]) (<-chan store.Event, <-chan error) {
	records := make(chan store.Event)
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

func TestPostgresPrincipalStoreStreamInterleaved(t *testing.T) {
	s, _ := newTestStore(t)
	firstRevocation, firstPath := revocationPath(t)
	add(t, s, firstRevocation, firstPath)
	invalidation, tenant, principal := principalInvalidation(t)
	addPrincipalRevocation(t, s, invalidation, tenant, principal)
	secondRevocation, secondPath := revocationPath(t)
	add(t, s, secondRevocation, secondPath)

	ctx, cancel := context.WithCancel(context.Background())
	events, done := collectStream(s.Stream(ctx, time.Time{}))

	// Both kinds share one stream, ordered by recorded_at.
	event := <-events
	require.Equal(t, store.EventKindRevocation, event.Kind)
	require.Equal(t, firstRevocation.Link(), event.Cause().Link())

	event = <-events
	require.Equal(t, store.EventKindPrincipalRevocation, event.Kind)
	require.Nil(t, event.Revocation)
	require.NotNil(t, event.PrincipalRevocation)
	require.Equal(t, tenant, event.PrincipalRevocation.Tenant)
	require.Equal(t, principal, event.PrincipalRevocation.Principal)
	require.Equal(t, invalidation.Link(), event.PrincipalRevocation.Cause.Link())
	require.False(t, event.PrincipalRevocation.RecordedAt.IsZero())
	require.Equal(t, invalidation.Link(), event.Cause().Link())
	require.True(t, event.RecordedAt().Equal(event.PrincipalRevocation.RecordedAt))

	event = <-events
	require.Equal(t, store.EventKindRevocation, event.Kind)
	require.Equal(t, secondRevocation.Link(), event.Cause().Link())

	// A principal invalidation stored while streaming is picked up by the
	// next poll.
	liveInvalidation, liveTenant, livePrincipal := principalInvalidation(t)
	addPrincipalRevocation(t, s, liveInvalidation, liveTenant, livePrincipal)
	event = <-events
	require.Equal(t, store.EventKindPrincipalRevocation, event.Kind)
	require.Equal(t, liveInvalidation.Link(), event.Cause().Link())
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)

	// Principal records do not affect revocation lookup.
	record, err := s.Get(context.Background(), firstPath[len(firstPath)-1].Link())
	require.NoError(t, err)
	require.Equal(t, firstRevocation.Link(), record.Cause.Link())
}

func TestPostgresPrincipalStoreStreamLateArrivals(t *testing.T) {
	s, pool := newTestStore(t)
	recordedAt := time.Now().UTC().Truncate(time.Microsecond)

	revocation, path := revocationPath(t)
	insertAt(t, pool, revocation, path, recordedAt)
	invalidation, tenant, principal := principalInvalidation(t)
	insertPrincipalAt(t, pool, invalidation, tenant, principal, recordedAt)

	ctx, cancel := context.WithCancel(context.Background())
	events, done := collectStream(s.Stream(ctx, recordedAt))

	// Records of both kinds sharing recorded_at are ordered by id, so
	// delivery order is not deterministic: both must arrive, exactly once.
	delivered := map[string]int{}
	delivered[(<-events).Cause().Link().String()]++
	delivered[(<-events).Cause().Link().String()]++
	require.Equal(t, 1, delivered[revocation.Link().String()])
	require.Equal(t, 1, delivered[invalidation.Link().String()])

	// A principal invalidation committing at a timestamp the stream has
	// already passed is still delivered, exactly once.
	lateInvalidation, lateTenant, latePrincipal := principalInvalidation(t)
	insertPrincipalAt(t, pool, lateInvalidation, lateTenant, latePrincipal, recordedAt)
	event := <-events
	require.Equal(t, store.EventKindPrincipalRevocation, event.Kind)
	require.Equal(t, lateInvalidation.Link(), event.Cause().Link())

	// Hold the stream open past a poll interval: rows in the unsettled window
	// are re-read but not re-delivered.
	select {
	case event := <-events:
		require.Failf(t, "stream re-delivered a record", "cause: %s", event.Cause().Link())
	case <-time.After(2 * time.Second):
	}
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
}

func TestPostgresPrincipalStoreAddRejectsInvalid(t *testing.T) {
	s := postgres.New(nil)
	invalidation, tenant, principal := principalInvalidation(t)

	require.Error(t, s.AddPrincipalRevocation(context.Background(), invalidation, did.Undef, principal))
	require.Error(t, s.AddPrincipalRevocation(context.Background(), invalidation, tenant, ""))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, s.AddPrincipalRevocation(ctx, invalidation, tenant, principal), context.Canceled)
}

func addPrincipalRevocation(t *testing.T, s store.RevocationStore, invalidation ucan.Invocation, tenant did.DID, principal string) {
	t.Helper()
	require.NoError(t, s.AddPrincipalRevocation(context.Background(), invalidation, tenant, principal))
}

// insertPrincipalAt stores a principal invalidation like
// AddPrincipalRevocation, but with an explicit recorded_at instead of the
// column default.
func insertPrincipalAt(t *testing.T, pool *pgxpool.Pool, invalidation ucan.Invocation, tenant did.DID, principal string, recordedAt time.Time) {
	t.Helper()
	invalidationBytes, err := invocation.Encode(invalidation)
	require.NoError(t, err)
	_, err = pool.Exec(
		context.Background(),
		`INSERT INTO principal_invalidation (id, cause, tenant, principal, recorded_at)
		 VALUES ($1, $2, $3, $4, $5)`,
		invalidation.Link().String(),
		invalidationBytes,
		tenant.String(),
		principal,
		recordedAt,
	)
	require.NoError(t, err)
}

func principalInvalidation(t *testing.T) (ucan.Invocation, did.DID, string) {
	t.Helper()

	issuer, err := ed25519.GenerateIssuer()
	require.NoError(t, err)
	cmd, err := command.Parse("/test/invalidate")
	require.NoError(t, err)
	invalidation, err := invocation.Invoke(issuer, did.Undef, cmd, nil)
	require.NoError(t, err)
	tenant, err := did.Parse("did:plc:" + issuer.DID().Identifier())
	require.NoError(t, err)
	return invalidation, tenant, "principal-" + invalidation.Link().String()[:8]
}
