package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/fil-forge/swarf/pkg/store/postgres/migrations"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// A migration that cannot take its table lock gives up with lock_not_available
// instead of queueing every other query on the table behind it.
func TestMigrationGivesUpWaitingForATableLock(t *testing.T) {
	pool := newTestPool(t)
	migrateTo(t, pool, 1)
	holdTableLock(t, pool)
	limits := migrations.DefaultLimits
	limits.Lock = 100 * time.Millisecond

	err := migrations.UpWithLimits(t.Context(), pool, zap.NewNop(), limits)
	require.Equal(t, "55P03", pgErrorCode(err), "error: %v", err)
}

// Canceling a migration stops it on the server too, so no backend is left
// waiting for the table lock it asked for.
func TestCanceledMigrationStopsOnTheServer(t *testing.T) {
	pool := newTestPool(t)
	migrateTo(t, pool, 1)
	holdTableLock(t, pool)
	limits := migrations.DefaultLimits
	limits.Lock = time.Minute
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- migrations.UpWithLimits(ctx, pool, zap.NewNop(), limits) }()
	waitForLockWaiters(t, pool, 1)

	cancel()
	<-done
	waitForLockWaiters(t, pool, 0)
}

// migrateTo applies the migrations up to version.
func migrateTo(t *testing.T, pool *pgxpool.Pool, version int64) {
	t.Helper()
	db := stdlib.OpenDBFromPool(pool)
	t.Cleanup(func() { _ = db.Close() })
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.UpToContext(t.Context(), db, "sql", version))
}

// holdTableLock holds a lock on the revocation table, as a long query does,
// until the test ends.
func holdTableLock(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	tx, err := pool.Begin(t.Context())
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	_, err = tx.Exec(t.Context(), `LOCK TABLE revocation IN ACCESS SHARE MODE`)
	require.NoError(t, err)
}

// waitForLockWaiters waits until exactly want backends are waiting for a lock.
func waitForLockWaiters(t *testing.T, pool *pgxpool.Pool, want int) {
	t.Helper()
	var got int
	require.Eventually(t, func() bool {
		err := pool.QueryRow(t.Context(),
			`SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock'`).Scan(&got)
		return err == nil && got == want
	}, 10*time.Second, 20*time.Millisecond, "backends waiting for a lock: got %d, want %d", got, want)
}

func pgErrorCode(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}
