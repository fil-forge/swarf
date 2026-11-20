// Package migrations embeds the hilt Postgres migrations and exposes a runner
// that applies them via goose.
package migrations

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"path/filepath"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgconn/ctxwatch"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"go.uber.org/zap"
)

//go:embed sql/*.sql
var FS embed.FS

// Limits bound what a migration can do to the database when it is slow, or
// when the Swarf process running it is gone. Each one is set on the
// migration's own connections, never on the service's pool.
type Limits struct {
	// Statement is the statement_timeout: the longest one statement of a
	// migration may run. It ends a migration whose client vanished without
	// closing its connection. It must not be shorter than the app's start
	// timeout, or it cuts off a migration the app would have waited for.
	Statement time.Duration
	// Lock is the lock_timeout: the longest a migration waits for a table
	// lock. While it waits for one, every other query on the table queues
	// behind it, so it gives up instead and the start fails.
	Lock time.Duration
	// IdleInTransaction is the idle_in_transaction_session_timeout: it ends a
	// migration's transaction once its client stops sending statements.
	IdleInTransaction time.Duration
	// ClientConnectionCheck is the client_connection_check_interval: how
	// often Postgres checks, while a statement runs, that the client is still
	// connected. It ends a migration whose process exited.
	ClientConnectionCheck time.Duration
}

// DefaultLimits are the limits [Up] applies.
var DefaultLimits = Limits{
	Statement:             10 * time.Minute,
	Lock:                  10 * time.Second,
	IdleInTransaction:     time.Minute,
	ClientConnectionCheck: 2 * time.Second,
}

// Up applies all pending migrations embedded in FS to the database behind
// pool, with [DefaultLimits].
func Up(ctx context.Context, pool *pgxpool.Pool, logger *zap.Logger) error {
	return UpWithLimits(ctx, pool, logger, DefaultLimits)
}

// UpWithLimits applies all pending migrations embedded in FS to the database
// behind pool. It runs them on connections of its own, opened with pool's
// connection settings and limits. When ctx ends, it sends Postgres a cancel
// request, so the statement stops on the server too.
func UpWithLimits(ctx context.Context, pool *pgxpool.Pool, logger *zap.Logger, limits Limits) error {
	connConfig := pool.Config().ConnConfig.Copy()
	for name, value := range limits.runtimeParams() {
		connConfig.RuntimeParams[name] = value
	}
	connConfig.BuildContextWatcherHandler = func(conn *pgconn.PgConn) ctxwatch.Handler {
		return &pgconn.CancelRequestContextWatcherHandler{Conn: conn, DeadlineDelay: time.Second}
	}
	db := stdlib.OpenDB(*connConfig)
	defer db.Close()
	return runUp(ctx, db, logger)
}

// UpDB is equivalent to Up but takes a *sql.DB directly, without applying any
// limits. Useful in tests where a pool is not available.
func UpDB(ctx context.Context, db *sql.DB, logger *zap.Logger) error {
	return runUp(ctx, db, logger)
}

func (l Limits) runtimeParams() map[string]string {
	return map[string]string{
		"statement_timeout":                   milliseconds(l.Statement),
		"lock_timeout":                        milliseconds(l.Lock),
		"idle_in_transaction_session_timeout": milliseconds(l.IdleInTransaction),
		"client_connection_check_interval":    milliseconds(l.ClientConnectionCheck),
	}
}

func milliseconds(d time.Duration) string {
	return strconv.FormatInt(d.Milliseconds(), 10)
}

// runUp applies the pending migrations one at a time, logging when each starts
// and how long it took, since a migration can hold the service's start for
// minutes.
func runUp(ctx context.Context, db *sql.DB, logger *zap.Logger) error {
	goose.SetBaseFS(FS)
	goose.SetLogger(&zapGooseLogger{logger: logger})
	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("setting goose dialect: %w", err)
	}
	current, err := goose.EnsureDBVersionContext(ctx, db)
	if err != nil {
		return fmt.Errorf("reading the schema version: %w", err)
	}
	pending, err := goose.CollectMigrations("sql", current, goose.MaxVersion)
	if err != nil {
		return fmt.Errorf("collecting migrations: %w", err)
	}
	for _, migration := range pending {
		fields := []zap.Field{
			zap.Int64("version", migration.Version),
			zap.String("migration", filepath.Base(migration.Source)),
		}
		logger.Info("applying postgres migration", fields...)
		start := time.Now()
		err := goose.UpToContext(ctx, db, "sql", migration.Version)
		fields = append(fields, zap.Duration("duration", time.Since(start)))
		if err != nil {
			logger.Error("postgres migration failed", append(fields, zap.Error(err))...)
			return fmt.Errorf("applying migration %s: %w", filepath.Base(migration.Source), err)
		}
		logger.Info("applied postgres migration", fields...)
	}
	return nil
}

type zapGooseLogger struct {
	logger *zap.Logger
}

func (l *zapGooseLogger) Fatalf(format string, v ...interface{}) {
	l.logger.Sugar().Fatalf(format, v...)
}

func (l *zapGooseLogger) Printf(format string, v ...interface{}) {
	l.logger.Sugar().Infof(format, v...)
}
