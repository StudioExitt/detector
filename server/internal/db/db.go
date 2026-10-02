package db

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"

	"detector/internal/config"
)

const schema = `
CREATE TABLE IF NOT EXISTS events (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	category    TEXT    NOT NULL,
	severity    TEXT    NOT NULL,
	source      TEXT    NOT NULL DEFAULT '',
	message     TEXT    NOT NULL,
	detected_at TEXT    NOT NULL,
	created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_events_detected_at ON events(detected_at);
CREATE INDEX IF NOT EXISTS idx_events_category ON events(category);

CREATE TABLE IF NOT EXISTS detect_state (
	detector   TEXT NOT NULL,
	key        TEXT NOT NULL,
	value      TEXT NOT NULL,
	updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
	PRIMARY KEY (detector, key)
);

CREATE TABLE IF NOT EXISTS detect_runs (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	detector    TEXT    NOT NULL,
	started_at  TEXT    NOT NULL,
	duration_ms INTEGER NOT NULL,
	error       TEXT    NOT NULL DEFAULT '',
	summary     TEXT    NOT NULL DEFAULT '',
	findings    INTEGER NOT NULL DEFAULT 0,
	checks_ok   INTEGER NOT NULL DEFAULT 0,
	checks_warn INTEGER NOT NULL DEFAULT 0,
	checks_fail INTEGER NOT NULL DEFAULT 0,
	checks      TEXT    NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_detect_runs_detector ON detect_runs(detector, id);

CREATE TABLE IF NOT EXISTS metrics (
	ts    INTEGER NOT NULL, -- unix seconds
	name  TEXT    NOT NULL,
	value REAL    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_metrics_name_ts ON metrics(name, ts);
`

// columns added after the initial schema: table -> column -> definition
var migrations = []struct{ table, column, def string }{
	{"events", "detector", "TEXT NOT NULL DEFAULT ''"},
	{"events", "rule", "TEXT NOT NULL DEFAULT ''"},
	{"events", "fingerprint", "TEXT NOT NULL DEFAULT ''"},
}

// indexes that depend on migrated columns
const postMigrate = `
CREATE INDEX IF NOT EXISTS idx_events_fingerprint ON events(fingerprint, detected_at);
`

// Open opens the database (SQLite in WAL mode) and applies the schema.
func Open(ctx context.Context, cfg config.DatabaseConfig) (*sql.DB, error) {
	switch cfg.DBType {
	case "sqlite3":
		return openSQLite(ctx, cfg.FilePath)
	default:
		return nil, fmt.Errorf("unsupported dbType: %q", cfg.DBType)
	}
}

func openSQLite(ctx context.Context, filePath string) (*sql.DB, error) {
	if dir := filepath.Dir(filePath); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create db dir: %w", err)
		}
	}
	dsn := filePath + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(10000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}
	if _, err := db.ExecContext(ctx, schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	if err := migrate(ctx, db); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func migrate(ctx context.Context, db *sql.DB) error {
	for _, m := range migrations {
		var n int
		err := db.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ?", m.table, m.column).Scan(&n)
		if err != nil {
			return fmt.Errorf("inspect %s.%s: %w", m.table, m.column, err)
		}
		if n > 0 {
			continue
		}
		if _, err := db.ExecContext(ctx, fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", m.table, m.column, m.def)); err != nil {
			return fmt.Errorf("add column %s.%s: %w", m.table, m.column, err)
		}
	}
	if _, err := db.ExecContext(ctx, postMigrate); err != nil {
		return fmt.Errorf("create indexes: %w", err)
	}
	return nil
}
