package enrollment

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

func RunMigrations(ctx context.Context, database *sql.DB) error {
	if ctx == nil || database == nil {
		return errors.New("enrollment database and context are required")
	}
	entries, err := fs.Glob(migrationFiles, "migrations/*.sql")
	if err != nil {
		return fmt.Errorf("list enrollment migrations: %w", err)
	}
	sort.Strings(entries)
	if _, err := database.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS dbpilot_schema_migrations (name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW())"); err != nil {
		return fmt.Errorf("create migration registry: %w", err)
	}
	for _, path := range entries {
		if err := applyMigration(ctx, database, path); err != nil {
			return err
		}
	}
	return nil
}

func applyMigration(ctx context.Context, database *sql.DB, path string) error {
	content, err := migrationFiles.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read enrollment migration %s: %w", path, err)
	}
	transaction, err := database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin enrollment migration %s: %w", path, err)
	}
	rollback := func() { _ = transaction.Rollback() }
	if _, err := transaction.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1)", int64(0x444250494c4f54)); err != nil {
		rollback()
		return fmt.Errorf("lock migrations: %w", err)
	}
	name := "enrollment/" + path
	var applied bool
	if err := transaction.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM dbpilot_schema_migrations WHERE name = $1)", name).Scan(&applied); err != nil {
		rollback()
		return fmt.Errorf("check enrollment migration %s: %w", path, err)
	}
	if !applied {
		body := strings.TrimSpace(string(content))
		body = strings.TrimSpace(strings.TrimPrefix(body, "BEGIN;"))
		body = strings.TrimSpace(strings.TrimSuffix(body, "COMMIT;"))
		if _, err := transaction.ExecContext(ctx, body); err != nil {
			rollback()
			return fmt.Errorf("apply enrollment migration %s: %w", path, err)
		}
		if _, err := transaction.ExecContext(ctx, "INSERT INTO dbpilot_schema_migrations (name) VALUES ($1)", name); err != nil {
			rollback()
			return fmt.Errorf("record enrollment migration %s: %w", path, err)
		}
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit enrollment migration %s: %w", path, err)
	}
	return nil
}
