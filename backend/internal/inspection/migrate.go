package inspection

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
		return errors.New("inspection database and context are required")
	}
	entries, err := fs.Glob(migrationFiles, "migrations/*.sql")
	if err != nil {
		return fmt.Errorf("list inspection migrations: %w", err)
	}
	sort.Strings(entries)
	if _, err := database.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS dbpilot_schema_migrations (name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW())"); err != nil {
		return fmt.Errorf("create migration registry: %w", err)
	}
	for _, path := range entries {
		if err := applyInspectionMigration(ctx, database, path); err != nil {
			return err
		}
	}
	return nil
}

func applyInspectionMigration(ctx context.Context, database *sql.DB, path string) error {
	content, err := migrationFiles.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read inspection migration %s: %w", path, err)
	}
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin inspection migration %s: %w", path, err)
	}
	rollback := func() { _ = tx.Rollback() }
	if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1)", int64(0x444250494c4f54)); err != nil {
		rollback()
		return fmt.Errorf("lock migrations: %w", err)
	}
	name := "inspection/" + path
	var applied bool
	if err := tx.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM dbpilot_schema_migrations WHERE name = $1)", name).Scan(&applied); err != nil {
		rollback()
		return fmt.Errorf("check inspection migration %s: %w", path, err)
	}
	if !applied {
		body := strings.TrimSpace(string(content))
		body = strings.TrimSpace(strings.TrimPrefix(body, "BEGIN;"))
		body = strings.TrimSpace(strings.TrimSuffix(body, "COMMIT;"))
		if _, err := tx.ExecContext(ctx, body); err != nil {
			rollback()
			return fmt.Errorf("apply inspection migration %s: %w", path, err)
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO dbpilot_schema_migrations (name) VALUES ($1)", name); err != nil {
			rollback()
			return fmt.Errorf("record inspection migration %s: %w", path, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit inspection migration %s: %w", path, err)
	}
	return nil
}
