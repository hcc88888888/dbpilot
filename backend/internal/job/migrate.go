package job

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

// RunMigrations applies embedded Job migrations exactly once. Package-qualified
// registry names prevent collisions in the platform-wide migration table.
func RunMigrations(ctx context.Context, database *sql.DB) error {
	if database == nil {
		return errors.New("database is required")
	}
	entries, err := fs.Glob(migrationFiles, "migrations/*.sql")
	if err != nil {
		return fmt.Errorf("list job migrations: %w", err)
	}
	sort.Strings(entries)
	if _, err := database.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS dbpilot_schema_migrations (name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW())"); err != nil {
		return fmt.Errorf("create migration registry: %w", err)
	}
	for _, path := range entries {
		content, err := migrationFiles.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read job migration %s: %w", path, err)
		}
		registryName := "job/" + path
		tx, err := database.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin job migration %s: %w", path, err)
		}
		if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1)", int64(0x444250494c4f54)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("lock migrations: %w", err)
		}
		var applied bool
		if err := tx.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM dbpilot_schema_migrations WHERE name = $1)", registryName).Scan(&applied); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("check job migration %s: %w", path, err)
		}
		if applied {
			if err := tx.Commit(); err != nil {
				return fmt.Errorf("commit job migration check %s: %w", path, err)
			}
			continue
		}
		body := strings.TrimSpace(string(content))
		body = strings.TrimSpace(strings.TrimPrefix(body, "BEGIN;"))
		body = strings.TrimSpace(strings.TrimSuffix(body, "COMMIT;"))
		if _, err := tx.ExecContext(ctx, body); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("apply job migration %s: %w", path, err)
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO dbpilot_schema_migrations (name) VALUES ($1)", registryName); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("record job migration %s: %w", path, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit job migration %s: %w", path, err)
		}
	}
	return nil
}
