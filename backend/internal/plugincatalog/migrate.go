package plugincatalog

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

func RunMigrations(ctx context.Context, database *sql.DB) error {
	if ctx == nil || database == nil {
		return ErrInvalid
	}
	entries, err := fs.Glob(migrationFiles, "migrations/*.sql")
	if err != nil {
		return fmt.Errorf("list plugin catalog migrations: %w", err)
	}
	sort.Strings(entries)
	if _, err := database.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS dbpilot_schema_migrations (name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW())"); err != nil {
		return fmt.Errorf("create migration registry: %w", err)
	}
	for _, migrationPath := range entries {
		content, err := migrationFiles.ReadFile(migrationPath)
		if err != nil {
			return fmt.Errorf("read plugin catalog migration %s: %w", migrationPath, err)
		}
		transaction, err := database.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin plugin catalog migration %s: %w", migrationPath, err)
		}
		rollback := func() { _ = transaction.Rollback() }
		if _, err := transaction.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1)", int64(0x444250494c4f54)); err != nil {
			rollback()
			return fmt.Errorf("lock plugin catalog migrations: %w", err)
		}
		registryName := "plugincatalog/" + migrationPath
		var applied bool
		if err := transaction.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM dbpilot_schema_migrations WHERE name = $1)", registryName).Scan(&applied); err != nil {
			rollback()
			return fmt.Errorf("check plugin catalog migration %s: %w", migrationPath, err)
		}
		if !applied {
			body := strings.TrimSpace(string(content))
			body = strings.TrimSpace(strings.TrimPrefix(body, "BEGIN;"))
			body = strings.TrimSpace(strings.TrimSuffix(body, "COMMIT;"))
			if _, err := transaction.ExecContext(ctx, body); err != nil {
				rollback()
				return fmt.Errorf("apply plugin catalog migration %s: %w", migrationPath, err)
			}
			if _, err := transaction.ExecContext(ctx, "INSERT INTO dbpilot_schema_migrations (name) VALUES ($1)", registryName); err != nil {
				rollback()
				return fmt.Errorf("record plugin catalog migration %s: %w", migrationPath, err)
			}
		}
		if err := transaction.Commit(); err != nil {
			return fmt.Errorf("commit plugin catalog migration %s: %w", migrationPath, err)
		}
	}
	return nil
}
