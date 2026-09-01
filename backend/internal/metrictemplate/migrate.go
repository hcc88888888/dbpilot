package metrictemplate

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
		return fmt.Errorf("list metric template migrations: %w", err)
	}
	sort.Strings(entries)
	if _, err := database.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS dbpilot_schema_migrations (name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW())"); err != nil {
		return err
	}
	for _, path := range entries {
		body, err := migrationFiles.ReadFile(path)
		if err != nil {
			return err
		}
		tx, err := database.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		rollback := func() { _ = tx.Rollback() }
		if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1)", int64(0x444250494c4f54)); err != nil {
			rollback()
			return err
		}
		name := "metrictemplate/" + path
		var applied bool
		if err := tx.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM dbpilot_schema_migrations WHERE name=$1)", name).Scan(&applied); err != nil {
			rollback()
			return err
		}
		if !applied {
			sqlBody := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(body)), "BEGIN;")), "COMMIT;"))
			if _, err := tx.ExecContext(ctx, sqlBody); err != nil {
				rollback()
				return fmt.Errorf("apply metric template migration %s: %w", path, err)
			}
			if _, err := tx.ExecContext(ctx, "INSERT INTO dbpilot_schema_migrations (name) VALUES ($1)", name); err != nil {
				rollback()
				return err
			}
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}
