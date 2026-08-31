package credentiallease

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
		return ErrLeaseRejected
	}
	entries, err := fs.Glob(migrationFiles, "migrations/*.sql")
	if err != nil {
		return ErrLeaseRejected
	}
	sort.Strings(entries)
	if _, err := database.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS dbpilot_schema_migrations (name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW())"); err != nil {
		return err
	}
	for _, migrationPath := range entries {
		content, readErr := migrationFiles.ReadFile(migrationPath)
		if readErr != nil {
			return readErr
		}
		transaction, beginErr := database.BeginTx(ctx, nil)
		if beginErr != nil {
			return beginErr
		}
		rollback := func() { _ = transaction.Rollback() }
		if _, err := transaction.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1)", int64(0x444250494c4f54)); err != nil {
			rollback()
			return err
		}
		name := "credentiallease/" + migrationPath
		var applied bool
		if err := transaction.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM dbpilot_schema_migrations WHERE name=$1)", name).Scan(&applied); err != nil {
			rollback()
			return err
		}
		if !applied {
			body := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(content)), "BEGIN;")), "COMMIT;"))
			if _, err := transaction.ExecContext(ctx, body); err != nil {
				rollback()
				return fmt.Errorf("apply credential lease migration: %w", err)
			}
			if _, err := transaction.ExecContext(ctx, "INSERT INTO dbpilot_schema_migrations (name) VALUES ($1)", name); err != nil {
				rollback()
				return err
			}
		}
		if err := transaction.Commit(); err != nil {
			return err
		}
	}
	return nil
}
