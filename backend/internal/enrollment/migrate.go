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
	"time"
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
	return backfillCredentialIdentities(ctx, database)
}

func backfillCredentialIdentities(ctx context.Context, database *sql.DB) error {
	rows, err := database.QueryContext(ctx, `SELECT issuance.token_hash,issuance.certificate_pem,token.generation,issuance.tenant_id,issuance.project_id,issuance.host_id,issuance.agent_id,issuance.issued_at FROM agent_enrollment_issuances issuance JOIN agent_enrollment_tokens token ON token.token_hash=issuance.token_hash WHERE issuance.credential_generation IS NULL OR issuance.certificate_fingerprint IS NULL OR issuance.certificate_serial IS NULL ORDER BY issuance.tenant_id,issuance.project_id,issuance.host_id,token.generation`)
	if err != nil {
		return fmt.Errorf("list enrollment credential backfill: %w", err)
	}
	type pending struct {
		token, certificate []byte
		generation         uint64
		tenant, project    string
		host, agent        string
		issuedAt           time.Time
	}
	var values []pending
	for rows.Next() {
		var value pending
		if err := rows.Scan(&value.token, &value.certificate, &value.generation, &value.tenant, &value.project, &value.host, &value.agent, &value.issuedAt); err != nil {
			_ = rows.Close()
			return err
		}
		values = append(values, value)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, value := range values {
		identity, err := normalizeEnrollmentResult(EnrollResult{CertificatePEM: value.certificate}, EnrollmentGrant{Generation: value.generation})
		if err != nil {
			return fmt.Errorf("decode enrollment credential backfill: %w", err)
		}
		tx, err := database.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE agent_enrollment_issuances SET credential_generation=$1,certificate_fingerprint=$2,certificate_serial=$3 WHERE token_hash=$4 AND credential_generation IS NULL`, value.generation, identity.CertificateFingerprint[:], identity.CertificateSerial, value.token); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE managed_hosts SET credential_generation=$1,active_certificate_fingerprint=$2,active_certificate_serial=$3,credential_revoked_at=NULL WHERE tenant_id=$4 AND project_id=$5 AND host_id=$6 AND agent_id=$7 AND status<>'decommissioned' AND credential_generation<$1`, value.generation, identity.CertificateFingerprint[:], identity.CertificateSerial, value.tenant, value.project, value.host, value.agent); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE agent_enrollment_issuances SET revoked_at=$1 WHERE tenant_id=$2 AND project_id=$3 AND host_id=$4 AND agent_id=$5 AND credential_generation<$6 AND revoked_at IS NULL`, value.issuedAt.UTC(), value.tenant, value.project, value.host, value.agent, value.generation); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
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
