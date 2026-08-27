ALTER TABLE audit_events
    ADD COLUMN IF NOT EXISTS dedupe_key TEXT NOT NULL DEFAULT '';

CREATE UNIQUE INDEX IF NOT EXISTS audit_events_scope_dedupe_idx
    ON audit_events (tenant_id, project_id, dedupe_key)
    WHERE dedupe_key <> '';
