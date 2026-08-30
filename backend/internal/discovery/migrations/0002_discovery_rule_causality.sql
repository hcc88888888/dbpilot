BEGIN;
ALTER TABLE discovery_scan_state ADD COLUMN IF NOT EXISTS rule_set_digest BYTEA;
ALTER TABLE discovery_scan_state ADD COLUMN IF NOT EXISTS disappearance_grace_seconds BIGINT;
ALTER TABLE discovery_scan_state ADD COLUMN IF NOT EXISTS agent_observed_at TIMESTAMPTZ;
ALTER TABLE discovery_scan_state ADD CONSTRAINT discovery_scan_rule_digest_size CHECK (rule_set_digest IS NULL OR octet_length(rule_set_digest)=32);
ALTER TABLE discovery_scan_state ADD CONSTRAINT discovery_scan_grace_positive CHECK (disappearance_grace_seconds IS NULL OR disappearance_grace_seconds>0);
COMMIT;
