BEGIN;

CREATE FUNCTION revoke_agent_issuances_on_host_decommission()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.status = 'decommissioned' AND OLD.status <> 'decommissioned' THEN
        UPDATE agent_enrollment_issuances
        SET revoked_at = COALESCE(NEW.credential_revoked_at, NEW.updated_at)
        WHERE tenant_id = NEW.tenant_id
          AND project_id = NEW.project_id
          AND host_id = NEW.host_id
          AND agent_id = NEW.agent_id
          AND revoked_at IS NULL;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER managed_hosts_revoke_agent_issuances
AFTER UPDATE OF status ON managed_hosts
FOR EACH ROW
EXECUTE FUNCTION revoke_agent_issuances_on_host_decommission();

UPDATE agent_enrollment_issuances issuance
SET revoked_at = COALESCE(host.credential_revoked_at, host.updated_at)
FROM managed_hosts host
WHERE host.tenant_id = issuance.tenant_id
  AND host.project_id = issuance.project_id
  AND host.host_id = issuance.host_id
  AND host.agent_id = issuance.agent_id
  AND host.status = 'decommissioned'
  AND issuance.revoked_at IS NULL;

COMMIT;
