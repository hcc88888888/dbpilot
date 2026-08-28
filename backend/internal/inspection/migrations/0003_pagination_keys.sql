BEGIN;

CREATE INDEX inspection_items_pagination_v2_idx
ON inspection_items (tenant_id, project_id, created_at DESC, item_id DESC, version DESC);

ALTER TABLE inspection_reports
ADD COLUMN created_at TIMESTAMPTZ GENERATED ALWAYS AS (generated_at) STORED;

CREATE INDEX inspection_reports_pagination_v2_idx
ON inspection_reports (tenant_id, project_id, created_at DESC, id DESC);

COMMIT;
