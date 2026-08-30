ALTER TABLE billing_events ADD COLUMN error TEXT;
CREATE TABLE IF NOT EXISTS reconciliation_issues (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  issue TEXT NOT NULL,
  d1_plan TEXT,
  stripe_status TEXT,
  detected_at INTEGER DEFAULT (unixepoch()),
  resolved INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_reconciliation_tenant ON reconciliation_issues(tenant_id);
