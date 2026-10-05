-- Feedback / support requests from in-app button
-- Run: wrangler d1 execute warehub-db --file=feedback_migration.sql

CREATE TABLE IF NOT EXISTS feedback (
  id            TEXT PRIMARY KEY,
  tenant_id     TEXT NOT NULL REFERENCES tenants(id),
  user_id       TEXT,
  user_email    TEXT,
  user_name     TEXT,
  page          TEXT,                 -- which tab/view the user was on
  category      TEXT DEFAULT 'general', -- bug | feature | question | general
  message       TEXT NOT NULL,
  debug_log     TEXT,                 -- truncated recent debug log
  user_agent    TEXT,
  app_version   TEXT,
  created_at    TEXT NOT NULL DEFAULT (datetime('now')),
  status        TEXT NOT NULL DEFAULT 'open'  -- open | reviewed | resolved
);

CREATE INDEX IF NOT EXISTS idx_feedback_tenant ON feedback(tenant_id);
CREATE INDEX IF NOT EXISTS idx_feedback_status ON feedback(status);
CREATE INDEX IF NOT EXISTS idx_feedback_created ON feedback(created_at);
