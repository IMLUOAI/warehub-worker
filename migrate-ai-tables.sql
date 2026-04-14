-- ══════════════════════════════════════════════════════════════════
--  Warehub AI — Self-Learning Tables Migration
--  Run via: wrangler d1 execute warehub-db --file=migrate-ai-tables.sql
-- ══════════════════════════════════════════════════════════════════

-- ── Events: every meaningful user action is logged here ──────────
CREATE TABLE IF NOT EXISTS events (
  id           TEXT    PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  tenant_id    TEXT    NOT NULL,
  user_id      TEXT,
  event_type   TEXT    NOT NULL,   -- 'order_packed','fba_created','return_logged', etc.
  entity_type  TEXT,               -- 'order','fba','return','product','packer'
  entity_id    TEXT,               -- ID of the entity involved
  payload      TEXT    DEFAULT '{}', -- JSON: extra context (counts, values, etc.)
  occurred_at  INTEGER DEFAULT (unixepoch()),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);

CREATE INDEX IF NOT EXISTS idx_events_tenant_time
  ON events(tenant_id, occurred_at DESC);

CREATE INDEX IF NOT EXISTS idx_events_type
  ON events(tenant_id, event_type, occurred_at DESC);

-- ── Insights: AI-generated analysis results ───────────────────────
CREATE TABLE IF NOT EXISTS insights (
  id           TEXT    PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  tenant_id    TEXT    NOT NULL,
  insight_type TEXT    NOT NULL,   -- 'velocity_trend','reorder_alert','anomaly','performance','digest'
  title        TEXT    NOT NULL,
  body         TEXT    NOT NULL,
  severity     TEXT    DEFAULT 'info',  -- 'info','warning','critical'
  entity_type  TEXT,
  entity_id    TEXT,
  is_read      INTEGER DEFAULT 0,
  created_at   INTEGER DEFAULT (unixepoch()),
  expires_at   INTEGER,            -- unix timestamp; NULL = never expires
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);

CREATE INDEX IF NOT EXISTS idx_insights_unread
  ON insights(tenant_id, is_read, created_at DESC);
