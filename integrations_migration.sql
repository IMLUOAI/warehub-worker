-- Per-tenant ERP / external system connectors
-- Run: wrangler d1 execute warehub-db --file=integrations_migration.sql --remote

CREATE TABLE IF NOT EXISTS integrations (
  id              TEXT PRIMARY KEY,
  tenant_id       TEXT NOT NULL REFERENCES tenants(id),
  provider        TEXT NOT NULL,              -- e.g. 'xlwms', 'shipstation', 'custom'
  display_name    TEXT,                       -- optional label
  -- credentials stored as JSON: { "app_key": "...", "app_secret": "..." }
  -- Prefer encrypting at rest with CREDENTIALS_KEY env secret in the Worker.
  credentials_json TEXT NOT NULL DEFAULT '{}',
  config_json     TEXT NOT NULL DEFAULT '{}', -- extra options (warehouse id, filters…)
  active          INTEGER NOT NULL DEFAULT 1,
  last_sync_at    TEXT,
  last_sync_status TEXT,                      -- ok | error message
  created_at      TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at      TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE (tenant_id, provider)
);

CREATE INDEX IF NOT EXISTS idx_integrations_tenant ON integrations(tenant_id);
CREATE INDEX IF NOT EXISTS idx_integrations_provider ON integrations(tenant_id, provider);
