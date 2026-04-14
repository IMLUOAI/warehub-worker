-- ══════════════════════════════════════════════════════════════════
--  Warehub SaaS — D1 Database Schema
--  Run: wrangler d1 execute warehub-db --file=schema.sql
-- ══════════════════════════════════════════════════════════════════

PRAGMA foreign_keys = ON;

-- ── Tenants (one per warehouse customer account) ──────────────────
CREATE TABLE IF NOT EXISTS tenants (
  id            TEXT PRIMARY KEY,              -- UUID
  name          TEXT NOT NULL,                 -- company / warehouse name
  plan          TEXT NOT NULL DEFAULT 'trial', -- trial | starter | pro | enterprise
  stripe_customer_id TEXT,
  stripe_subscription_id TEXT,
  plan_expires_at TEXT,                        -- ISO8601, NULL = active
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── Users (staff accounts per tenant) ────────────────────────────
CREATE TABLE IF NOT EXISTS users (
  id            TEXT PRIMARY KEY,              -- UUID
  tenant_id     TEXT NOT NULL REFERENCES tenants(id),
  clerk_user_id TEXT UNIQUE NOT NULL,          -- Clerk's user ID
  email         TEXT NOT NULL,
  name          TEXT NOT NULL,
  role          TEXT NOT NULL DEFAULT 'staff', -- owner | manager | staff
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_users_tenant     ON users(tenant_id);
CREATE INDEX IF NOT EXISTS idx_users_clerk      ON users(clerk_user_id);

-- ── Packers ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS packers (
  id                    TEXT PRIMARY KEY,      -- UUID
  tenant_id             TEXT NOT NULL REFERENCES tenants(id),
  name                  TEXT NOT NULL,
  color                 TEXT NOT NULL DEFAULT '#4a9eff',
  pin                   TEXT,                  -- 4-digit PIN
  is_manager            INTEGER NOT NULL DEFAULT 0,
  online                INTEGER NOT NULL DEFAULT 0,
  daily_orders_date     TEXT NOT NULL DEFAULT '',
  daily_orders_completed INTEGER NOT NULL DEFAULT 0,
  created_at            TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_packers_tenant ON packers(tenant_id);

-- ── Packer shift sessions (clock-in / clock-out) ─────────────────
CREATE TABLE IF NOT EXISTS packer_sessions (
  id          TEXT PRIMARY KEY,                -- UUID
  tenant_id   TEXT NOT NULL REFERENCES tenants(id),
  packer_id   TEXT NOT NULL REFERENCES packers(id),
  clock_in    TEXT NOT NULL,                   -- ISO8601
  clock_out   TEXT,                            -- ISO8601, NULL = still on shift
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_sessions_tenant  ON packer_sessions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_sessions_packer  ON packer_sessions(packer_id);
CREATE INDEX IF NOT EXISTS idx_sessions_clockin ON packer_sessions(clock_in);

-- ── Orders (imported from PDF labels) ────────────────────────────
CREATE TABLE IF NOT EXISTS orders (
  id           TEXT PRIMARY KEY,               -- UUID
  tenant_id    TEXT NOT NULL REFERENCES tenants(id),
  tracking     TEXT NOT NULL,
  carrier      TEXT NOT NULL DEFAULT 'Unknown',
  shelf        TEXT,
  status       TEXT NOT NULL DEFAULT 'pending', -- pending | done
  assigned_to  TEXT REFERENCES packers(id),
  packed_by    TEXT REFERENCES packers(id),
  completed_at TEXT,                            -- ISO8601
  imported_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_orders_tenant   ON orders(tenant_id);
CREATE INDEX IF NOT EXISTS idx_orders_status   ON orders(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_orders_tracking ON orders(tenant_id, tracking);

-- ── Order SKUs (one-to-many per order) ───────────────────────────
CREATE TABLE IF NOT EXISTS order_skus (
  id        TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  order_id  TEXT NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
  sku       TEXT NOT NULL,
  qty       INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_order_skus_order  ON order_skus(order_id);
CREATE INDEX IF NOT EXISTS idx_order_skus_tenant ON order_skus(tenant_id);

-- ── Vehicle trips ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS vehicle_trips (
  id          TEXT PRIMARY KEY,
  tenant_id   TEXT NOT NULL REFERENCES tenants(id),
  driver      TEXT NOT NULL,
  destination TEXT NOT NULL,
  depart_time TEXT,
  return_time TEXT,
  odo_start   REAL,
  odo_end     REAL,
  miles       REAL,
  notes       TEXT,
  trip_date   TEXT NOT NULL,                   -- YYYY-MM-DD
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_trips_tenant ON vehicle_trips(tenant_id);
CREATE INDEX IF NOT EXISTS idx_trips_date   ON vehicle_trips(tenant_id, trip_date);

-- ── Returns intake ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS returns (
  id          TEXT PRIMARY KEY,
  tenant_id   TEXT NOT NULL REFERENCES tenants(id),
  tracking    TEXT,
  carrier     TEXT,
  type        TEXT,
  condition   TEXT,
  sku         TEXT,
  qty         INTEGER DEFAULT 1,
  pile        TEXT,
  location    TEXT,
  notes       TEXT,
  scanned_by  TEXT,
  mgr_review  INTEGER DEFAULT 0,
  return_date TEXT NOT NULL,                   -- YYYY-MM-DD
  return_time TEXT NOT NULL,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_returns_tenant ON returns(tenant_id);
CREATE INDEX IF NOT EXISTS idx_returns_date   ON returns(tenant_id, return_date);

-- ── FBA outbound shipments ────────────────────────────────────────
CREATE TABLE IF NOT EXISTS fba_shipments (
  id              TEXT PRIMARY KEY,
  tenant_id       TEXT NOT NULL REFERENCES tenants(id),
  shipment_id     TEXT NOT NULL,               -- FBA15XXXXXX
  fulfillment_center TEXT,
  units           INTEGER,
  boxes           INTEGER,
  dims            TEXT,
  weight          REAL,
  carrier         TEXT,
  tracking        TEXT,
  submitted_by    TEXT,
  notes           TEXT,
  ship_date       TEXT NOT NULL,               -- YYYY-MM-DD
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_fba_tenant ON fba_shipments(tenant_id);
CREATE INDEX IF NOT EXISTS idx_fba_date   ON fba_shipments(tenant_id, ship_date);

-- ── FBA SKUs (one-to-many per shipment) ──────────────────────────
CREATE TABLE IF NOT EXISTS fba_skus (
  id          TEXT PRIMARY KEY,
  tenant_id   TEXT NOT NULL REFERENCES tenants(id),
  shipment_id TEXT NOT NULL REFERENCES fba_shipments(id) ON DELETE CASCADE,
  sku         TEXT NOT NULL,
  qty         INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_fba_skus_shipment ON fba_skus(shipment_id);

-- ── Rack / inventory map ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS rack_inventory (
  id        TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  shelf     TEXT NOT NULL,                     -- e.g. R1-01, B-1-05
  sku       TEXT NOT NULL,
  qty       INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_rack_tenant ON rack_inventory(tenant_id);
CREATE INDEX IF NOT EXISTS idx_rack_shelf  ON rack_inventory(tenant_id, shelf);
CREATE INDEX IF NOT EXISTS idx_rack_sku    ON rack_inventory(tenant_id, sku);

-- ── Per-tenant settings (key-value store) ────────────────────────
CREATE TABLE IF NOT EXISTS settings (
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  key       TEXT NOT NULL,
  value     TEXT,
  PRIMARY KEY (tenant_id, key)
);

-- ── Subscription event log (Stripe webhooks) ─────────────────────
CREATE TABLE IF NOT EXISTS billing_events (
  id           TEXT PRIMARY KEY,
  tenant_id    TEXT REFERENCES tenants(id),
  stripe_event TEXT NOT NULL,
  event_type   TEXT NOT NULL,
  created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);
