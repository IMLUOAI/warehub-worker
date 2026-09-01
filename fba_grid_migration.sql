CREATE TABLE IF NOT EXISTS fba_outbound_items (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  ship_date TEXT,
  shipment_id TEXT,
  fulfillment_center TEXT,
  sku TEXT,
  qty INTEGER DEFAULT 0,
  size TEXT,
  weight REAL,
  carrier TEXT,
  tracking TEXT,
  boxes INTEGER,
  submitted_by TEXT,
  notes TEXT,
  created_at INTEGER DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS idx_fba_outbound_items_tenant ON fba_outbound_items(tenant_id);
