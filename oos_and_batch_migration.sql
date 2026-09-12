CREATE TABLE IF NOT EXISTS out_of_stock_log (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  tracking TEXT NOT NULL,
  sku TEXT,
  carrier TEXT,
  order_id TEXT,
  reported_by TEXT,
  notes TEXT,
  resolved INTEGER DEFAULT 0,
  created_at INTEGER DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS idx_oos_tenant ON out_of_stock_log(tenant_id);

CREATE TABLE IF NOT EXISTS fba_batches (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  label TEXT,
  created_at INTEGER DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS idx_fba_batches_tenant ON fba_batches(tenant_id);

ALTER TABLE fba_outbound_items ADD COLUMN batch_id TEXT;

INSERT INTO fba_batches (id, tenant_id, label, created_at)
SELECT lower(hex(randomblob(16))), tenant_id, 'Batch 1', unixepoch()
FROM (SELECT DISTINCT tenant_id FROM fba_outbound_items WHERE batch_id IS NULL);

UPDATE fba_outbound_items
SET batch_id = (
  SELECT id FROM fba_batches
  WHERE fba_batches.tenant_id = fba_outbound_items.tenant_id
  ORDER BY fba_batches.created_at ASC LIMIT 1
)
WHERE batch_id IS NULL;
