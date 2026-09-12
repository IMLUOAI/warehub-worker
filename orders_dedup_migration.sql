CREATE INDEX IF NOT EXISTS idx_orders_tenant_tracking ON orders(tenant_id, tracking);
