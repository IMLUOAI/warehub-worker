// ══════════════════════════════════════════════════════════════════
//  Warehub SaaS — Cloudflare Worker API
//  Auth: Clerk JWT verification via JWKS
//  Data: Cloudflare D1 with tenant isolation
// ══════════════════════════════════════════════════════════════════

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PATCH, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Tenant-ID",
  "Access-Control-Max-Age": "86400",
};

const CLERK_DOMAIN = "golden-magpie-54.clerk.accounts.dev";
const CLERK_JWKS = `https://${CLERK_DOMAIN}/.well-known/jwks.json`;

// ── Helpers ───────────────────────────────────────────────────────

function uuid() {
  return crypto.randomUUID();
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
  });
}

function err(message, status = 400) {
  return json({ error: message }, status);
}

function b64url(str) {
  // Base64url → base64: replace URL-safe chars, then add required padding
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  return atob(str);
}

// ── Clerk JWT Verification ────────────────────────────────────────

let _jwksCache = null;
let _jwksCacheAt = 0;

async function getJwks() {
  if (_jwksCache && Date.now() - _jwksCacheAt < 3600000) return _jwksCache;
  const resp = await fetch(CLERK_JWKS);
  const data = await resp.json();
  _jwksCache = data.keys;
  _jwksCacheAt = Date.now();
  return _jwksCache;
}

async function verifyClerkJWT(token) {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;

    const header = JSON.parse(b64url(parts[0]));
    const payload = JSON.parse(b64url(parts[1]));

    // Check expiry
    if (payload.exp && Date.now() / 1000 > payload.exp) return null;

    // Find matching key by kid
    const keys = await getJwks();
    const jwk = keys.find((k) => k.kid === header.kid);
    if (!jwk) return null;

    // Import key and verify signature
    const key = await crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"]
    );

    const data = new TextEncoder().encode(parts[0] + "." + parts[1]);
    const sig = Uint8Array.from(b64url(parts[2]), (c) => c.charCodeAt(0));

    const valid = await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5",
      key,
      sig,
      data
    );
    return valid ? payload : null;
  } catch (e) {
    return null;
  }
}

// ── Auth middleware ───────────────────────────────────────────────
// Returns { tenant, clerkUserId } or null

async function resolveAuth(request, env) {
  const authHeader = request.headers.get("Authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) return null;

  const token = authHeader.slice(7);
  const payload = await verifyClerkJWT(token);
  if (!payload) return null;

  const clerkUserId = payload.sub;

  const row = await env.DB.prepare(
    `SELECT u.id as userId, u.role, u.name as userName, u.email as userEmail,
            t.id as tenantId, t.name as tenantName, t.plan, t.plan_expires_at,
            t.stripe_customer_id, t.stripe_subscription_id
     FROM users u
     JOIN tenants t ON t.id = u.tenant_id
     WHERE u.clerk_user_id = ?`
  )
    .bind(clerkUserId)
    .first();

  if (!row) return null;

  return {
    clerkUserId,
    userId: row.userId,
    userEmail: row.userEmail || "",
    role: row.role,
    tenant: {
      id: row.tenantId,
      name: row.tenantName,
      plan: row.plan,
      plan_expires_at: row.plan_expires_at,
      stripe_customer_id: row.stripe_customer_id || null,
      stripe_subscription_id: row.stripe_subscription_id || null,
    },
  };
}

// ── Interactive AI chat/actions proxy ────────────────────────────
// Thin authenticated pass-through to Anthropic — same request shape
// the client already builds (model/system/tools/messages), same
// ANTHROPIC_KEY already used by the nightly analyzeTenant() job.
// The client owns building the tenant's shift context and executing
// any "actions" the model proposes locally, so this route never
// touches the DB itself beyond the auth check already done by the
// router before it gets here.
async function handleAiChat(request, tenant, env) {
  if (!env.ANTHROPIC_KEY) return err("AI is not configured for this deployment.", 503);

  let body;
  try {
    body = await request.json();
  } catch (e) {
    return err("Invalid request body", 400);
  }

  const messages = Array.isArray(body.messages) ? body.messages : null;
  if (!messages || !messages.length) return err("messages is required", 400);

  // Defense in depth: clamp what a (possibly tampered) client can ask
  // for, regardless of what it sends.
  const maxTokens = Math.min(Number(body.max_tokens) || 2000, 4096);

  const resp = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-api-key": env.ANTHROPIC_KEY,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model: body.model || "claude-sonnet-5",
      max_tokens: maxTokens,
      system: typeof body.system === "string" ? body.system : undefined,
      tools: Array.isArray(body.tools) ? body.tools : undefined,
      messages,
    }),
  });

  const data = await resp.json();
  if (!resp.ok) {
    console.error("[Warehub AI] Anthropic error:", resp.status, JSON.stringify(data));
    return err(data.error?.message || "AI request failed", resp.status);
  }

  return json(data);
}

// ── Router ────────────────────────────────────────────────────────

export default {
  async fetch(request, env, ctx) {
    try {
      return await handleRequest(request, env, ctx);
    } catch (e) {
      console.error("[Warehub] Unhandled error:", e.message, e.stack);
      return new Response(
        JSON.stringify({ error: "Internal server error", detail: e.message }),
        {
          status: 500,
          headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
        }
      );
    }
  },

  // ── Nightly cron: runs at 02:00 UTC every day ──────────────────
  async scheduled(event, env, ctx) {
    ctx.waitUntil(runNightlyAnalysis(env));
  },
};

async function handleRequest(request, env, ctx) {
  const url = new URL(request.url);
  const method = request.method;
  const path = url.pathname;

  if (method === "OPTIONS") {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }

  // ── Public routes ──────────────────────────────────────────────
  if (method === "POST" && path === "/api/tenants/register") {
    return handleRegister(request, env);
  }
  if (method === "POST" && path === "/api/stripe/webhook") {
    return handleStripeWebhook(request, env);
  }
  if (method === "GET" && path === "/api/billing/plans") {
    return getBillingPlans();
  }

  // ── Authenticated routes ───────────────────────────────────────
  const auth = await resolveAuth(request, env);
  if (!auth) return err("Unauthorized", 401);

  const { tenant } = auth;

  // Block expired/suspended plans
  if (tenant.plan_expires_at && new Date(tenant.plan_expires_at) < new Date()) {
    return err(
      "Subscription expired — please renew at app.warehub.com/billing",
      402
    );
  }

  // ── Health ────────────────────────────────────────────────────
  if (path === "/api/health") {
    return json({ status: "ok", tenant: tenant.name, plan: tenant.plan });
  }

  // ── AI chat/actions ───────────────────────────────────────────
  if (path === "/api/ai" && method === "POST") {
    return handleAiChat(request, tenant, env);
  }

  // ── Billing ───────────────────────────────────────────────────
  if (path === "/api/billing/status" && method === "GET") {
    const active = tenant.plan === "starter" || tenant.plan === "pro";
    return json({
      plan: tenant.plan || "trial",
      active,
      expiresAt: tenant.plan_expires_at || null,
    });
  }
  if (path === "/api/billing/checkout" && method === "POST") {
    return createCheckoutSession(request, tenant, auth, env);
  }
  if (path === "/api/billing/portal" && method === "POST") {
    return createBillingPortal(request, tenant, env);
  }

  // ── Packers ───────────────────────────────────────────────────
  if (path === "/api/packers") {
    if (method === "GET") return getPackers(tenant, env);
    if (method === "POST") return createPacker(request, tenant, env);
  }
  if (path === "/api/packers/sync" && method === "POST") {
    return syncPackers(request, tenant, env);
  }
  const packerMatch = path.match(/^\/api\/packers\/([^/]+)$/);
  if (packerMatch) {
    const id = packerMatch[1];
    if (method === "PATCH") return updatePacker(request, tenant, id, env);
    if (method === "DELETE") return deletePacker(tenant, id, env);
  }

  // ── Sessions ──────────────────────────────────────────────────
  if (path === "/api/sessions") {
    if (method === "GET") return getSessions(request, tenant, env);
    if (method === "POST") return createSession(request, tenant, env);
  }
  const sessionMatch = path.match(/^\/api\/sessions\/([^/]+)$/);
  if (sessionMatch) {
    if (method === "PATCH")
      return updateSession(request, tenant, sessionMatch[1], env);
  }

  // ── Orders ────────────────────────────────────────────────────
  if (path === "/api/orders") {
    if (method === "GET") return getOrders(tenant, env);
    if (method === "POST") return createOrders(request, tenant, env);
  }
  const orderMatch = path.match(/^\/api\/orders\/([^/]+)$/);
  if (orderMatch) {
    const id = orderMatch[1];
    if (method === "PATCH") return updateOrder(request, tenant, id, env);
    if (method === "DELETE") return deleteOrder(tenant, id, env);
  }
  if (path === "/api/orders/clear" && method === "POST") {
    return clearOrders(tenant, env);
  }

  // ── Vehicle ───────────────────────────────────────────────────
  if (path === "/api/vehicle/trips") {
    if (method === "GET") return getTrips(tenant, env);
    if (method === "POST") return createTrip(request, tenant, env);
  }
  const tripMatch = path.match(/^\/api\/vehicle\/trips\/([^/]+)$/);
  if (tripMatch) {
    if (method === "DELETE") return deleteTrip(tenant, tripMatch[1], env);
  }

  // ── Returns ───────────────────────────────────────────────────
  if (path === "/api/returns") {
    if (method === "GET") return getReturns(tenant, env);
    if (method === "POST") return createReturn(request, tenant, env);
  }
  const returnMatch = path.match(/^\/api\/returns\/([^/]+)$/);
  if (returnMatch) {
    if (method === "DELETE") return deleteReturn(tenant, returnMatch[1], env);
  }

  // ── FBA ───────────────────────────────────────────────────────
  if (path === "/api/fba") {
    if (method === "GET") return getFBA(tenant, env);
    if (method === "POST") return createFBA(request, tenant, env);
  }
  const fbaMatch = path.match(/^\/api\/fba\/([^/]+)$/);
  if (fbaMatch) {
    if (method === "DELETE") return deleteFBA(tenant, fbaMatch[1], env);
  }

  // ── Settings ──────────────────────────────────────────────────
  if (path === "/api/settings") {
    if (method === "GET") return getSettings(tenant, env);
    if (method === "POST") return saveSettings(request, tenant, env);
  }

  // ── Events (telemetry for AI learning) ────────────────────────
  if (path === "/api/events" && method === "POST") {
    return logEvent(request, tenant, auth, env);
  }

  // ── Insights (AI-generated, read by client) ───────────────────
  if (path === "/api/insights" && method === "GET") {
    return getInsights(tenant, env);
  }
  const insightReadMatch = path.match(/^\/api\/insights\/([^/]+)\/read$/);
  if (insightReadMatch && method === "POST") {
    return markInsightRead(tenant, insightReadMatch[1], env);
  }

  return err("Not found", 404);
}

// ══════════════════════════════════════════════════════════════════
//  HANDLERS
// ══════════════════════════════════════════════════════════════════

// ── Tenant registration (called after Clerk signup) ───────────────

async function handleRegister(request, env) {
  const body = await request.json().catch(() => ({}));
  const { name, email, clerkUserId } = body;
  if (!name || !email || !clerkUserId) {
    return err("name, email and clerkUserId are required");
  }

  // Check if user already exists (re-registration guard)
  const existing = await env.DB.prepare(
    `SELECT u.tenant_id, t.plan, t.plan_expires_at
     FROM users u JOIN tenants t ON t.id = u.tenant_id
     WHERE u.clerk_user_id = ?`
  )
    .bind(clerkUserId)
    .first();
  if (existing) {
    return json({
      tenantId: existing.tenant_id,
      plan: existing.plan || "trial",
      active: existing.plan === "starter" || existing.plan === "pro",
      existing: true,
    });
  }

  const tenantId = uuid();
  const userId = uuid();

  await env.DB.prepare(
    `INSERT INTO tenants (id, name, plan) VALUES (?, ?, 'trial')`
  )
    .bind(tenantId, name)
    .run();

  await env.DB.prepare(
    `INSERT INTO users (id, tenant_id, clerk_user_id, email, name, role)
     VALUES (?, ?, ?, ?, ?, 'owner')`
  )
    .bind(userId, tenantId, clerkUserId, email, name)
    .run();

  return json({ tenantId, userId, plan: "trial", active: false }, 201);
}

// ── Packers ───────────────────────────────────────────────────────

async function getPackers(tenant, env) {
  const { results } = await env.DB.prepare(
    `SELECT * FROM packers WHERE tenant_id = ? ORDER BY name`
  )
    .bind(tenant.id)
    .all();

  const { results: sessions } = await env.DB.prepare(
    `SELECT * FROM packer_sessions
     WHERE tenant_id = ? AND clock_in >= datetime('now', '-8 days')
     ORDER BY clock_in DESC`
  )
    .bind(tenant.id)
    .all();

  const sessionMap = {};
  for (const s of sessions) {
    if (!sessionMap[s.packer_id]) sessionMap[s.packer_id] = [];
    sessionMap[s.packer_id].push({
      clockIn: s.clock_in,
      clockOut: s.clock_out,
      id: s.id,
    });
  }

  return json({
    packers: results.map((p) => ({
      ...p,
      is_manager: !!p.is_manager,
      online: !!p.online,
      shiftSessions: sessionMap[p.id] || [],
    })),
  });
}

async function syncPackers(request, tenant, env) {
  const b = await request.json().catch(() => ({}));
  const list = b.packers || [];
  if (!list.length) return json({ ok: true, synced: 0 });

  for (const p of list) {
    const existing = await env.DB.prepare(
      `SELECT id FROM packers WHERE id = ? AND tenant_id = ?`
    )
      .bind(p.id, tenant.id)
      .first();

    if (existing) {
      await env.DB.prepare(
        `UPDATE packers SET name=?,color=?,pin=?,is_manager=?,online=?,
          daily_orders_date=?,daily_orders_completed=? WHERE id=? AND tenant_id=?`
      )
        .bind(
          p.name || "",
          p.color || "#4a9eff",
          p.pin || null,
          p.is_manager ? 1 : 0,
          p.online ? 1 : 0,
          p.dailyOrdersDate || "",
          p.dailyOrdersCompleted || 0,
          p.id,
          tenant.id
        )
        .run();
    } else {
      await env.DB.prepare(
        `INSERT INTO packers (id,tenant_id,name,color,pin,is_manager,online,
          daily_orders_date,daily_orders_completed)
         VALUES (?,?,?,?,?,?,?,?,?)`
      )
        .bind(
          p.id,
          tenant.id,
          p.name || "",
          p.color || "#4a9eff",
          p.pin || null,
          p.is_manager ? 1 : 0,
          p.online ? 1 : 0,
          p.dailyOrdersDate || "",
          p.dailyOrdersCompleted || 0
        )
        .run();
    }

    // Sync shift sessions
    if (Array.isArray(p.shiftSessions)) {
      for (const s of p.shiftSessions) {
        const clockIn = s.clockIn ? new Date(s.clockIn).toISOString() : null;
        const clockOut = s.clockOut ? new Date(s.clockOut).toISOString() : null;
        if (!clockIn) continue;
        // Use a deterministic ID based on packer + clockIn to avoid duplicates
        const sessionId = "SES-" + p.id + "-" + new Date(s.clockIn).getTime();
        const existSes = await env.DB.prepare(
          `SELECT id FROM packer_sessions WHERE id = ?`
        )
          .bind(sessionId)
          .first();
        if (!existSes) {
          await env.DB.prepare(
            `INSERT INTO packer_sessions (id,tenant_id,packer_id,clock_in,clock_out)
             VALUES (?,?,?,?,?)`
          )
            .bind(sessionId, tenant.id, p.id, clockIn, clockOut)
            .run();
        } else if (clockOut) {
          await env.DB.prepare(
            `UPDATE packer_sessions SET clock_out=? WHERE id=?`
          )
            .bind(clockOut, sessionId)
            .run();
        }
      }
    }
  }
  return json({ ok: true, synced: list.length });
}

async function createPacker(request, tenant, env) {
  const b = await request.json().catch(() => ({}));
  if (!b.name) return err("name is required");
  const id = uuid();
  await env.DB.prepare(
    `INSERT INTO packers (id, tenant_id, name, color, pin, is_manager)
     VALUES (?, ?, ?, ?, ?, ?)`
  )
    .bind(
      id,
      tenant.id,
      b.name,
      b.color || "#4a9eff",
      b.pin || null,
      b.is_manager ? 1 : 0
    )
    .run();
  return json({ id }, 201);
}

async function updatePacker(request, tenant, packerId, env) {
  const b = await request.json().catch(() => ({}));
  const allowed = [
    "name",
    "color",
    "pin",
    "is_manager",
    "online",
    "daily_orders_date",
    "daily_orders_completed",
  ];
  const fields = [],
    values = [];
  for (const key of allowed) {
    if (key in b) {
      fields.push(`${key} = ?`);
      values.push(typeof b[key] === "boolean" ? (b[key] ? 1 : 0) : b[key]);
    }
  }
  if (!fields.length) return err("Nothing to update");
  values.push(packerId, tenant.id);
  await env.DB.prepare(
    `UPDATE packers SET ${fields.join(", ")} WHERE id = ? AND tenant_id = ?`
  )
    .bind(...values)
    .run();
  return json({ ok: true });
}

async function deletePacker(tenant, packerId, env) {
  await env.DB.prepare(`DELETE FROM packers WHERE id = ? AND tenant_id = ?`)
    .bind(packerId, tenant.id)
    .run();
  return json({ ok: true });
}

// ── Sessions ──────────────────────────────────────────────────────

async function getSessions(request, tenant, env) {
  const url = new URL(request.url);
  const since =
    url.searchParams.get("since") ||
    new Date(Date.now() - 8 * 24 * 3600000).toISOString();
  const { results } = await env.DB.prepare(
    `SELECT * FROM packer_sessions
     WHERE tenant_id = ? AND clock_in >= ?
     ORDER BY clock_in DESC`
  )
    .bind(tenant.id, since)
    .all();
  return json({ sessions: results });
}

async function createSession(request, tenant, env) {
  const b = await request.json().catch(() => ({}));
  if (!b.packer_id || !b.clock_in)
    return err("packer_id and clock_in required");
  const id = uuid();
  await env.DB.prepare(
    `INSERT INTO packer_sessions (id, tenant_id, packer_id, clock_in)
     VALUES (?, ?, ?, ?)`
  )
    .bind(id, tenant.id, b.packer_id, b.clock_in)
    .run();
  return json({ id }, 201);
}

async function updateSession(request, tenant, sessionId, env) {
  const b = await request.json().catch(() => ({}));
  if (!b.clock_out) return err("clock_out required");
  await env.DB.prepare(
    `UPDATE packer_sessions SET clock_out = ?
     WHERE id = ? AND tenant_id = ?`
  )
    .bind(b.clock_out, sessionId, tenant.id)
    .run();
  return json({ ok: true });
}

// ── Orders ────────────────────────────────────────────────────────

async function getOrders(tenant, env) {
  const { results: orders } = await env.DB.prepare(
    `SELECT * FROM orders WHERE tenant_id = ? ORDER BY imported_at DESC`
  )
    .bind(tenant.id)
    .all();
  const { results: skus } = await env.DB.prepare(
    `SELECT * FROM order_skus WHERE tenant_id = ?`
  )
    .bind(tenant.id)
    .all();
  const skuMap = {};
  for (const s of skus) {
    if (!skuMap[s.order_id]) skuMap[s.order_id] = [];
    skuMap[s.order_id].push({ sku: s.sku, qty: s.qty });
  }
  return json({
    orders: orders.map((o) => ({ ...o, skus: skuMap[o.id] || [] })),
  });
}

async function createOrders(request, tenant, env) {
  const b = await request.json().catch(() => ({}));
  if (!Array.isArray(b.orders) || !b.orders.length)
    return err("orders array required");
  let inserted = 0;
  for (const o of b.orders) {
    const id = uuid();
    await env.DB.prepare(
      `INSERT INTO orders (id, tenant_id, tracking, carrier, shelf, status)
       VALUES (?, ?, ?, ?, ?, 'pending')`
    )
      .bind(id, tenant.id, o.tracking, o.carrier || "Unknown", o.shelf || null)
      .run();
    if (o.skus && o.skus.length) {
      for (const s of o.skus) {
        await env.DB.prepare(
          `INSERT INTO order_skus (id, tenant_id, order_id, sku, qty)
           VALUES (?, ?, ?, ?, ?)`
        )
          .bind(uuid(), tenant.id, id, s.sku, s.qty || 1)
          .run();
      }
    }
    inserted++;
  }
  return json({ inserted }, 201);
}

async function updateOrder(request, tenant, orderId, env) {
  const b = await request.json().catch(() => ({}));
  const allowed = [
    "status",
    "assigned_to",
    "packed_by",
    "completed_at",
    "shelf",
  ];
  const fields = [],
    values = [];
  for (const key of allowed) {
    if (key in b) {
      fields.push(`${key} = ?`);
      values.push(b[key]);
    }
  }
  if (!fields.length) return err("Nothing to update");
  values.push(orderId, tenant.id);
  await env.DB.prepare(
    `UPDATE orders SET ${fields.join(", ")} WHERE id = ? AND tenant_id = ?`
  )
    .bind(...values)
    .run();
  return json({ ok: true });
}

async function deleteOrder(tenant, orderId, env) {
  await env.DB.prepare(`DELETE FROM orders WHERE id = ? AND tenant_id = ?`)
    .bind(orderId, tenant.id)
    .run();
  return json({ ok: true });
}

async function clearOrders(tenant, env) {
  await env.DB.prepare(`DELETE FROM order_skus WHERE tenant_id = ?`)
    .bind(tenant.id)
    .run();
  await env.DB.prepare(`DELETE FROM orders WHERE tenant_id = ?`)
    .bind(tenant.id)
    .run();
  return json({ ok: true });
}

// ── Vehicle trips ─────────────────────────────────────────────────

async function getTrips(tenant, env) {
  const { results } = await env.DB.prepare(
    `SELECT * FROM vehicle_trips WHERE tenant_id = ?
     ORDER BY trip_date DESC, created_at DESC`
  )
    .bind(tenant.id)
    .all();
  return json({ trips: results });
}

async function createTrip(request, tenant, env) {
  const b = await request.json().catch(() => ({}));
  const id = uuid();
  await env.DB.prepare(
    `INSERT INTO vehicle_trips
       (id, tenant_id, driver, destination, depart_time, return_time,
        odo_start, odo_end, miles, notes, trip_date)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(
      id,
      tenant.id,
      b.driver || "",
      b.destination || "",
      b.depart_time || null,
      b.return_time || null,
      b.odo_start || null,
      b.odo_end || null,
      b.miles || null,
      b.notes || null,
      b.trip_date || new Date().toISOString().slice(0, 10)
    )
    .run();
  return json({ id }, 201);
}

async function deleteTrip(tenant, tripId, env) {
  await env.DB.prepare(
    `DELETE FROM vehicle_trips WHERE id = ? AND tenant_id = ?`
  )
    .bind(tripId, tenant.id)
    .run();
  return json({ ok: true });
}

// ── Returns ───────────────────────────────────────────────────────

async function getReturns(tenant, env) {
  const { results } = await env.DB.prepare(
    `SELECT * FROM returns WHERE tenant_id = ?
     ORDER BY return_date DESC, return_time DESC`
  )
    .bind(tenant.id)
    .all();
  return json({ returns: results });
}

async function createReturn(request, tenant, env) {
  const b = await request.json().catch(() => ({}));
  const id = uuid();
  await env.DB.prepare(
    `INSERT INTO returns
       (id, tenant_id, tracking, carrier, type, condition, sku, qty,
        pile, location, notes, scanned_by, mgr_review, return_date, return_time)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(
      id,
      tenant.id,
      b.tracking || null,
      b.carrier || null,
      b.type || null,
      b.condition || null,
      b.sku || null,
      b.qty || 1,
      b.pile || null,
      b.location || null,
      b.notes || null,
      b.scanned_by || null,
      b.mgr_review ? 1 : 0,
      b.return_date || new Date().toISOString().slice(0, 10),
      b.return_time || new Date().toTimeString().slice(0, 8)
    )
    .run();
  return json({ id }, 201);
}

async function deleteReturn(tenant, returnId, env) {
  await env.DB.prepare(`DELETE FROM returns WHERE id = ? AND tenant_id = ?`)
    .bind(returnId, tenant.id)
    .run();
  return json({ ok: true });
}

// ── FBA ───────────────────────────────────────────────────────────

async function getFBA(tenant, env) {
  const { results: shipments } = await env.DB.prepare(
    `SELECT * FROM fba_shipments WHERE tenant_id = ? ORDER BY ship_date DESC`
  )
    .bind(tenant.id)
    .all();
  const { results: skus } = await env.DB.prepare(
    `SELECT * FROM fba_skus WHERE tenant_id = ?`
  )
    .bind(tenant.id)
    .all();
  const skuMap = {};
  for (const s of skus) {
    if (!skuMap[s.shipment_id]) skuMap[s.shipment_id] = [];
    skuMap[s.shipment_id].push({ sku: s.sku, qty: s.qty });
  }
  return json({
    shipments: shipments.map((s) => ({ ...s, skus: skuMap[s.id] || [] })),
  });
}

async function createFBA(request, tenant, env) {
  const b = await request.json().catch(() => ({}));
  const id = uuid();
  await env.DB.prepare(
    `INSERT INTO fba_shipments
       (id, tenant_id, shipment_id, fulfillment_center, units, boxes,
        dims, weight, carrier, tracking, submitted_by, notes, ship_date)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(
      id,
      tenant.id,
      b.shipment_id || "",
      b.fulfillment_center || null,
      b.units || null,
      b.boxes || null,
      b.dims || null,
      b.weight || null,
      b.carrier || null,
      b.tracking || null,
      b.submitted_by || null,
      b.notes || null,
      b.ship_date || new Date().toISOString().slice(0, 10)
    )
    .run();
  if (b.skus && b.skus.length) {
    for (const s of b.skus) {
      await env.DB.prepare(
        `INSERT INTO fba_skus (id, tenant_id, shipment_id, sku, qty)
         VALUES (?, ?, ?, ?, ?)`
      )
        .bind(uuid(), tenant.id, id, s.sku, s.qty || 0)
        .run();
    }
  }
  return json({ id }, 201);
}

async function deleteFBA(tenant, fbaId, env) {
  await env.DB.prepare(
    `DELETE FROM fba_shipments WHERE id = ? AND tenant_id = ?`
  )
    .bind(fbaId, tenant.id)
    .run();
  return json({ ok: true });
}

// ── Settings ──────────────────────────────────────────────────────

async function getSettings(tenant, env) {
  const { results } = await env.DB.prepare(
    `SELECT key, value FROM settings WHERE tenant_id = ?`
  )
    .bind(tenant.id)
    .all();
  const settings = {};
  for (const r of results) {
    try {
      settings[r.key] = JSON.parse(r.value);
    } catch {
      settings[r.key] = r.value;
    }
  }
  return json({ settings });
}

async function saveSettings(request, tenant, env) {
  const body = await request.json().catch(() => ({}));
  for (const [key, value] of Object.entries(body)) {
    await env.DB.prepare(
      `INSERT INTO settings (tenant_id, key, value) VALUES (?, ?, ?)
       ON CONFLICT(tenant_id, key) DO UPDATE SET value = excluded.value`
    )
      .bind(tenant.id, key, JSON.stringify(value))
      .run();
  }
  return json({ ok: true });
}

// ── Stripe webhook ────────────────────────────────────────────────

// ── Stripe helpers ────────────────────────────────────────────────

const STRIPE_PRICES = {
  starter: "price_1TLRhV2LoLs8cdPyZWNNFkUd",
  pro: "price_1TLRiZ2LoLs8cdPy7UXwltuD",
};

async function stripeRequest(path, method, body, env) {
  const resp = await fetch("https://api.stripe.com" + path, {
    method,
    headers: {
      Authorization: "Bearer " + env.STRIPE_SECRET_KEY,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: body ? new URLSearchParams(body).toString() : undefined,
  });
  return resp.json();
}

async function verifyStripeSignature(body, sigHeader, secret) {
  try {
    const parts = sigHeader.split(",");
    const tPart = parts.find((p) => p.startsWith("t="));
    const v1Part = parts.find((p) => p.startsWith("v1="));
    if (!tPart || !v1Part) return false;
    const timestamp = tPart.slice(2);
    const signature = v1Part.slice(3);
    const payload = timestamp + "." + body;
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    const sig = await crypto.subtle.sign(
      "HMAC",
      key,
      new TextEncoder().encode(payload)
    );
    const expected = Array.from(new Uint8Array(sig))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    return expected === signature;
  } catch (e) {
    return false;
  }
}

function getBillingPlans() {
  return json({
    plans: [
      {
        id: "starter",
        name: "Warehub Starter",
        price: 79,
        priceId: STRIPE_PRICES.starter,
        description: "1 warehouse location, up to 10 packers",
        features: [
          "Order queue & scanning",
          "PDF label import",
          "Packer time tracking",
          "Vehicle log",
          "Returns intake",
          "FBA outbound",
          "Excel exports",
        ],
      },
      {
        id: "pro",
        name: "Warehub Pro",
        price: 149,
        priceId: STRIPE_PRICES.pro,
        description: "Multi-location, unlimited packers, priority support",
        features: [
          "Everything in Starter",
          "Unlimited packers",
          "Multi-location support",
          "FedEx live tracking",
          "Priority support",
          "Early access to new features",
        ],
      },
    ],
  });
}

async function createCheckoutSession(request, tenant, auth, env) {
  const b = await request.json().catch(() => ({}));
  const priceId = STRIPE_PRICES[b.plan];
  if (!priceId) return err("Invalid plan — choose starter or pro");

  // Get or create Stripe customer
  let customerId = tenant.stripe_customer_id;
  if (!customerId) {
    const customer = await stripeRequest(
      "/v1/customers",
      "POST",
      {
        email: auth.userEmail || "",
        name: tenant.name,
        "metadata[tenant_id]": tenant.id,
      },
      env
    );
    if (customer.error) {
      return err("Stripe customer error: " + customer.error.message);
    }
    if (!customer.id) {
      return err("Failed to create Stripe customer — check Stripe API key");
    }
    customerId = customer.id;
    await env.DB.prepare(
      `UPDATE tenants SET stripe_customer_id = ? WHERE id = ?`
    )
      .bind(customerId, tenant.id)
      .run();
  }

  const successUrl =
    b.successUrl || "https://app.wareplatform.com/?billing=success";
  const cancelUrl = b.cancelUrl || "https://app.wareplatform.com/billing.html";

  const session = await stripeRequest(
    "/v1/checkout/sessions",
    "POST",
    {
      customer: customerId,
      mode: "subscription",
      "line_items[0][price]": priceId,
      "line_items[0][quantity]": "1",
      success_url: successUrl,
      cancel_url: cancelUrl,
      "subscription_data[metadata][tenant_id]": tenant.id,
      allow_promotion_codes: "true",
    },
    env
  );

  if (session.error)
    return err("Stripe session error: " + session.error.message);
  if (!session.url) return err("No checkout URL returned from Stripe");
  return json({ url: session.url });
}

async function createBillingPortal(request, tenant, env) {
  if (!tenant.stripe_customer_id) {
    return err("No billing account found — please subscribe first");
  }
  const b = await request.json().catch(() => ({}));
  const returnUrl = b.returnUrl || "https://app.wareplatform.com/billing.html";

  const session = await stripeRequest(
    "/v1/billing_portal/sessions",
    "POST",
    {
      customer: tenant.stripe_customer_id,
      return_url: returnUrl,
    },
    env
  );

  if (session.error) return err(session.error.message);
  return json({ url: session.url });
}

async function handleStripeWebhook(request, env) {
  const body = await request.text();
  const sigHeader = request.headers.get("Stripe-Signature") || "";

  // Verify webhook signature
  const valid = await verifyStripeSignature(
    body,
    sigHeader,
    env.STRIPE_WEBHOOK_SECRET
  );
  if (!valid) return err("Invalid webhook signature", 400);

  try {
    const event = JSON.parse(body);

    if (
      event.type === "customer.subscription.updated" ||
      event.type === "customer.subscription.created"
    ) {
      const sub = event.data.object;
      const custId = sub.customer;
      const status = sub.status;
      // Determine plan from price ID
      const priceId = sub.items?.data?.[0]?.price?.id || "";
      const plan =
        priceId === STRIPE_PRICES.pro
          ? "pro"
          : priceId === STRIPE_PRICES.starter
          ? "starter"
          : "trial";
      const active = status === "active" || status === "trialing";
      const expiry = active
        ? null
        : new Date(sub.current_period_end * 1000).toISOString();
      await env.DB.prepare(
        `UPDATE tenants SET plan = ?, plan_expires_at = ?, stripe_subscription_id = ?
         WHERE stripe_customer_id = ?`
      )
        .bind(active ? plan : "trial", expiry, sub.id, custId)
        .run();
    }

    if (event.type === "customer.subscription.deleted") {
      const custId = event.data.object.customer;
      await env.DB.prepare(
        `UPDATE tenants SET plan = 'trial', plan_expires_at = datetime('now')
         WHERE stripe_customer_id = ?`
      )
        .bind(custId)
        .run();
    }

    if (event.type === "checkout.session.completed") {
      const session = event.data.object;
      const tenantId =
        session.subscription_data?.metadata?.tenant_id ||
        session.metadata?.tenant_id;
      if (tenantId && session.customer) {
        await env.DB.prepare(
          `UPDATE tenants SET stripe_customer_id = ? WHERE id = ?`
        )
          .bind(session.customer, tenantId)
          .run();
      }
    }

    await env.DB.prepare(
      `INSERT INTO billing_events (id, stripe_event, event_type)
       VALUES (?, ?, ?)`
    )
      .bind(uuid(), body.slice(0, 4000), event.type || "unknown")
      .run();
  } catch (e) {
    console.error("[Warehub webhook]", e.message);
  }
  return json({ received: true });
}

// ══════════════════════════════════════════════════════════════════
//  AI SELF-LEARNING SYSTEM
//  Events → nightly Claude analysis → Insights surfaced in the app
// ══════════════════════════════════════════════════════════════════

// ── Log a user action event ───────────────────────────────────────
async function logEvent(request, tenant, auth, env) {
  const b = await request.json().catch(() => ({}));
  const { eventType, entityType, entityId, payload } = b;
  if (!eventType) return err("eventType required");

  await env.DB.prepare(
    `INSERT INTO events (id, tenant_id, user_id, event_type, entity_type, entity_id, payload)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(
      uuid(),
      tenant.id,
      auth.userId,
      eventType,
      entityType || null,
      entityId || null,
      JSON.stringify(payload || {})
    )
    .run();

  return json({ ok: true });
}

// ── Get unread insights for this tenant ───────────────────────────
async function getInsights(tenant, env) {
  const { results } = await env.DB.prepare(
    `SELECT * FROM insights
     WHERE tenant_id = ?
       AND (expires_at IS NULL OR expires_at > unixepoch())
     ORDER BY created_at DESC
     LIMIT 50`
  )
    .bind(tenant.id)
    .all();

  return json({ insights: results });
}

// ── Mark a single insight as read ────────────────────────────────
async function markInsightRead(tenant, insightId, env) {
  await env.DB.prepare(
    `UPDATE insights SET is_read = 1
     WHERE id = ? AND tenant_id = ?`
  )
    .bind(insightId, tenant.id)
    .run();
  return json({ ok: true });
}

// ══════════════════════════════════════════════════════════════════
//  NIGHTLY ANALYSIS — runs via Cloudflare cron at 02:00 UTC
// ══════════════════════════════════════════════════════════════════

async function runNightlyAnalysis(env) {
  console.log("[Warehub AI] Starting nightly analysis");

  // Get all active tenants
  const { results: tenants } = await env.DB.prepare(
    `SELECT id, name FROM tenants WHERE plan != 'suspended'`
  ).all();

  for (const tenant of tenants) {
    try {
      await analyzeTenant(tenant, env);
    } catch (e) {
      console.error(`[Warehub AI] Failed for tenant ${tenant.id}:`, e.message);
    }
  }

  // Clean up insights older than 30 days
  await env.DB.prepare(
    `DELETE FROM insights WHERE created_at < unixepoch() - 2592000`
  ).run();

  console.log("[Warehub AI] Nightly analysis complete");
}

async function analyzeTenant(tenant, env) {
  const thirtyDaysAgo = Math.floor(Date.now() / 1000) - 30 * 86400;
  const sevenDaysAgo = Math.floor(Date.now() / 1000) - 7 * 86400;
  const oneDayAgo = Math.floor(Date.now() / 1000) - 86400;

  // ── Aggregate raw event counts ─────────────────────────────────
  const { results: eventCounts } = await env.DB.prepare(
    `SELECT event_type, COUNT(*) as cnt,
            MAX(occurred_at) as last_seen
     FROM events
     WHERE tenant_id = ? AND occurred_at > ?
     GROUP BY event_type`
  )
    .bind(tenant.id, thirtyDaysAgo)
    .all();

  if (!eventCounts.length) return; // no data yet, skip

  // ── Daily activity breakdown (last 7 days) ─────────────────────
  const { results: dailyActivity } = await env.DB.prepare(
    `SELECT date(occurred_at, 'unixepoch') as day,
            event_type, COUNT(*) as cnt
     FROM events
     WHERE tenant_id = ? AND occurred_at > ?
     GROUP BY day, event_type
     ORDER BY day DESC`
  )
    .bind(tenant.id, sevenDaysAgo)
    .all();

  // ── Yesterday's summary ────────────────────────────────────────
  const { results: yesterdayEvents } = await env.DB.prepare(
    `SELECT event_type, COUNT(*) as cnt
     FROM events
     WHERE tenant_id = ? AND occurred_at > ?
     GROUP BY event_type`
  )
    .bind(tenant.id, oneDayAgo)
    .all();

  // ── Recent payloads for context ───────────────────────────────
  const { results: recentSamples } = await env.DB.prepare(
    `SELECT event_type, payload, occurred_at
     FROM events
     WHERE tenant_id = ? AND occurred_at > ?
     ORDER BY occurred_at DESC
     LIMIT 40`
  )
    .bind(tenant.id, sevenDaysAgo)
    .all();

  // ── Build context for Claude ───────────────────────────────────
  const context = {
    tenantName: tenant.name,
    analysisDate: new Date().toISOString().split("T")[0],
    last30Days: eventCounts,
    last7DaysByDay: dailyActivity,
    yesterday: yesterdayEvents,
    recentSamples: recentSamples.slice(0, 20),
  };

  // ── Call Claude Haiku for insight generation ───────────────────
  let aiInsights = [];

  if (env.ANTHROPIC_KEY) {
    try {
      const resp = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-api-key": env.ANTHROPIC_KEY,
          "anthropic-version": "2023-06-01",
        },
        body: JSON.stringify({
          model: "claude-haiku-4-5-20251001",
          max_tokens: 1200,
          messages: [
            {
              role: "user",
              content:
                `You are analyzing 30 days of warehouse operations data for "${tenant.name}".\n` +
                `Generate 3-5 specific, actionable insights based on the activity patterns below.\n` +
                `Focus on: efficiency trends, anomalies, predictions, and concrete recommendations.\n\n` +
                `Return ONLY a valid JSON array (no markdown, no explanation):\n` +
                `[{"insight_type":"velocity_trend|reorder_alert|anomaly|performance|digest",` +
                `"severity":"info|warning|critical","title":"short title","body":"2-3 sentences max"}]\n\n` +
                `DATA:\n${JSON.stringify(context, null, 2)}`,
            },
          ],
        }),
      });

      if (resp.ok) {
        const data = await resp.json();
        const raw = data.content?.[0]?.text || "[]";
        // Strip any accidental markdown fences
        const cleaned = raw
          .replace(/```json?/g, "")
          .replace(/```/g, "")
          .trim();
        aiInsights = JSON.parse(cleaned);
        if (!Array.isArray(aiInsights)) aiInsights = [];
      }
    } catch (e) {
      console.error("[Warehub AI] Claude call failed:", e.message);
    }
  }

  // ── Fallback: rule-based insights if Claude unavailable ────────
  if (!aiInsights.length) {
    aiInsights = generateRuleBasedInsights(context);
  }

  // ── Write insights to D1 ──────────────────────────────────────
  // Delete today's insights first (idempotent re-run)
  await env.DB.prepare(
    `DELETE FROM insights
     WHERE tenant_id = ? AND created_at > unixepoch() - 86400`
  )
    .bind(tenant.id)
    .run();

  const expiresAt = Math.floor(Date.now() / 1000) + 7 * 86400; // 7 day TTL

  for (const ins of aiInsights.slice(0, 6)) {
    await env.DB.prepare(
      `INSERT INTO insights (id, tenant_id, insight_type, title, body, severity, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(
        uuid(),
        tenant.id,
        ins.insight_type || "digest",
        String(ins.title || "").slice(0, 120),
        String(ins.body || "").slice(0, 600),
        ins.severity || "info",
        expiresAt
      )
      .run();
  }

  console.log(
    `[Warehub AI] ${aiInsights.length} insights written for tenant ${tenant.id}`
  );
}

// ── Rule-based fallback (no AI key needed) ────────────────────────
function generateRuleBasedInsights(ctx) {
  const insights = [];
  const counts = {};
  for (const e of ctx.last30Days) counts[e.event_type] = e.cnt;

  // Orders per day trend
  const packed = counts["order_packed"] || 0;
  if (packed > 0) {
    const perDay = (packed / 30).toFixed(1);
    insights.push({
      insight_type: "velocity_trend",
      severity: "info",
      title: `${perDay} orders packed per day (30-day avg)`,
      body:
        `Your warehouse processed ${packed} orders in the last 30 days, averaging ${perDay}/day. ` +
        `Use this as a baseline to spot slowdowns or peak days.`,
    });
  }

  // Return rate
  const returns = counts["return_logged"] || 0;
  if (packed > 0 && returns > 0) {
    const rate = ((returns / packed) * 100).toFixed(1);
    const sev = rate > 10 ? "warning" : "info";
    insights.push({
      insight_type: "anomaly",
      severity: sev,
      title: `Return rate: ${rate}%`,
      body:
        `${returns} returns logged against ${packed} packed orders this month (${rate}% rate). ` +
        (sev === "warning"
          ? "This is above typical 10% — investigate which SKUs are driving returns."
          : "This is within a healthy range."),
    });
  }

  // FBA activity
  const fba = counts["fba_created"] || 0;
  if (fba > 0) {
    insights.push({
      insight_type: "performance",
      severity: "info",
      title: `${fba} FBA shipments initiated this month`,
      body:
        `On average you're sending ${(fba / 4).toFixed(
          1
        )} FBA batches per week. ` +
        `Consider grouping shipments to reduce per-unit prep cost.`,
    });
  }

  // Yesterday quiet
  if (!ctx.yesterday.length) {
    insights.push({
      insight_type: "digest",
      severity: "info",
      title: "No activity recorded yesterday",
      body:
        "The warehouse was quiet yesterday — or data was not synced. " +
        "Make sure the app stays open during shift hours for full telemetry.",
    });
  }

  return insights;
}
