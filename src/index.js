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

const CLERK_DOMAIN = "clerk.login.wareplatform.com";
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

    if (payload.exp && Date.now() / 1000 > payload.exp) return null;

    const keys = await getJwks();
    const jwk = keys.find((k) => k.kid === header.kid);
    if (!jwk) return null;

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
            t.stripe_customer_id, t.stripe_subscription_id, t.cancel_at_period_end,
            t.trial_started_at
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
      cancel_at_period_end: !!row.cancel_at_period_end,
      trial_started_at: row.trial_started_at || null,
      stripe_customer_id: row.stripe_customer_id || null,
      stripe_subscription_id: row.stripe_subscription_id || null,
    },
  };
}

function requireOwner(auth) {
  if (auth.role !== "owner") return err("Only the account owner can do this", 403);
  return null;
}

const TRIAL_DAYS = 14;

// Single source of truth for "does this tenant currently have access" —
// a paid plan always counts; a trial counts only within its first 14 days.
// Previously this was computed 4 separate times, none of which ever
// counted 'trial' as active at all — meaning the advertised 14-day free
// trial never actually worked.
function tenantIsActive(tenant) {
  if (tenant.plan === "starter" || tenant.plan === "pro" || tenant.plan === "basic") {
    return true;
  }
  if (tenant.plan === "trial" && tenant.trial_started_at) {
    const trialEnd = tenant.trial_started_at + TRIAL_DAYS * 86400;
    return Math.floor(Date.now() / 1000) < trialEnd;
  }
  return false;
}

function trialEndsAt(tenant) {
  if (!tenant.trial_started_at) return null;
  return new Date((tenant.trial_started_at + TRIAL_DAYS * 86400) * 1000).toISOString();
}

// ── API key auth (for third-party integrations, e.g. an ERP) ──────
// Separate from Clerk JWT auth — machine clients authenticate with a
// long-lived key instead of a human session token.

function generateApiKey() {
  const raw = "wh_live_" + Array.from(crypto.getRandomValues(new Uint8Array(24)))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return raw;
}

async function hashApiKey(key) {
  const data = new TextEncoder().encode(key);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// Returns { tenant } for a valid, non-revoked API key, or null.
async function resolveApiKeyAuth(request, env) {
  const keyHeader = request.headers.get("X-API-Key") || "";
  if (!keyHeader.startsWith("wh_live_")) return null;

  const hash = await hashApiKey(keyHeader);
  const row = await env.DB.prepare(
    `SELECT ak.id as keyId, ak.tenant_id, t.id as tenantId, t.name as tenantName,
            t.plan, t.plan_expires_at, t.cancel_at_period_end
     FROM api_keys ak
     JOIN tenants t ON t.id = ak.tenant_id
     WHERE ak.key_hash = ? AND ak.revoked = 0`
  )
    .bind(hash)
    .first();

  if (!row) return null;

  // Fire-and-forget last-used timestamp — don't block the request on it.
  env.DB.prepare(`UPDATE api_keys SET last_used_at = unixepoch() WHERE id = ?`)
    .bind(row.keyId)
    .run()
    .catch(() => {});

  return {
    apiKeyId: row.keyId,
    tenant: {
      id: row.tenantId,
      name: row.tenantName,
      plan: row.plan,
      plan_expires_at: row.plan_expires_at,
      cancel_at_period_end: !!row.cancel_at_period_end,
    },
  };
}

// ── Outbound webhooks — fire events to a tenant's registered ERP/
// integration endpoint in real time as things happen in the app.

async function fireWebhookEvent(tenantId, eventType, payload, env) {
  const { results: endpoints } = await env.DB.prepare(
    `SELECT id, url, secret, events FROM webhook_endpoints
     WHERE tenant_id = ? AND active = 1`
  )
    .bind(tenantId)
    .all();

  for (const ep of endpoints) {
    const subscribedEvents = (ep.events || "").split(",").map((s) => s.trim());
    if (!subscribedEvents.includes(eventType) && !subscribedEvents.includes("*")) continue;

    const body = JSON.stringify({ type: eventType, data: payload, timestamp: Date.now() });
    try {
      const sig = await signWebhookBody(body, ep.secret);
      const resp = await fetch(ep.url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Warehub-Signature": sig,
        },
        body,
      });
      await env.DB.prepare(
        `UPDATE webhook_endpoints SET last_triggered_at = unixepoch(), last_status = ? WHERE id = ?`
      )
        .bind(resp.status, ep.id)
        .run();
    } catch (e) {
      console.error(`[Warehub Webhook] Failed to deliver to ${ep.url}:`, e.message);
      await env.DB.prepare(
        `UPDATE webhook_endpoints SET last_triggered_at = unixepoch(), last_status = 0 WHERE id = ?`
      )
        .bind(ep.id)
        .run()
        .catch(() => {});
    }
  }
}

async function signWebhookBody(body, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(body));
  return Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function createApiKey(request, tenant, auth, env) {
  const b = await request.json().catch(() => ({}));
  const name = (b.name || "").trim() || "Unnamed key";

  const rawKey = generateApiKey();
  const hash = await hashApiKey(rawKey);
  const prefix = rawKey.slice(0, 14) + "…"; // e.g. "wh_live_a1b2c3…" for display

  const id = uuid();
  await env.DB.prepare(
    `INSERT INTO api_keys (id, tenant_id, name, key_hash, key_prefix, created_by)
     VALUES (?, ?, ?, ?, ?, ?)`
  )
    .bind(id, tenant.id, name, hash, prefix, auth.userId)
    .run();

  // The raw key is only ever shown this one time — it isn't recoverable
  // from storage afterward (only its hash is kept).
  return json({ id, key: rawKey, prefix }, 201);
}

async function createWebhookEndpoint(request, tenant, env) {
  const b = await request.json().catch(() => ({}));
  const url = (b.url || "").trim();
  const events = Array.isArray(b.events) && b.events.length ? b.events.join(",") : "*";
  if (!url || !url.startsWith("https://")) {
    return err("A valid https:// URL is required");
  }

  const secretBytes = crypto.getRandomValues(new Uint8Array(24));
  const secret = Array.from(secretBytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  const id = uuid();
  await env.DB.prepare(
    `INSERT INTO webhook_endpoints (id, tenant_id, url, secret, events)
     VALUES (?, ?, ?, ?, ?)`
  )
    .bind(id, tenant.id, url, secret, events)
    .run();

  // Secret is shown once, same pattern as the API key itself — needed so
  // the ERP side can verify the X-Warehub-Signature header on delivery.
  return json({ id, url, secret, events }, 201);
}

// ── Interactive AI chat/actions proxy ────────────────────────────
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
  if (method === "POST" && path === "/api/billing/webhook") {
    return handleStripeWebhook(request, env);
  }
  if (method === "GET" && path === "/api/billing/plans") {
    return getBillingPlans();
  }

  // ── API key routes (third-party integrations, e.g. an ERP) ──────
  // Separate auth path from the Clerk-session routes below — machine
  // clients present X-API-Key instead of a Bearer JWT.
  if (path.startsWith("/api/v1/")) {
    const apiAuth = await resolveApiKeyAuth(request, env);
    if (!apiAuth) return err("Invalid or missing API key", 401);
    const v1Tenant = apiAuth.tenant;

    if (path === "/api/v1/orders" && method === "GET") {
      return v1GetOrders(request, v1Tenant, env);
    }
    if (path === "/api/v1/orders" && method === "POST") {
      return v1CreateOrders(request, v1Tenant, env);
    }
    const v1OrderMatch = path.match(/^\/api\/v1\/orders\/([^/]+)$/);
    if (v1OrderMatch && method === "PATCH") {
      return v1UpdateOrder(request, v1Tenant, v1OrderMatch[1], env);
    }
    return err("Not found", 404);
  }

  // ── Authenticated routes ───────────────────────────────────────
  const auth = await resolveAuth(request, env);
  if (!auth) return err("Unauthorized", 401);

  const { tenant } = auth;

  // Only block access once the period has passed AND it's not set to
  // auto-renew — an auto-renewing sub's plan_expires_at is just next
  // month's billing date, not a cutoff. If a renewal webhook is late,
  // this avoids locking out a paying customer.
  if (
    tenant.cancel_at_period_end &&
    tenant.plan_expires_at &&
    new Date(tenant.plan_expires_at) < new Date()
  ) {
    return err(
      "Subscription expired — please renew at app.warehub.com/billing",
      402
    );
  }
  // A trial tenant whose 14 days have run out and never subscribed.
  if (tenant.plan === "trial" && !tenantIsActive(tenant)) {
    return err(
      "Your free trial has ended — choose a plan at app.wareplatform.com/billing.html to continue",
      402
    );
  }

  if (path === "/api/health") {
    return json({ status: "ok", tenant: tenant.name, plan: tenant.plan });
  }

  if (path === "/api/ai" && method === "POST") {
    const denied = requireFeature(tenant, "ai");
    if (denied) return denied;
    return handleAiChat(request, tenant, env);
  }

  if (path === "/api/billing/status" && method === "GET") {
    return json({
      plan: tenant.plan || "trial",
      active: tenantIsActive(tenant),
      expiresAt: tenant.plan_expires_at || null,
      cancelAtPeriodEnd: tenant.cancel_at_period_end || false,
      trialEndsAt: tenant.plan === "trial" ? trialEndsAt(tenant) : null,
    });
  }
  if (path === "/api/billing/checkout" && method === "POST") {
    return createCheckoutSession(request, tenant, auth, env);
  }
  if (path === "/api/billing/portal" && method === "POST") {
    return createBillingPortal(request, tenant, env);
  }

  // ── Reconciliation issues (owner only) ──────────────────────────
  if (path === "/api/billing/issues" && method === "GET") {
    const denied = requireOwner(auth);
    if (denied) return denied;
    const { results } = await env.DB.prepare(
      `SELECT id, issue, d1_plan, stripe_status, detected_at
       FROM reconciliation_issues
       WHERE tenant_id = ? AND resolved = 0
       ORDER BY detected_at DESC`
    )
      .bind(tenant.id)
      .all();
    return json({ issues: results });
  }

  // ── xlwms integration (owner only) — pull outbound orders ───────
  if (path === "/api/integrations/xlwms/sync" && method === "POST") {
    const denied = requireOwner(auth);
    if (denied) return denied;
    const b = await request.json().catch(() => ({}));
    const result = await xlwmsSyncOrders(tenant, env, b);
    if (result.error) return json({ error: result.error, code: result.code, raw: result.raw }, 502);
    return json(result);
  }

  // ── API integrations (owner only) — keys + outbound webhooks ────
  if (path === "/api/integrations/keys" && method === "GET") {
    const denied = requireOwner(auth);
    if (denied) return denied;
    const { results } = await env.DB.prepare(
      `SELECT id, name, key_prefix, created_at, last_used_at, revoked
       FROM api_keys WHERE tenant_id = ? AND revoked = 0 ORDER BY created_at DESC`
    )
      .bind(tenant.id)
      .all();
    return json({ keys: results });
  }
  if (path === "/api/integrations/keys" && method === "POST") {
    const denied = requireOwner(auth);
    if (denied) return denied;
    return createApiKey(request, tenant, auth, env);
  }
  const keyRevokeMatch = path.match(/^\/api\/integrations\/keys\/([^/]+)$/);
  if (keyRevokeMatch && method === "DELETE") {
    const denied = requireOwner(auth);
    if (denied) return denied;
    await env.DB.prepare(
      `UPDATE api_keys SET revoked = 1 WHERE id = ? AND tenant_id = ?`
    )
      .bind(keyRevokeMatch[1], tenant.id)
      .run();
    return json({ ok: true });
  }
  if (path === "/api/integrations/webhooks" && method === "GET") {
    const denied = requireOwner(auth);
    if (denied) return denied;
    const { results } = await env.DB.prepare(
      `SELECT id, url, events, active, created_at, last_triggered_at, last_status
       FROM webhook_endpoints WHERE tenant_id = ? ORDER BY created_at DESC`
    )
      .bind(tenant.id)
      .all();
    return json({ webhooks: results });
  }
  if (path === "/api/integrations/webhooks" && method === "POST") {
    const denied = requireOwner(auth);
    if (denied) return denied;
    return createWebhookEndpoint(request, tenant, env);
  }
  const webhookDeleteMatch = path.match(/^\/api\/integrations\/webhooks\/([^/]+)$/);
  if (webhookDeleteMatch && method === "DELETE") {
    const denied = requireOwner(auth);
    if (denied) return denied;
    await env.DB.prepare(
      `DELETE FROM webhook_endpoints WHERE id = ? AND tenant_id = ?`
    )
      .bind(webhookDeleteMatch[1], tenant.id)
      .run();
    return json({ ok: true });
  }

  // ── Team management (owner only) ───────────────────────────────
  if (path === "/api/team" && method === "GET") {
    return getTeam(tenant, env);
  }
  if (path === "/api/team/invite" && method === "POST") {
    const denied = requireOwner(auth);
    if (denied) return denied;
    return inviteTeamMember(request, tenant, auth, env);
  }
  const inviteCancelMatch = path.match(/^\/api\/team\/invite\/([^/]+)$/);
  if (inviteCancelMatch && method === "DELETE") {
    const denied = requireOwner(auth);
    if (denied) return denied;
    return cancelInvite(tenant, inviteCancelMatch[1], env);
  }
  const teamMemberMatch = path.match(/^\/api\/team\/([^/]+)$/);
  if (teamMemberMatch && method === "DELETE") {
    const denied = requireOwner(auth);
    if (denied) return denied;
    return removeTeamMember(tenant, auth, teamMemberMatch[1], env);
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
    const denied = requireFeature(tenant, "vehicle");
    if (denied) return denied;
    if (method === "GET") return getTrips(tenant, env);
    if (method === "POST") return createTrip(request, tenant, env);
  }
  const tripMatch = path.match(/^\/api\/vehicle\/trips\/([^/]+)$/);
  if (tripMatch) {
    const denied = requireFeature(tenant, "vehicle");
    if (denied) return denied;
    if (method === "DELETE") return deleteTrip(tenant, tripMatch[1], env);
  }

  // ── Returns ───────────────────────────────────────────────────
  if (path === "/api/returns") {
    const denied = requireFeature(tenant, "returns");
    if (denied) return denied;
    if (method === "GET") return getReturns(tenant, env);
    if (method === "POST") return createReturn(request, tenant, env);
  }
  const returnMatch = path.match(/^\/api\/returns\/([^/]+)$/);
  if (returnMatch) {
    const denied = requireFeature(tenant, "returns");
    if (denied) return denied;
    if (method === "DELETE") return deleteReturn(tenant, returnMatch[1], env);
  }

  // ── FBA ───────────────────────────────────────────────────────
  if (path === "/api/fba") {
    const denied = requireFeature(tenant, "fba");
    if (denied) return denied;
    if (method === "GET") return getFBA(tenant, env);
    if (method === "POST") return createFBA(request, tenant, env);
  }
  const fbaMatch = path.match(/^\/api\/fba\/([^/]+)$/);
  if (fbaMatch) {
    const denied = requireFeature(tenant, "fba");
    if (denied) return denied;
    if (method === "DELETE") return deleteFBA(tenant, fbaMatch[1], env);
  }

  // ── FBA Outbound grid (flat, spreadsheet-style) ─────────────────
  if (path === "/api/fba-grid") {
    const denied = requireFeature(tenant, "fba");
    if (denied) return denied;
    if (method === "GET") return getFbaGrid(tenant, env);
    if (method === "POST") return createFbaGridRow(request, tenant, env);
  }
  const fbaGridMatch = path.match(/^\/api\/fba-grid\/([^/]+)$/);
  if (fbaGridMatch) {
    const denied = requireFeature(tenant, "fba");
    if (denied) return denied;
    if (method === "PATCH") return updateFbaGridRow(request, tenant, fbaGridMatch[1], env);
    if (method === "DELETE") return deleteFbaGridRow(tenant, fbaGridMatch[1], env);
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

  // Already-registered user (any role) — just return their tenant/role
  const existing = await env.DB.prepare(
    `SELECT u.tenant_id, u.role, t.plan, t.plan_expires_at, t.trial_started_at
     FROM users u JOIN tenants t ON t.id = u.tenant_id
     WHERE u.clerk_user_id = ?`
  )
    .bind(clerkUserId)
    .first();
  if (existing) {
    return json({
      tenantId: existing.tenant_id,
      plan: existing.plan || "trial",
      active: tenantIsActive(existing),
      role: existing.role,
      trialEndsAt: existing.plan === "trial" ? trialEndsAt(existing) : null,
      existing: true,
    });
  }

  // Check for a pending invite matching this email — join that tenant
  // instead of creating a brand new one.
  const invite = await env.DB.prepare(
    `SELECT i.id as inviteId, i.tenant_id, i.role, t.plan, t.plan_expires_at, t.trial_started_at
     FROM invites i JOIN tenants t ON t.id = i.tenant_id
     WHERE lower(i.email) = lower(?) AND i.accepted_at IS NULL`
  )
    .bind(email)
    .first();

  if (invite) {
    const userId = uuid();
    await env.DB.prepare(
      `INSERT INTO users (id, tenant_id, clerk_user_id, email, name, role)
       VALUES (?, ?, ?, ?, ?, ?)`
    )
      .bind(userId, invite.tenant_id, clerkUserId, email, name, invite.role || "packer")
      .run();
    await env.DB.prepare(
      `UPDATE invites SET accepted_at = unixepoch() WHERE id = ?`
    )
      .bind(invite.inviteId)
      .run();

    return json({
      tenantId: invite.tenant_id,
      plan: invite.plan || "trial",
      active: tenantIsActive(invite),
      role: invite.role || "packer",
      trialEndsAt: invite.plan === "trial" ? trialEndsAt(invite) : null,
      existing: false,
    });
  }

  // Same email already has an account under a DIFFERENT Clerk identity —
  // this happens if someone re-signs-up after an auth widget hiccup, or
  // after a dev→production Clerk migration issues a new user id for the
  // same person. Attach to their existing tenant instead of silently
  // spinning up a new empty duplicate company (which is exactly what
  // happened before this check existed).
  const emailMatch = await env.DB.prepare(
    `SELECT u.tenant_id, u.role, t.plan, t.plan_expires_at, t.trial_started_at
     FROM users u JOIN tenants t ON t.id = u.tenant_id
     WHERE lower(u.email) = lower(?)
     ORDER BY u.id ASC LIMIT 1`
  )
    .bind(email)
    .first();

  if (emailMatch) {
    const userId = uuid();
    await env.DB.prepare(
      `INSERT INTO users (id, tenant_id, clerk_user_id, email, name, role)
       VALUES (?, ?, ?, ?, ?, ?)`
    )
      .bind(userId, emailMatch.tenant_id, clerkUserId, email, name, emailMatch.role)
      .run();

    return json({
      tenantId: emailMatch.tenant_id,
      plan: emailMatch.plan || "trial",
      active: tenantIsActive(emailMatch),
      role: emailMatch.role,
      trialEndsAt: emailMatch.plan === "trial" ? trialEndsAt(emailMatch) : null,
      existing: false,
      merged: true,
    });
  }

  // No invite — create a brand-new tenant, this user becomes the owner.
  // Start the 14-day free trial clock right now — this is the fix for the
  // trial never actually working before.
  const tenantId = uuid();
  const userId = uuid();
  const trialStartedAt = Math.floor(Date.now() / 1000);

  await env.DB.prepare(
    `INSERT INTO tenants (id, name, plan, trial_started_at) VALUES (?, ?, 'trial', ?)`
  )
    .bind(tenantId, name, trialStartedAt)
    .run();

  await env.DB.prepare(
    `INSERT INTO users (id, tenant_id, clerk_user_id, email, name, role)
     VALUES (?, ?, ?, ?, ?, 'owner')`
  )
    .bind(userId, tenantId, clerkUserId, email, name)
    .run();

  return json({
    tenantId,
    userId,
    plan: "trial",
    active: true,
    role: "owner",
    trialEndsAt: trialEndsAt({ trial_started_at: trialStartedAt }),
  }, 201);
}

// ── Team management ─────────────────────────────────────────────

async function getTeam(tenant, env) {
  const { results: members } = await env.DB.prepare(
    `SELECT id, name, email, role FROM users WHERE tenant_id = ? ORDER BY role DESC, name`
  )
    .bind(tenant.id)
    .all();

  const { results: pending } = await env.DB.prepare(
    `SELECT id, email, role, created_at FROM invites
     WHERE tenant_id = ? AND accepted_at IS NULL ORDER BY created_at DESC`
  )
    .bind(tenant.id)
    .all();

  return json({ members, pendingInvites: pending });
}

async function inviteTeamMember(request, tenant, auth, env) {
  const b = await request.json().catch(() => ({}));
  const email = (b.email || "").trim().toLowerCase();
  const role = b.role === "manager" ? "manager" : "packer"; // only owner/manager/packer allowed via invite
  if (!email || !email.includes("@")) return err("A valid email is required");

  const alreadyMember = await env.DB.prepare(
    `SELECT id FROM users WHERE tenant_id = ? AND lower(email) = ?`
  )
    .bind(tenant.id, email)
    .first();
  if (alreadyMember) return err("That email is already on your team");

  const existingInvite = await env.DB.prepare(
    `SELECT id FROM invites WHERE tenant_id = ? AND lower(email) = ? AND accepted_at IS NULL`
  )
    .bind(tenant.id, email)
    .first();
  if (existingInvite) return err("An invite is already pending for that email");

  const id = uuid();
  await env.DB.prepare(
    `INSERT INTO invites (id, tenant_id, email, role, invited_by)
     VALUES (?, ?, ?, ?, ?)`
  )
    .bind(id, tenant.id, email, role, auth.userId)
    .run();

  return json({ ok: true, id }, 201);
}

async function cancelInvite(tenant, inviteId, env) {
  await env.DB.prepare(
    `DELETE FROM invites WHERE id = ? AND tenant_id = ? AND accepted_at IS NULL`
  )
    .bind(inviteId, tenant.id)
    .run();
  return json({ ok: true });
}

async function removeTeamMember(tenant, auth, userId, env) {
  if (userId === auth.userId) return err("You can't remove yourself");
  const target = await env.DB.prepare(
    `SELECT role FROM users WHERE id = ? AND tenant_id = ?`
  )
    .bind(userId, tenant.id)
    .first();
  if (!target) return err("Team member not found", 404);
  if (target.role === "owner") return err("Can't remove the account owner");

  await env.DB.prepare(`DELETE FROM users WHERE id = ? AND tenant_id = ?`)
    .bind(userId, tenant.id)
    .run();
  return json({ ok: true });
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

  const limits = planLimitsFor(tenant);
  const { count: existingCount } = await env.DB.prepare(
    `SELECT COUNT(*) as count FROM packers WHERE tenant_id = ?`
  )
    .bind(tenant.id)
    .first();
  let currentCount = existingCount;

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
      if (currentCount >= limits.maxPackers) {
        // Skip packers beyond the plan's limit rather than failing the
        // whole sync batch — the rest of the list still gets synced.
        continue;
      }
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
      currentCount++;
    }

    if (Array.isArray(p.shiftSessions)) {
      for (const s of p.shiftSessions) {
        const clockIn = s.clockIn ? new Date(s.clockIn).toISOString() : null;
        const clockOut = s.clockOut ? new Date(s.clockOut).toISOString() : null;
        if (!clockIn) continue;
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

  const limits = planLimitsFor(tenant);
  const { count } = await env.DB.prepare(
    `SELECT COUNT(*) as count FROM packers WHERE tenant_id = ?`
  )
    .bind(tenant.id)
    .first();
  if (count >= limits.maxPackers) {
    return err(
      `Your ${tenant.plan} plan allows up to ${limits.maxPackers} packers. Upgrade to add more.`,
      403
    );
  }

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
  const insertedOrders = [];
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
    insertedOrders.push({ id, tracking: o.tracking, carrier: o.carrier || "Unknown" });
    inserted++;
  }
  if (insertedOrders.length) {
    fireWebhookEvent(tenant.id, "order.created", { orders: insertedOrders }, env).catch(() => {});
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

  if (b.status === "done") {
    const order = await env.DB.prepare(
      `SELECT id, tracking, carrier, packed_by, completed_at FROM orders WHERE id = ? AND tenant_id = ?`
    )
      .bind(orderId, tenant.id)
      .first();
    if (order) {
      fireWebhookEvent(tenant.id, "order.completed", order, env).catch(() => {});
    }
  }

  return json({ ok: true });
}

// ══════════════════════════════════════════════════════════════════
//  API v1 — third-party integration endpoints (API key auth)
// ══════════════════════════════════════════════════════════════════

async function v1GetOrders(request, tenant, env) {
  const url = new URL(request.url);
  const since = url.searchParams.get("since"); // ISO timestamp, optional
  const status = url.searchParams.get("status"); // 'pending' | 'done', optional

  let query = `SELECT * FROM orders WHERE tenant_id = ?`;
  const params = [tenant.id];
  if (since) {
    query += ` AND imported_at >= ?`;
    params.push(since);
  }
  if (status) {
    query += ` AND status = ?`;
    params.push(status);
  }
  query += ` ORDER BY imported_at DESC LIMIT 500`;

  const { results: orders } = await env.DB.prepare(query).bind(...params).all();
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

async function v1CreateOrders(request, tenant, env) {
  // Same shape/behavior as the browser-facing create — an ERP pushing new
  // orders in should look identical to importing a carrier PDF.
  return createOrders(request, tenant, env);
}

async function v1UpdateOrder(request, tenant, orderId, env) {
  return updateOrder(request, tenant, orderId, env);
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

// ── FBA Outbound grid (flat, spreadsheet-style row entry) ──────────

async function getFbaGrid(tenant, env) {
  const { results } = await env.DB.prepare(
    `SELECT * FROM fba_outbound_items WHERE tenant_id = ? ORDER BY created_at DESC`
  )
    .bind(tenant.id)
    .all();
  return json({ rows: results });
}

async function createFbaGridRow(request, tenant, env) {
  const b = await request.json().catch(() => ({}));
  const id = uuid();
  await env.DB.prepare(
    `INSERT INTO fba_outbound_items
       (id, tenant_id, ship_date, shipment_id, fulfillment_center, sku, qty,
        size, weight, carrier, tracking, boxes, submitted_by, notes)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(
      id,
      tenant.id,
      b.ship_date || new Date().toISOString().slice(0, 10),
      b.shipment_id || "",
      b.fulfillment_center || "",
      b.sku || "",
      b.qty || 0,
      b.size || "",
      b.weight || null,
      b.carrier || "",
      b.tracking || "",
      b.boxes || null,
      b.submitted_by || "",
      b.notes || ""
    )
    .run();
  return json({ id }, 201);
}

async function updateFbaGridRow(request, tenant, rowId, env) {
  const b = await request.json().catch(() => ({}));
  const allowed = [
    "ship_date", "shipment_id", "fulfillment_center", "sku", "qty",
    "size", "weight", "carrier", "tracking", "boxes", "submitted_by", "notes",
  ];
  const fields = [], values = [];
  for (const key of allowed) {
    if (key in b) {
      fields.push(`${key} = ?`);
      values.push(b[key]);
    }
  }
  if (!fields.length) return err("Nothing to update");
  values.push(rowId, tenant.id);
  await env.DB.prepare(
    `UPDATE fba_outbound_items SET ${fields.join(", ")} WHERE id = ? AND tenant_id = ?`
  )
    .bind(...values)
    .run();
  return json({ ok: true });
}

async function deleteFbaGridRow(tenant, rowId, env) {
  await env.DB.prepare(
    `DELETE FROM fba_outbound_items WHERE id = ? AND tenant_id = ?`
  )
    .bind(rowId, tenant.id)
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

// ── Stripe helpers ────────────────────────────────────────────────

// ══════════════════════════════════════════════════════════════════
//  xlwms (领星WMS) Integration — pull outbound orders/labels
//  Credentials come from env.XLWMS_APP_KEY / env.XLWMS_APP_SECRET
//  (set via `wrangler secret put`, never stored in source or DB).
// ══════════════════════════════════════════════════════════════════

// Recursively sorts object keys alphabetically — JS's default key order
// isn't guaranteed to match "字典升序排序" (dictionary ascending order),
// so this makes it explicit before JSON.stringify.
function sortKeysDeep(value) {
  if (Array.isArray(value)) return value.map(sortKeysDeep);
  if (value && typeof value === "object") {
    const sorted = {};
    for (const key of Object.keys(value).sort()) {
      sorted[key] = sortKeysDeep(value[key]);
    }
    return sorted;
  }
  return value;
}

async function xlwmsSign(dataObj, appKey, appSecret, timestamp) {
  const dataStr = JSON.stringify(sortKeysDeep(dataObj));
  const concatStr = appKey + dataStr + timestamp;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(appSecret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sigBuf = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(concatStr));
  return Array.from(new Uint8Array(sigBuf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function xlwmsRequest(path, dataObj, env) {
  if (!env.XLWMS_APP_KEY || !env.XLWMS_APP_SECRET) {
    return { error: { message: "xlwms credentials not configured on this Worker" } };
  }
  const timestamp = String(Math.floor(Date.now() / 1000));
  const sign = await xlwmsSign(dataObj, env.XLWMS_APP_KEY, env.XLWMS_APP_SECRET, timestamp);

  const resp = await fetch("https://api.xlwms.com" + path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      appKey: env.XLWMS_APP_KEY,
      timestamp,
      sign,
      data: dataObj,
    }),
  });
  return resp.json();
}

// Pulls recent outbound orders from xlwms and imports them as pending
// orders in D1 — same shape as a manual PDF label import, just automated.
async function xlwmsSyncOrders(tenant, env, opts) {
  opts = opts || {};
  const pageSize = 100;
  let page = 1;
  let imported = 0;
  let totalPages = 1;

  do {
    const result = await xlwmsRequest(
      "/openapi/v2/order/delivery/page",
      {
        current: page,
        size: pageSize,
        timeType: "createTime",
        startTime: opts.startTime || new Date(Date.now() - 24 * 3600000).toISOString().slice(0, 19).replace("T", " "),
        endTime: opts.endTime || new Date().toISOString().slice(0, 19).replace("T", " "),
      },
      env
    );

    if (!result.success) {
      return { error: result.msg || "xlwms request failed", code: result.code, raw: JSON.stringify(result).slice(0, 300) };
    }

    const records = (result.data && result.data.records) || [];
    totalPages = (result.data && result.data.pages) || 1;

    for (const rec of records) {
      // Avoid re-importing the same order on repeated syncs.
      const existing = await env.DB.prepare(
        `SELECT id FROM orders WHERE tenant_id = ? AND tracking = ?`
      )
        .bind(tenant.id, rec.expressNo || rec.sourceNo)
        .first();
      if (existing) continue;

      const id = uuid();
      await env.DB.prepare(
        `INSERT INTO orders (id, tenant_id, tracking, carrier, shelf, status)
         VALUES (?, ?, ?, ?, ?, 'pending')`
      )
        .bind(
          id,
          tenant.id,
          rec.expressNo || rec.sourceNo || "",
          rec.logisticsChannelName || rec.logisticsChannel || "Unknown",
          null
        )
        .run();

      if (Array.isArray(rec.productList)) {
        for (const p of rec.productList) {
          await env.DB.prepare(
            `INSERT INTO order_skus (id, tenant_id, order_id, sku, qty)
             VALUES (?, ?, ?, ?, ?)`
          )
            .bind(uuid(), tenant.id, id, p.productSku || "", p.qty || 1)
            .run();
        }
      }
      imported++;
    }
    page++;
  } while (page <= totalPages && page <= 20); // safety cap: 20 pages per sync

  return { imported };
}

const STRIPE_PRICES = {
  basic: "price_1U8a4YRrPnCkZ2Dx2A94sTLI",
  starter: "price_1U8a7tRrPnCkZ2DxwWu1KRHv",
  pro: "price_1U8aBXRrPnCkZ2DxHXEaZJhA",
};

// Single source of truth for what each plan actually includes — must stay
// in sync with the feature lists on the landing page and billing.html.
const PLAN_LIMITS = {
  trial:   { maxPackers: 3,         vehicle: false, returns: false, fba: false, ai: false, multiLocation: false },
  basic:   { maxPackers: 3,         vehicle: false, returns: false, fba: false, ai: false, multiLocation: false },
  starter: { maxPackers: 10,        vehicle: true,  returns: true,  fba: true,  ai: false, multiLocation: false },
  pro:     { maxPackers: Infinity,  vehicle: true,  returns: true,  fba: true,  ai: true,  multiLocation: true  },
};

function planLimitsFor(tenant) {
  return PLAN_LIMITS[tenant.plan] || PLAN_LIMITS.trial;
}

// Returns an error Response if this feature isn't included in the tenant's
// plan, otherwise null. Use: `const denied = requireFeature(tenant, 'fba'); if (denied) return denied;`
function requireFeature(tenant, feature) {
  const limits = planLimitsFor(tenant);
  if (!limits[feature]) {
    return err(
      `This feature isn't included in your current plan (${tenant.plan}). Upgrade at app.wareplatform.com/billing.html to unlock it.`,
      403
    );
  }
  return null;
}

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
        id: "basic",
        name: "Warehub Basic",
        price: 29,
        priceId: STRIPE_PRICES.basic,
        description: "For solo sellers and small teams just getting started.",
        features: [
          "Order queue & barcode scanning",
          "PDF label import (all carriers)",
          "Basic productivity stats",
          "Single warehouse location",
          "Up to 3 packers",
        ],
      },
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
  if (!priceId) return err("Invalid plan — choose basic, starter or pro");

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

  const valid = await verifyStripeSignature(
    body,
    sigHeader,
    env.STRIPE_WEBHOOK_SECRET
  );
  if (!valid) return err("Invalid webhook signature", 400);

  let event;
  try {
    event = JSON.parse(body);
  } catch (e) {
    // Malformed payload — log and ack so Stripe doesn't retry forever on
    // something that will never parse.
    await env.DB.prepare(
      `INSERT INTO billing_events (id, stripe_event, event_type, error)
       VALUES (?, ?, ?, ?)`
    )
      .bind(uuid(), body.slice(0, 4000), "unknown", "JSON parse failed: " + e.message)
      .run();
    return json({ received: true });
  }

  let handlerError = null;
  try {
    if (
      event.type === "customer.subscription.updated" ||
      event.type === "customer.subscription.created"
    ) {
      const sub = event.data.object;
      const custId = sub.customer;
      const status = sub.status;
      const priceId = sub.items?.data?.[0]?.price?.id || "";
      const plan =
        priceId === STRIPE_PRICES.pro
          ? "pro"
          : priceId === STRIPE_PRICES.starter
          ? "starter"
          : priceId === STRIPE_PRICES.basic
          ? "basic"
          : "trial";
      const active = status === "active" || status === "trialing";
      // Always record the current period's end date — this is either the
      // next renewal date (auto-renewing) or the date access cuts off
      // (canceled). cancel_at_period_end tells the frontend which case it is.
      const periodEnd = sub.current_period_end
        ? new Date(sub.current_period_end * 1000).toISOString()
        : null;
      const result = await env.DB.prepare(
        `UPDATE tenants SET plan = ?, plan_expires_at = ?, stripe_subscription_id = ?,
                cancel_at_period_end = ?
         WHERE stripe_customer_id = ?`
      )
        .bind(
          active ? plan : "trial",
          periodEnd,
          sub.id,
          sub.cancel_at_period_end ? 1 : 0,
          custId
        )
        .run();
      // No tenant matched this customer ID — this event silently did
      // nothing, which is exactly the class of bug that went undetected
      // for days. Flag it instead of letting it disappear.
      if (!result.meta || result.meta.changes === 0) {
        handlerError = `No tenant found with stripe_customer_id=${custId}`;
      }
    }

    if (event.type === "customer.subscription.deleted") {
      const custId = event.data.object.customer;
      const result = await env.DB.prepare(
        `UPDATE tenants SET plan = 'trial', plan_expires_at = datetime('now')
         WHERE stripe_customer_id = ?`
      )
        .bind(custId)
        .run();
      if (!result.meta || result.meta.changes === 0) {
        handlerError = `No tenant found with stripe_customer_id=${custId}`;
      }
    }

    if (event.type === "checkout.session.completed") {
      const session = event.data.object;
      const tenantId =
        session.subscription_data?.metadata?.tenant_id ||
        session.metadata?.tenant_id;
      if (tenantId && session.customer) {
        const result = await env.DB.prepare(
          `UPDATE tenants SET stripe_customer_id = ? WHERE id = ?`
        )
          .bind(session.customer, tenantId)
          .run();
        if (!result.meta || result.meta.changes === 0) {
          handlerError = `No tenant found with id=${tenantId}`;
        }
      } else {
        handlerError = "checkout.session.completed missing tenant_id metadata";
      }
    }
  } catch (e) {
    console.error("[Warehub webhook]", event.type, e.message);
    handlerError = e.message;
  }

  // Always record what happened — success or failure — so nothing goes
  // silently missing the way it did before.
  await env.DB.prepare(
    `INSERT INTO billing_events (id, stripe_event, event_type, error)
     VALUES (?, ?, ?, ?)`
  )
    .bind(uuid(), body.slice(0, 4000), event.type || "unknown", handlerError)
    .run();

  return json({ received: true });
}

// ══════════════════════════════════════════════════════════════════
//  AI SELF-LEARNING SYSTEM
// ══════════════════════════════════════════════════════════════════

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

  await env.DB.prepare(
    `DELETE FROM insights WHERE created_at < unixepoch() - 2592000`
  ).run();

  console.log("[Warehub AI] Nightly analysis complete");

  try {
    await reconcileBilling(env);
  } catch (e) {
    console.error("[Warehub Reconcile] Failed:", e.message);
  }
}

// ══════════════════════════════════════════════════════════════════
//  NIGHTLY RECONCILIATION — catches drift between D1 and Stripe that
//  a missed/failed webhook would otherwise leave undetected
// ══════════════════════════════════════════════════════════════════

async function reconcileBilling(env) {
  console.log("[Warehub Reconcile] Starting billing reconciliation");

  const { results: tenants } = await env.DB.prepare(
    `SELECT id, name, plan, stripe_customer_id, stripe_subscription_id,
            plan_expires_at, cancel_at_period_end
     FROM tenants
     WHERE stripe_customer_id IS NOT NULL`
  ).all();

  let issues = 0;

  for (const tenant of tenants) {
    try {
      // Ask Stripe what's actually true for this customer, independent of
      // whatever our own webhook history says.
      const subs = await stripeRequest(
        `/v1/subscriptions?customer=${tenant.stripe_customer_id}&status=all&limit=10`,
        "GET",
        null,
        env
      );
      if (subs.error) {
        await flagIssue(env, tenant.id, `Stripe API error: ${subs.error.message}`, tenant.plan, null);
        issues++;
        continue;
      }

      const activeSubs = (subs.data || []).filter(
        (s) => s.status === "active" || s.status === "trialing"
      );

      if (tenant.plan !== "trial" && activeSubs.length === 0) {
        // D1 thinks this tenant is paying; Stripe says no active subscription exists.
        await flagIssue(
          env,
          tenant.id,
          "Tenant marked as paid in D1 but has no active Stripe subscription",
          tenant.plan,
          "none"
        );
        issues++;
      } else if (activeSubs.length > 1) {
        // Seen this exact scenario today — duplicate subscriptions racing
        // each other for which one "wins" in D1.
        await flagIssue(
          env,
          tenant.id,
          `Tenant has ${activeSubs.length} simultaneous active Stripe subscriptions`,
          tenant.plan,
          activeSubs.map((s) => s.id).join(",")
        );
        issues++;
      } else if (activeSubs.length === 1) {
        const sub = activeSubs[0];
        const priceId = sub.items?.data?.[0]?.price?.id || "";
        const stripePlan =
          priceId === STRIPE_PRICES.pro
            ? "pro"
            : priceId === STRIPE_PRICES.starter
            ? "starter"
            : priceId === STRIPE_PRICES.basic
            ? "basic"
            : "unknown";
        if (stripePlan !== tenant.plan) {
          await flagIssue(
            env,
            tenant.id,
            `D1 plan (${tenant.plan}) does not match Stripe's active subscription plan (${stripePlan})`,
            tenant.plan,
            sub.status
          );
          issues++;
        }
        if (tenant.stripe_subscription_id !== sub.id) {
          await flagIssue(
            env,
            tenant.id,
            `D1 stripe_subscription_id is stale or missing (Stripe has ${sub.id})`,
            tenant.plan,
            sub.status
          );
          issues++;
        }
      }
    } catch (e) {
      console.error(`[Warehub Reconcile] Failed for tenant ${tenant.id}:`, e.message);
    }
  }

  console.log(`[Warehub Reconcile] Complete — ${issues} issue(s) flagged`);
}

async function flagIssue(env, tenantId, issue, d1Plan, stripeStatus) {
  // Avoid re-flagging the exact same unresolved issue every night.
  const existing = await env.DB.prepare(
    `SELECT id FROM reconciliation_issues
     WHERE tenant_id = ? AND issue = ? AND resolved = 0`
  )
    .bind(tenantId, issue)
    .first();
  if (existing) return;

  await env.DB.prepare(
    `INSERT INTO reconciliation_issues (id, tenant_id, issue, d1_plan, stripe_status)
     VALUES (?, ?, ?, ?, ?)`
  )
    .bind(uuid(), tenantId, issue, d1Plan, stripeStatus)
    .run();
}

async function analyzeTenant(tenant, env) {
  const thirtyDaysAgo = Math.floor(Date.now() / 1000) - 30 * 86400;
  const sevenDaysAgo = Math.floor(Date.now() / 1000) - 7 * 86400;
  const oneDayAgo = Math.floor(Date.now() / 1000) - 86400;

  const { results: eventCounts } = await env.DB.prepare(
    `SELECT event_type, COUNT(*) as cnt,
            MAX(occurred_at) as last_seen
     FROM events
     WHERE tenant_id = ? AND occurred_at > ?
     GROUP BY event_type`
  )
    .bind(tenant.id, thirtyDaysAgo)
    .all();

  if (!eventCounts.length) return;

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

  const { results: yesterdayEvents } = await env.DB.prepare(
    `SELECT event_type, COUNT(*) as cnt
     FROM events
     WHERE tenant_id = ? AND occurred_at > ?
     GROUP BY event_type`
  )
    .bind(tenant.id, oneDayAgo)
    .all();

  const { results: recentSamples } = await env.DB.prepare(
    `SELECT event_type, payload, occurred_at
     FROM events
     WHERE tenant_id = ? AND occurred_at > ?
     ORDER BY occurred_at DESC
     LIMIT 40`
  )
    .bind(tenant.id, sevenDaysAgo)
    .all();

  const context = {
    tenantName: tenant.name,
    analysisDate: new Date().toISOString().split("T")[0],
    last30Days: eventCounts,
    last7DaysByDay: dailyActivity,
    yesterday: yesterdayEvents,
    recentSamples: recentSamples.slice(0, 20),
  };

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

  if (!aiInsights.length) {
    aiInsights = generateRuleBasedInsights(context);
  }

  await env.DB.prepare(
    `DELETE FROM insights
     WHERE tenant_id = ? AND created_at > unixepoch() - 86400`
  )
    .bind(tenant.id)
    .run();

  const expiresAt = Math.floor(Date.now() / 1000) + 7 * 86400;

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

function generateRuleBasedInsights(ctx) {
  const insights = [];
  const counts = {};
  for (const e of ctx.last30Days) counts[e.event_type] = e.cnt;

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
