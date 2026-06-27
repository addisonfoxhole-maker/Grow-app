/* ============================================================================
   Addison Garden — shared-grow sync API (Cloudflare Worker)
   ----------------------------------------------------------------------------
   One shared grow lives in a single D1 row. Anyone who logs in with the shared
   passcode reads/writes the same grow. Auth is a passcode -> short HMAC-signed
   token (sent as `Authorization: Bearer <token>`). Last-write-wins on PUT.

   Bindings (wrangler.toml):   DB  -> your D1 database
   Secrets  (wrangler secret): GROW_PASSCODE  (the shared passcode)
                               AUTH_SECRET    (a long random string)

   Endpoints:
     POST /api/login   { passcode }          -> { token }
     GET  /api/state                          -> { rev, data }
     PUT  /api/state   { data, baseRev }      -> { rev, updated_at }
     GET  /api/health                         -> { ok: true }

   NOTE: photos are NOT synced yet (they stay on each device). Adding photo sync
   means an R2 bucket + upload/serve endpoints — a clean follow-up.
   ========================================================================== */

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,PUT,POST,OPTIONS",
  "Access-Control-Allow-Headers": "Authorization,Content-Type",
  "Access-Control-Max-Age": "86400",
};

function json(body, status = 200, extra = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...CORS, ...extra },
  });
}

const enc = new TextEncoder();

function b64url(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
}

async function hmac(secret, msg) {
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(msg));
  return b64url(new Uint8Array(sig));
}

async function makeToken(env) {
  const payload = btoa(JSON.stringify({ iat: Date.now() })).replace(/=+$/, "");
  const sig = await hmac(env.AUTH_SECRET, payload);
  return payload + "." + sig;
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

async function verify(env, token) {
  if (!token) return false;
  const i = token.lastIndexOf(".");
  if (i < 0) return false;
  const payload = token.slice(0, i);
  const sig = token.slice(i + 1);
  const expect = await hmac(env.AUTH_SECRET, payload);
  return timingSafeEqual(sig, expect);
}

async function authed(req, env) {
  const h = req.headers.get("Authorization") || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : "";
  return verify(env, token);
}

export default {
  async fetch(req, env) {
    if (req.method === "OPTIONS") return new Response(null, { headers: CORS });

    if (!env.AUTH_SECRET || !env.GROW_PASSCODE) {
      return json({ error: "Server not configured: set GROW_PASSCODE and AUTH_SECRET secrets." }, 500);
    }

    const url = new URL(req.url);
    const path = url.pathname.replace(/\/+$/, "");

    try {
      if (path === "/api/health") return json({ ok: true });

      if (path === "/api/login" && req.method === "POST") {
        const body = await req.json().catch(() => ({}));
        const passcode = (body && body.passcode) || "";
        if (!passcode || !timingSafeEqual(String(passcode), String(env.GROW_PASSCODE))) {
          return json({ error: "Wrong passcode" }, 401);
        }
        return json({ token: await makeToken(env) });
      }

      if (path === "/api/state" && req.method === "GET") {
        if (!(await authed(req, env))) return json({ error: "Unauthorized" }, 401);
        const row = await env.DB.prepare("SELECT rev, data FROM grow_state WHERE id = 1").first();
        return json({
          rev: row ? row.rev : 0,
          data: row && row.data ? JSON.parse(row.data) : {},
        });
      }

      if (path === "/api/state" && req.method === "PUT") {
        if (!(await authed(req, env))) return json({ error: "Unauthorized" }, 401);
        const body = await req.json().catch(() => ({}));
        const data = JSON.stringify((body && body.data) || {});
        const now = new Date().toISOString();
        await env.DB
          .prepare("UPDATE grow_state SET rev = rev + 1, data = ?, updated_at = ? WHERE id = 1")
          .bind(data, now)
          .run();
        const row = await env.DB.prepare("SELECT rev FROM grow_state WHERE id = 1").first();
        return json({ rev: row ? row.rev : 0, updated_at: now });
      }

      return json({ error: "Not found" }, 404);
    } catch (e) {
      return json({ error: String((e && e.message) || e) }, 500);
    }
  },
};
