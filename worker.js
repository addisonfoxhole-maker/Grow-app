/* Addison Garden — sync Worker (grow-app)
   Backs the shared grow for the v0.18 app. Matches the client contract exactly:
     POST /api/register {email,password,familyCode} -> {token,email}
     POST /api/login    {email,password}            -> {token,email}
     POST /api/family   {code}                       -> {token}
     GET  /api/state    (Bearer)                     -> {rev, data}
     PUT  /api/state    (Bearer) {data, baseRev}     -> {rev}
     PUT  /api/photo/:id (Bearer, text body=dataURL) -> {ok:true}
     GET  /api/photo/:id (Bearer)                    -> text dataURL
     DELETE /api/photo/:id (Bearer)                  -> {ok:true}
     GET  /api/health                                -> {ok:true}
   Bindings (wrangler.toml): DB (D1 "growapp"), PHOTOS (R2 "growapp-photos")
   Secrets: FAMILY_CODE, AUTH_SECRET   (set with `wrangler secret put ...`)
   Auth model: one shared grow. A signed bearer token (HMAC over {sub,iat}) grants access;
   the same token — from an account login OR the family code — reaches the same grow. */

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,PUT,POST,DELETE,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type,Authorization",
  "Access-Control-Max-Age": "86400",
};
const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json", ...CORS } });
const err = (msg, status = 400) => json({ error: msg }, status);
const text = (body, status = 200) =>
  new Response(body, { status, headers: { "Content-Type": "text/plain", ...CORS } });

/* ---- small crypto helpers (Web Crypto, available in Workers) ---- */
const enc = new TextEncoder();
const dec = new TextDecoder();
const toHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
function b64url(bytes) {
  let s = btoa(String.fromCharCode(...bytes));
  return s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlToBytes(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(s);
  const b = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) b[i] = bin.charCodeAt(i);
  return b;
}

async function pbkdf2(password, saltBytes) {
  const km = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: saltBytes, iterations: 100000, hash: "SHA-256" },
    km,
    256
  );
  return toHex(new Uint8Array(bits));
}
async function hmac(msg, secret) {
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(msg)));
}
async function signToken(payload, secret) {
  const body = b64url(enc.encode(JSON.stringify(payload)));
  const sig = b64url(await hmac(body, secret));
  return body + "." + sig;
}
async function verifyToken(token, secret) {
  if (!token || token.indexOf(".") < 0) return null;
  const [body, sig] = token.split(".");
  const expect = b64url(await hmac(body, secret));
  if (sig !== expect) return null;
  try { return JSON.parse(dec.decode(b64urlToBytes(body))); } catch (_) { return null; }
}
const bearer = (req) => {
  const h = req.headers.get("Authorization") || "";
  return h.startsWith("Bearer ") ? h.slice(7) : "";
};
const normEmail = (e) => String(e || "").trim().toLowerCase();

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    if (method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
    if (path === "/api/health") return json({ ok: true, ts: new Date().toISOString() });

    // Config guardrails — clear errors if the operator forgot a secret/binding.
    if (!env.AUTH_SECRET) return err("Server not configured: AUTH_SECRET secret is missing.", 500);

    try {
      /* ---------- AUTH ---------- */
      if (path === "/api/register" && method === "POST") {
        if (!env.DB) return err("Server not configured: DB binding is missing.", 500);
        if (!env.FAMILY_CODE) return err("Server not configured: FAMILY_CODE secret is missing.", 500);
        const b = await request.json().catch(() => ({}));
        const email = normEmail(b.email);
        const password = String(b.password || "");
        if (!email || !password) return err("Email and password are required.", 400);
        if (String(b.familyCode || "") !== env.FAMILY_CODE) return err("That family code isn’t right.", 403);
        const existing = await env.DB.prepare("SELECT email FROM users WHERE email=?").bind(email).first();
        if (existing) return err("An account with that email already exists.", 409);
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const hash = await pbkdf2(password, salt);
        await env.DB.prepare("INSERT INTO users (email, salt, hash, created_at) VALUES (?,?,?,?)")
          .bind(email, toHex(salt), hash, new Date().toISOString()).run();
        const token = await signToken({ sub: email, iat: Date.now() }, env.AUTH_SECRET);
        return json({ token, email });
      }

      if (path === "/api/login" && method === "POST") {
        if (!env.DB) return err("Server not configured: DB binding is missing.", 500);
        const b = await request.json().catch(() => ({}));
        const email = normEmail(b.email);
        const password = String(b.password || "");
        if (!email || !password) return err("Email and password are required.", 400);
        const row = await env.DB.prepare("SELECT salt, hash FROM users WHERE email=?").bind(email).first();
        if (!row) return err("Email or password is incorrect.", 401);
        const saltBytes = new Uint8Array((row.salt.match(/.{1,2}/g) || []).map((h) => parseInt(h, 16)));
        const hash = await pbkdf2(password, saltBytes);
        if (hash !== row.hash) return err("Email or password is incorrect.", 401);
        const token = await signToken({ sub: email, iat: Date.now() }, env.AUTH_SECRET);
        return json({ token, email });
      }

      if (path === "/api/family" && method === "POST") {
        if (!env.FAMILY_CODE) return err("Server not configured: FAMILY_CODE secret is missing.", 500);
        const b = await request.json().catch(() => ({}));
        if (String(b.code || "") !== env.FAMILY_CODE) return err("That family code isn’t right.", 403);
        const token = await signToken({ sub: "family", iat: Date.now() }, env.AUTH_SECRET);
        return json({ token });
      }

      /* ---------- everything below needs a valid token ---------- */
      const claims = await verifyToken(bearer(request), env.AUTH_SECRET);

      /* ---------- STATE (D1) ---------- */
      if (path === "/api/state") {
        if (!claims) return err("unauthorized", 401);
        if (!env.DB) return err("Server not configured: DB binding is missing.", 500);

        if (method === "GET") {
          const row = await env.DB.prepare("SELECT rev, data FROM grow_state WHERE id=1").first();
          const rev = row ? row.rev : 0;
          let data = {};
          if (row && row.data) { try { data = JSON.parse(row.data); } catch (_) { data = {}; } }
          return json({ rev, data });
        }
        if (method === "PUT") {
          const b = await request.json().catch(() => ({}));
          if (!b || typeof b.data !== "object" || b.data === null) return err("Missing state data.", 400);
          const cur = await env.DB.prepare("SELECT rev FROM grow_state WHERE id=1").first();
          const newRev = (cur ? cur.rev : 0) + 1; // last-write-wins
          await env.DB.prepare(
            "INSERT INTO grow_state (id, rev, data, updated_at) VALUES (1, ?, ?, ?) " +
            "ON CONFLICT(id) DO UPDATE SET rev=excluded.rev, data=excluded.data, updated_at=excluded.updated_at"
          ).bind(newRev, JSON.stringify(b.data), new Date().toISOString()).run();
          return json({ rev: newRev });
        }
        return err("Method not allowed", 405);
      }

      /* ---------- PHOTOS (R2) ---------- */
      if (path.startsWith("/api/photo/")) {
        if (!claims) return err("unauthorized", 401);
        if (!env.PHOTOS) return err("Photo storage isn’t configured (R2 binding PHOTOS missing).", 503);
        const id = decodeURIComponent(path.slice("/api/photo/".length));
        if (!id) return err("Missing photo id.", 400);

        if (method === "PUT") {
          const body = await request.text();
          await env.PHOTOS.put(id, body);
          return json({ ok: true });
        }
        if (method === "GET") {
          const obj = await env.PHOTOS.get(id);
          if (!obj) return err("Not found", 404);
          return text(await obj.text());
        }
        if (method === "DELETE") {
          await env.PHOTOS.delete(id);
          return json({ ok: true });
        }
        return err("Method not allowed", 405);
      }

      return err("Not found", 404);
    } catch (e) {
      return err("Server error: " + (e && e.message ? e.message : String(e)), 500);
    }
  },
};
