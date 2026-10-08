// Bagh Cloudflare Worker starter.
// Requires a Cloudflare KV namespace binding named BAGH_KV.
// This is a migration starter, not a drop-in replacement for every Firebase/SSE behavior.
const TOP = new Set(["users", "userchats", "chats", "calls", "ans", "ice"]);
const BAD = new Set(["__proto__", "constructor", "prototype"]);
const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,PUT,POST,PATCH,DELETE,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};
const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { ...cors, "Content-Type": "application/json; charset=utf-8" },
  });
const segments = (p) => p.replace(/\.json$/, "").split("/").filter(Boolean);
const valid = (s) => s.length && TOP.has(s[0]) && !s.some((x) => BAD.has(x));
const keyFor = (s) => "db:" + s.join("/");
async function readBody(req) {
  const t = await req.text();
  if (t.length > 1_000_000) throw new Error("body too large");
  return t ? JSON.parse(t) : null;
}
function clean(v) {
  if (Array.isArray(v)) return v.map(clean);
  if (v && typeof v === "object") {
    const o = {};
    for (const [k, val] of Object.entries(v)) {
      if (!BAD.has(k) && val !== undefined && val !== null) o[k] = clean(val);
    }
    return Object.keys(o).length ? o : null;
  }
  return v;
}
function applyServerValues(v, existing) {
  if (v && typeof v === "object" && !Array.isArray(v)) {
    if (Object.prototype.hasOwnProperty.call(v, ".sv")) {
      if (v[".sv"] === "timestamp") return Date.now();
      if (v[".sv"] && v[".sv"].increment != null)
        return (typeof existing === "number" ? existing : 0) + Number(v[".sv"].increment);
      return null;
    }
    const out = {};
    for (const [k, val] of Object.entries(v))
      out[k] = applyServerValues(val, existing && typeof existing === "object" ? existing[k] : undefined);
    return out;
  }
  return v;
}
async function getValue(env, segs) {
  if (!segs.length) {
    const out = {};
    for (const top of TOP) {
      const v = await env.BAGH_KV.get(keyFor([top]), "json");
      if (v !== null) out[top] = v;
    }
    return out;
  }
  // KV is key/value, so read exact node and descendants to rebuild a subtree.
  const exact = await env.BAGH_KV.get(keyFor(segs), "json");
  const prefix = keyFor(segs) + "/";
  const listed = await env.BAGH_KV.list({ prefix });
  if (exact !== null) return exact;
  if (!listed.keys.length) return null;
  const out = {};
  for (const item of listed.keys) {
    const tail = item.name.slice(prefix.length);
    if (!tail || tail.includes("/")) continue;
    out[tail] = await env.BAGH_KV.get(item.name, "json");
  }
  return Object.keys(out).length ? out : null;
}
async function putValue(env, segs, value) {
  const k = keyFor(segs);
  if (value === null) {
    await env.BAGH_KV.delete(k);
    const prefix = k + "/";
    let cursor;
    do {
      const batch = await env.BAGH_KV.list({ prefix, cursor });
      await Promise.all(batch.keys.map(x => env.BAGH_KV.delete(x.name)));
      cursor = batch.list_complete ? undefined : batch.cursor;
    } while (cursor);
    return;
  }
  await env.BAGH_KV.put(k, JSON.stringify(value));
}
export default {
  async fetch(req, env) {
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
    if (!env.BAGH_KV) return json({ ok: false, error: "BAGH_KV binding is not configured" }, 500);
    const url = new URL(req.url);
    let path;
    try { path = decodeURIComponent(url.pathname); } catch { return json({}, 400); }

    if (path === "/health") return json({ ok: true, service: "bagh-worker" });

    // Do not expose development OTP codes publicly. Configure KAVENEGAR_KEY and
    // KAVENEGAR_TEMPLATE as Worker secrets for real SMS; no secret means SMS disabled.
    if (path.startsWith("/auth/")) {
      if (path === "/auth/send" || path === "/auth/verify") {
        return json({ ok: false, err: "ورود پیامکی هنوز تنظیم نشده است؛ سرویس پیامک باید پیکربندی شود." }, 503);
      }
      if (path === "/auth/profile") return json({ ok: false, err: "احراز هویت کامل هنوز پیاده‌سازی نشده است." }, 501);
      return json({ ok: false }, 404);
    }

    if (!path.startsWith("/db")) return json({ error: "not found" }, 404);
    let p = path.slice(3);
    // Optional shared key: set DB_KEY as a Worker secret and use /db/<key>/...
    if (env.DB_KEY) {
      if (p !== "/" + env.DB_KEY && !p.startsWith("/" + env.DB_KEY + "/"))
        return json({ error: "forbidden" }, 403);
      p = p.slice(env.DB_KEY.length + 1);
    }
    const segs = segments(p);
    if (!valid(segs)) return json({ error: "forbidden" }, 403);

    try {
      if (req.method === "GET") {
        if (segs.length === 1 && segs[0] !== "users") return json({ error: "forbidden" }, 403);
        let value = await getValue(env, segs);
        if (segs.length === 1 && segs[0] === "users" && value && typeof value === "object") {
          const pub = {};
          for (const [k, u] of Object.entries(value)) {
            if (u && typeof u === "object") {
              const { phone, bio, ...rest } = u;
              pub[k] = rest;
            } else pub[k] = u;
          }
          value = pub;
        }
        return json(value);
      }
      if (req.method === "DELETE") {
        await putValue(env, segs, null);
        return json(null);
      }
      const body = clean(applyServerValues(await readBody(req), await getValue(env, segs)));
      if (req.method === "PUT") {
        await putValue(env, segs, body);
        return json(body);
      }
      if (req.method === "PATCH") {
        if (!body || typeof body !== "object" || Array.isArray(body)) return json({}, 400);
        const old = await getValue(env, segs);
        const merged = { ...(old && typeof old === "object" && !Array.isArray(old) ? old : {}), ...body };
        await putValue(env, segs, merged);
        return json(body);
      }
      if (req.method === "POST") {
        const id = Date.now().toString(36) + crypto.randomUUID().replace(/-/g, "").slice(0, 10);
        await putValue(env, [...segs, id], body);
        return json({ name: id });
      }
      return json({}, 405);
    } catch {
      return json({ error: "bad request" }, 400);
    }
  },
};
