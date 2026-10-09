// Bagh Cloudflare Worker
// Password-based authentication + KV database compatibility.
// Required KV binding: BAGH_KV
// Required secret: DB_KEY
// Never log passwords, tokens, or private user data.

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
    headers: {
      ...cors,
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });

const segments = (p) =>
  p.replace(/\.json$/, "").split("/").filter(Boolean);

const valid = (s) =>
  s.length > 0 &&
  TOP.has(s[0]) &&
  !s.some((x) => BAD.has(x));

const keyFor = (s) => "db:" + s.join("/");

const enc = new TextEncoder();

function logError(label, error) {
  // Do not log request bodies, passwords, session tokens, or DB_KEY.
  console.error(
    label,
    error instanceof Error
      ? error.stack || error.message
      : String(error)
  );
}

async function readBody(req) {
  const t = await req.text();

  if (t.length > 1_000_000) {
    throw new Error("Request body too large");
  }

  return t ? JSON.parse(t) : null;
}

function clean(v) {
  if (Array.isArray(v)) {
    return v.map(clean);
  }

  if (v && typeof v === "object") {
    const o = {};

    for (const [k, val] of Object.entries(v)) {
      if (!BAD.has(k) && val !== undefined && val !== null) {
        o[k] = clean(val);
      }
    }

    return Object.keys(o).length ? o : null;
  }

  return v;
}

function applyServerValues(v, existing) {
  if (v && typeof v === "object" && !Array.isArray(v)) {
    if (Object.prototype.hasOwnProperty.call(v, ".sv")) {
      if (v[".sv"] === "timestamp") {
        return Date.now();
      }

      if (v[".sv"] && v[".sv"].increment != null) {
        return (
          (typeof existing === "number" ? existing : 0) +
          Number(v[".sv"].increment)
        );
      }

      return null;
    }

    const out = {};

    for (const [k, val] of Object.entries(v)) {
      out[k] = applyServerValues(
        val,
        existing && typeof existing === "object"
          ? existing[k]
          : undefined
      );
    }

    return out;
  }

  return v;
}

async function getValue(env, segs) {
  if (!segs.length) {
    const out = {};

    for (const top of TOP) {
      const v = await env.BAGH_KV.get(keyFor([top]), "json");

      if (v !== null) {
        out[top] = v;
      }
    }

    return out;
  }

  const exact = await env.BAGH_KV.get(keyFor(segs), "json");
  const prefix = keyFor(segs) + "/";
  const listed = await env.BAGH_KV.list({ prefix });

  if (exact !== null) {
    return exact;
  }

  if (!listed.keys.length) {
    return null;
  }

  const out = {};

  for (const item of listed.keys) {
    const tail = item.name.slice(prefix.length);

    if (!tail || tail.includes("/")) {
      continue;
    }

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
      const batch = await env.BAGH_KV.list({
        prefix,
        ...(cursor ? { cursor } : {}),
      });

      await Promise.all(
        batch.keys.map((x) => env.BAGH_KV.delete(x.name))
      );

      cursor = batch.list_complete ? undefined : batch.cursor;
    } while (cursor);

    return;
  }

  await env.BAGH_KV.put(k, JSON.stringify(value));
}

// Merge database users with password-authenticated users.
// This is a read-only compatibility view; it does not delete or
// rewrite the original auth:user records.
async function getCombinedUsers(env) {
  const existing = await getValue(env, ["users"]);
  const out =
    existing && typeof existing === "object" && !Array.isArray(existing)
      ? { ...existing }
      : {};

  let cursor;

  do {
    const batch = await env.BAGH_KV.list({
      prefix: "auth:user:",
      ...(cursor ? { cursor } : {}),
    });

    for (const item of batch.keys) {
      try {
        const user = await env.BAGH_KV.get(item.name, "json");

        if (!user || typeof user !== "object") {
          continue;
        }

        // Use the phone digits as the key to match existing
        // phone-keyed user records when possible.
        const phoneKey = String(user.phone || "").replace(/\D/g, "");
        const userKey = phoneKey || user.uid || item.name.slice("auth:user:".length);

        // Never expose password hashes, salts, or internal auth fields.
        const {
          password,
          passwordHash,
          passwordSalt,
          token,
          ...publicUser
        } = user;

        // Keep any existing database entry for the same key.
        out[userKey] = {
          ...publicUser,
          ...(out[userKey] && typeof out[userKey] === "object"
            ? out[userKey]
            : {}),
        };
      } catch (error) {
        logError("BAGH_AUTH_USER_READ_ERROR", error);
      }
    }

    cursor = batch.list_complete ? undefined : batch.cursor;
  } while (cursor);

  return out;
}

function b64url(bytes) {
  let s = "";

  for (const b of bytes) {
    s += String.fromCharCode(b);
  }

  return btoa(s)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function fromB64url(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");

  while (s.length % 4) {
    s += "=";
  }

  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}

async function hashPassword(password, saltText) {
  const salt = saltText
    ? fromB64url(saltText)
    : crypto.getRandomValues(new Uint8Array(16));

  const material = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt,
      iterations: 210000,
    },
    material,
    256
  );

  return {
    salt: b64url(salt),
    hash: b64url(new Uint8Array(bits)),
  };
}

async function passwordMatches(password, salt, expected) {
  const result = await hashPassword(password, salt);
  const a = enc.encode(result.hash);
  const b = enc.encode(expected);

  if (a.length !== b.length) {
    return false;
  }

  let diff = 0;

  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }

  return diff === 0;
}

function normalizePhone(input) {
  const p = String(input || "").replace(/[\s()-]/g, "");

  if (!/^\+?[0-9]{8,15}$/.test(p)) {
    return null;
  }

  return p.startsWith("+") ? p : "+" + p;
}

function phoneId(phone) {
  return "auth:phone:" + phone.replace(/[^0-9]/g, "");
}

async function readJson(req) {
  const b = await readBody(req);

  return b && typeof b === "object" && !Array.isArray(b)
    ? b
    : {};
}

async function makeSession(env, user) {
  const token = b64url(
    crypto.getRandomValues(new Uint8Array(32))
  );

  const session = {
    uid: user.uid,
    createdAt: Date.now(),
    expiresAt: Date.now() + 30 * 24 * 60 * 60 * 1000,
  };

  await env.BAGH_KV.put(
    "auth:session:" + token,
    JSON.stringify(session),
    { expirationTtl: 60 * 60 * 24 * 30 }
  );

  return token;
}

async function currentUser(req, env) {
  const h = req.headers.get("Authorization") || "";
  const m = h.match(/^Bearer\s+([A-Za-z0-9_-]+)$/);

  if (!m) {
    return null;
  }

  const raw = await env.BAGH_KV.get(
    "auth:session:" + m[1],
    "json"
  );

  if (!raw || raw.expiresAt < Date.now()) {
    return null;
  }

  const user = await env.BAGH_KV.get(
    "auth:user:" + raw.uid,
    "json"
  );

  return user ? { ...user, token: m[1] } : null;
}

async function authRoute(req, env, path) {
  if (path === "/auth/register" && req.method === "POST") {
    const b = await readJson(req);
    const phone = normalizePhone(b.phone);
    const password = String(b.password || "");
    const displayName = String(b.displayName || "")
      .trim()
      .slice(0, 60);

    if (!phone) {
      return json(
        { ok: false, err: "شماره موبایل معتبر نیست." },
        400
      );
    }

    if (password.length < 10 || password.length > 128) {
      return json(
        {
          ok: false,
          err: "رمز عبور باید حداقل ۱۰ نویسه داشته باشد.",
        },
        400
      );
    }

    const idx = phoneId(phone);

    if (await env.BAGH_KV.get(idx)) {
      return json(
        {
          ok: false,
          err: "این شماره قبلاً ثبت‌نام کرده است؛ وارد شوید.",
        },
        409
      );
    }

    const uid = crypto.randomUUID();
    const ph = await hashPassword(password);

    const user = {
      uid,
      phone,
      displayName: displayName || "کاربر باغ",
      passwordSalt: ph.salt,
      passwordHash: ph.hash,
      createdAt: Date.now(),
    };

    await env.BAGH_KV.put(
      "auth:user:" + uid,
      JSON.stringify(user)
    );

    await env.BAGH_KV.put(idx, uid);

    const token = await makeSession(env, user);

    return json(
      {
        ok: true,
        token,
        user: {
          uid,
          phone,
          displayName: user.displayName,
        },
      },
      201
    );
  }

  if (path === "/auth/login" && req.method === "POST") {
    const b = await readJson(req);
    const phone = normalizePhone(b.phone);
    const password = String(b.password || "");

    if (!phone || !password) {
      return json(
        {
          ok: false,
          err: "شماره موبایل و رمز عبور را وارد کنید.",
        },
        400
      );
    }

    const uid = await env.BAGH_KV.get(phoneId(phone));

    if (!uid) {
      return json(
        { ok: false, err: "شماره یا رمز عبور اشتباه است." },
        401
      );
    }

    const user = await env.BAGH_KV.get(
      "auth:user:" + uid,
      "json"
    );

    if (
      !user ||
      !await passwordMatches(
        password,
        user.passwordSalt,
        user.passwordHash
      )
    ) {
      return json(
        { ok: false, err: "شماره یا رمز عبور اشتباه است." },
        401
      );
    }

    const token = await makeSession(env, user);

    return json({
      ok: true,
      token,
      user: {
        uid,
        phone,
        displayName: user.displayName,
      },
    });
  }

  if (path === "/auth/profile" && req.method === "GET") {
    const user = await currentUser(req, env);

    if (!user) {
      return json(
        {
          ok: false,
          err: "نشست معتبر نیست؛ دوباره وارد شوید.",
        },
        401
      );
    }

    return json({
      ok: true,
      user: {
        uid: user.uid,
        phone: user.phone,
        displayName: user.displayName,
      },
    });
  }

  if (path === "/auth/logout" && req.method === "POST") {
    const h = req.headers.get("Authorization") || "";
    const m = h.match(/^Bearer\s+([A-Za-z0-9_-]+)$/);

    if (m) {
      await env.BAGH_KV.delete("auth:session:" + m[1]);
    }

    return json({ ok: true });
  }

  if (path === "/auth/recovery" && req.method === "POST") {
    const b = await readJson(req);
    const phone = normalizePhone(b.phone);

    if (!phone) {
      return json(
        { ok: false, err: "شماره موبایل معتبر نیست." },
        400
      );
    }

    const id = crypto.randomUUID();

    const ticket = {
      id,
      phone,
      message: String(b.message || "")
        .trim()
        .slice(0, 1000),
      createdAt: Date.now(),
      status: "pending",
      support: "@mrmmdt",
    };

    await env.BAGH_KV.put(
      "auth:recovery:" + id,
      JSON.stringify(ticket),
      { expirationTtl: 60 * 60 * 24 * 90 }
    );

    return json(
      {
        ok: true,
        message: "درخواست ثبت شد؛ برای پیگیری به پشتیبانی پیام بدهید.",
        support: "@mrmmdt",
        ticketId: id,
      },
      201
    );
  }

  if (path === "/auth/send" || path === "/auth/verify") {
    return json(
      {
        ok: false,
        err: "ورود با پیامک هنوز فعال نیست. از ورود با رمز عبور استفاده کنید.",
      },
      501
    );
  }

  return json(
    { ok: false, err: "مسیر احراز هویت پیدا نشد." },
    404
  );
}

export default {
  async fetch(req, env) {
    if (req.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: cors,
      });
    }

    if (!env.BAGH_KV) {
      return json(
        {
          ok: false,
          error: "BAGH_KV binding is not configured",
        },
        500
      );
    }

    const url = new URL(req.url);
    let path;

    try {
      path = decodeURIComponent(url.pathname);
    } catch (error) {
      logError("BAGH_PATH_ERROR", error);
      return json({}, 400);
    }

    if (path === "/health") {
      return json({
        ok: true,
        service: "bagh-worker",
      });
    }

    if (path.startsWith("/auth/")) {
      try {
        return await authRoute(req, env, path);
      } catch (error) {
        logError("BAGH_AUTH_ROUTE_ERROR", error);

        return json(
          {
            ok: false,
            err: "درخواست نامعتبر است.",
          },
          400
        );
      }
    }

    if (!path.startsWith("/db")) {
      return json({ error: "not found" }, 404);
    }

    let p = path.slice(3);

    if (env.DB_KEY) {
      if (
        p !== "/" + env.DB_KEY &&
        !p.startsWith("/" + env.DB_KEY + "/")
      ) {
        return json({ error: "forbidden" }, 403);
      }

      p = p.slice(env.DB_KEY.length + 1);
    } else {
      return json(
        { error: "DB_KEY secret is required" },
        503
      );
    }

    const segs = segments(p);

    if (!valid(segs)) {
      return json({ error: "forbidden" }, 403);
    }

    try {
      if (req.method === "GET") {
        // Return the combined user listing for the admin/client
        // compatibility endpoint without exposing password data.
        if (
          segs.length === 1 &&
          segs[0] === "users"
        ) {
          const value = await getCombinedUsers(env);
          return json(value);
        }

        // Preserve the existing restriction on top-level reads.
        if (
          segs.length === 1 &&
          segs[0] !== "users"
        ) {
          return json({ error: "forbidden" }, 403);
        }

        const value = await getValue(env, segs);
        return json(value);
      }

      if (req.method === "DELETE") {
        await putValue(env, segs, null);
        return json(null);
      }

      const body = clean(
        applyServerValues(
          await readBody(req),
          await getValue(env, segs)
        )
      );

      if (req.method === "PUT") {
        await putValue(env, segs, body);
        return json(body);
      }

      if (req.method === "PATCH") {
        if (
          !body ||
          typeof body !== "object" ||
          Array.isArray(body)
        ) {
          return json({}, 400);
        }

        const old = await getValue(env, segs);

        const merged = {
          ...(old &&
          typeof old === "object" &&
          !Array.isArray(old)
            ? old
            : {}),
          ...body,
        };

        await putValue(env, segs, merged);
        return json(body);
      }

      if (req.method === "POST") {
        const id =
          Date.now().toString(36) +
          crypto.randomUUID().replace(/-/g, "").slice(0, 10);

        await putValue(env, [...segs, id], body);

        return json({ name: id });
      }

      return json({}, 405);
    } catch (error) {
      logError("BAGH_DB_ROUTE_ERROR", error);

      return json(
        { error: "bad request" },
        400
      );
    }
  },
};
