// Bagh Cloudflare Worker
// Password authentication + indexed KV database.
// Required KV binding: BAGH_KV
// Required secret: DB_KEY
// No KV.list() usage.

const TOP = new Set([
  "users",
  "userchats",
  "chats",
  "calls",
  "ans",
  "ice",
]);

const BAD = new Set([
  "__proto__",
  "constructor",
  "prototype",
]);

const PRIVATE_FIELDS = new Set([
  "password",
  "passwordHash",
  "passwordSalt",
  "token",
  "accessToken",
  "refreshToken",
  "sessionToken",
]);

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods":
    "GET,PUT,POST,PATCH,DELETE,OPTIONS",
  "Access-Control-Allow-Headers":
    "Content-Type, Authorization",
};

const enc = new TextEncoder();

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      ...cors,
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });

const keyFor = (segs) => "db:" + segs.join("/");
const indexKey = (segs) => "dbi:" + segs.join("/");

const segments = (path) =>
  path.replace(/\.json$/, "").split("/").filter(Boolean);

const valid = (segs) =>
  segs.length > 0 &&
  TOP.has(segs[0]) &&
  !segs.some((segment) =>
    BAD.has(segment) ||
    segment.includes("/") ||
    segment.includes("\\")
  );

function logError(label, error) {
  console.error(
    label,
    error instanceof Error
      ? error.stack || error.message
      : String(error)
  );
}

async function readBody(req) {
  const text = await req.text();

  if (text.length > 1_000_000) {
    throw new Error("Request body too large");
  }

  if (!text) return null;

  try {
    return JSON.parse(text);
  } catch {
    throw new Error("Invalid JSON body");
  }
}

async function readJson(req) {
  const value = await readBody(req);

  return value &&
    typeof value === "object" &&
    !Array.isArray(value)
    ? value
    : {};
}

function clean(value) {
  if (Array.isArray(value)) {
    return value.map(clean);
  }

  if (value && typeof value === "object") {
    const out = {};

    for (const [key, item] of Object.entries(value)) {
      if (BAD.has(key) || item === undefined) {
        continue;
      }

      out[key] = item === null ? null : clean(item);
    }

    return out;
  }

  return value;
}

function stripPrivate(user) {
  const out = {};

  for (const [key, value] of Object.entries(user || {})) {
    if (
      !BAD.has(key) &&
      !PRIVATE_FIELDS.has(key) &&
      value !== undefined
    ) {
      out[key] = value;
    }
  }

  return out;
}

function applyServerValues(value, existing) {
  if (
    value &&
    typeof value === "object" &&
    !Array.isArray(value)
  ) {
    if (Object.prototype.hasOwnProperty.call(value, ".sv")) {
      if (value[".sv"] === "timestamp") {
        return Date.now();
      }

      if (
        value[".sv"] &&
        value[".sv"].increment != null
      ) {
        const increment = Number(value[".sv"].increment);

        if (!Number.isFinite(increment)) {
          return existing ?? 0;
        }

        return (
          (typeof existing === "number" ? existing : 0) +
          increment
        );
      }

      return null;
    }

    const out = {};

    for (const [key, item] of Object.entries(value)) {
      if (BAD.has(key)) continue;

      out[key] = applyServerValues(
        item,
        existing && typeof existing === "object"
          ? existing[key]
          : undefined
      );
    }

    return out;
  }

  return value;
}

// ---------- KV helpers ----------

async function readKV(env, key) {
  const raw = await env.BAGH_KV.get(key);

  if (raw === null) return null;

  try {
    return JSON.parse(raw);
  } catch (error) {
    logError("BAGH_INVALID_JSON:" + key, error);
    return null;
  }
}

async function updateChildIndex(env, parent, child, add) {
  if (
    typeof child !== "string" ||
    !child ||
    BAD.has(child) ||
    child.includes("/") ||
    child.includes("\\")
  ) {
    return;
  }

  const key = indexKey(parent);
  const stored = await readKV(env, key);

  const children = Array.isArray(stored)
    ? stored.filter(
        (item) =>
          typeof item === "string" &&
          item &&
          !BAD.has(item) &&
          !item.includes("/") &&
          !item.includes("\\")
      )
    : [];

  const set = new Set(children);

  if (add) {
    set.add(child);
  } else {
    set.delete(child);
  }

  await env.BAGH_KV.put(
    key,
    JSON.stringify(Array.from(set))
  );
}

async function getValue(env, segs) {
  if (!segs.length) {
    const out = {};

    for (const top of TOP) {
      const value = await readKV(env, keyFor([top]));

      if (value !== null) out[top] = value;
    }

    return out;
  }

  const exact = await readKV(env, keyFor(segs));

  if (exact !== null) return exact;

  const children = await readKV(env, indexKey(segs));

  if (!Array.isArray(children) || !children.length) {
    return null;
  }

  const out = {};

  for (const child of children) {
    if (
      typeof child !== "string" ||
      !child ||
      BAD.has(child) ||
      child.includes("/") ||
      child.includes("\\")
    ) {
      continue;
    }

    const value = await getValue(env, [...segs, child]);

    if (value !== null) out[child] = value;
  }

  return Object.keys(out).length ? out : null;
}

async function deleteValue(env, segs) {
  if (!segs.length) return;

  const key = keyFor(segs);
  const children = await readKV(env, indexKey(segs));

  if (Array.isArray(children)) {
    for (const child of children) {
      if (
        typeof child === "string" &&
        child &&
        !BAD.has(child) &&
        !child.includes("/") &&
        !child.includes("\\")
      ) {
        await deleteValue(env, [...segs, child]);
      }
    }
  }

  await env.BAGH_KV.delete(key);
  await env.BAGH_KV.delete(indexKey(segs));

  if (segs.length > 1) {
    await updateChildIndex(
      env,
      segs.slice(0, -1),
      segs[segs.length - 1],
      false
    );
  }
}

async function putValue(env, segs, value) {
  if (!segs.length) {
    throw new Error("Cannot replace database root");
  }

  if (value === null) {
    await deleteValue(env, segs);
    return;
  }

  const key = keyFor(segs);
  const safeValue = clean(value);

  await env.BAGH_KV.put(
    key,
    JSON.stringify(safeValue)
  );

  if (
    safeValue &&
    typeof safeValue === "object" &&
    !Array.isArray(safeValue)
  ) {
    const children = Object.keys(safeValue).filter(
      (child) =>
        child &&
        !BAD.has(child) &&
        !child.includes("/") &&
        !child.includes("\\")
    );

    await env.BAGH_KV.put(
      indexKey(segs),
      JSON.stringify(children)
    );
  } else if (Array.isArray(safeValue)) {
    await env.BAGH_KV.put(
      indexKey(segs),
      JSON.stringify(
        safeValue.map((_, index) => String(index))
      )
    );
  } else {
    await env.BAGH_KV.delete(indexKey(segs));
  }

  if (segs.length > 1) {
    await updateChildIndex(
      env,
      segs.slice(0, -1),
      segs[segs.length - 1],
      true
    );
  }
}

// ---------- Public users ----------

// Merge users stored in the users root with users stored
// as individual indexed child keys. Never call KV.list().
async function getCombinedUsers(env) {
  const out = {};

  const root = await readKV(env, keyFor(["users"]));

  if (
    root &&
    typeof root === "object" &&
    !Array.isArray(root)
  ) {
    for (const [key, user] of Object.entries(root)) {
      if (
        !key ||
        BAD.has(key) ||
        !user ||
        typeof user !== "object" ||
        Array.isArray(user)
      ) {
        continue;
      }

      out[key] = stripPrivate(user);
    }
  }

  const children = await readKV(
    env,
    indexKey(["users"])
  );

  if (Array.isArray(children)) {
    for (const child of children) {
      if (
        typeof child !== "string" ||
        !child ||
        BAD.has(child) ||
        child.includes("/") ||
        child.includes("\\")
      ) {
        continue;
      }

      const user = await readKV(
        env,
        keyFor(["users", child])
      );

      if (
        !user ||
        typeof user !== "object" ||
        Array.isArray(user)
      ) {
        continue;
      }

      out[child] = stripPrivate({
        ...(out[child] || {}),
        ...user,
      });
    }
  }

  return out;
}

async function savePublicUser(env, user) {
  const phone = String(user.phone || "");
  const phoneDigits = phone.replace(/\D/g, "");
  const userKey = phoneDigits || String(user.uid || "");

  if (!userKey || BAD.has(userKey)) {
    throw new Error("Invalid public user key");
  }

  // Read the public root before updating it.
  const current = await readKV(
    env,
    keyFor(["users"])
  );

  const users =
    current &&
    typeof current === "object" &&
    !Array.isArray(current)
      ? { ...current }
      : {};

  const previous =
    users[userKey] &&
    typeof users[userKey] === "object" &&
    !Array.isArray(users[userKey])
      ? users[userKey]
      : {};

  // Public records must never contain password hashes or tokens.
  users[userKey] = stripPrivate({
    ...previous,
    uid: user.uid,
    phone: user.phone,
    displayName:
      String(user.displayName || "").trim().slice(0, 60) ||
      "کاربر باغ",
    createdAt: user.createdAt || Date.now(),
    online: true,
  });

  await env.BAGH_KV.put(
    keyFor(["users"]),
    JSON.stringify(users)
  );

  await updateChildIndex(env, [], "users", true);

  return users[userKey];
}

// ---------- Passwords and sessions ----------

function b64url(bytes) {
  let value = "";

  for (const byte of bytes) {
    value += String.fromCharCode(byte);
  }

  return btoa(value)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function fromB64url(value) {
  let text = value
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  while (text.length % 4) text += "=";

  return Uint8Array.from(
    atob(text),
    (character) => character.charCodeAt(0)
  );
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
  if (
    typeof salt !== "string" ||
    typeof expected !== "string"
  ) {
    return false;
  }

  const result = await hashPassword(password, salt);
  const actual = enc.encode(result.hash);
  const wanted = enc.encode(expected);

  if (actual.length !== wanted.length) return false;

  let difference = 0;

  for (let i = 0; i < actual.length; i++) {
    difference |= actual[i] ^ wanted[i];
  }

  return difference === 0;
}

function normalizePhone(input) {
  const phone = String(input || "")
    .replace(/[\s()-]/g, "");

  if (!/^\+?[0-9]{8,15}$/.test(phone)) {
    return null;
  }

  return phone.startsWith("+") ? phone : "+" + phone;
}

function phoneId(phone) {
  return "auth:phone:" + phone.replace(/\D/g, "");
}

async function makeSession(env, user) {
  const token = b64url(
    crypto.getRandomValues(new Uint8Array(32))
  );

  const now = Date.now();

  const session = {
    uid: user.uid,
    createdAt: now,
    expiresAt: now + 30 * 24 * 60 * 60 * 1000,
  };

  await env.BAGH_KV.put(
    "auth:session:" + token,
    JSON.stringify(session),
    { expirationTtl: 60 * 60 * 24 * 30 }
  );

  return token;
}

async function currentUser(req, env) {
  const authorization =
    req.headers.get("Authorization") || "";

  const match = authorization.match(
    /^Bearer\s+([A-Za-z0-9_-]+)$/
  );

  if (!match) return null;

  const session = await readKV(
    env,
    "auth:session:" + match[1]
  );

  if (
    !session ||
    !session.uid ||
    !Number.isFinite(session.expiresAt) ||
    session.expiresAt < Date.now()
  ) {
    return null;
  }

  const user = await readKV(
    env,
    "auth:user:" + session.uid
  );

  return user ? { ...user, token: match[1] } : null;
}

// ---------- Authentication routes ----------

async function authRoute(req, env, path) {
  if (
    path === "/auth/register" &&
    req.method === "POST"
  ) {
    const body = await readJson(req);
    const phone = normalizePhone(body.phone);
    const password = String(body.password || "");
    const displayName = String(body.displayName || "")
      .trim()
      .slice(0, 60);

    if (!phone) {
      return json({
        ok: false,
        err: "شماره موبایل معتبر نیست.",
      }, 400);
    }

    if (password.length < 10 || password.length > 128) {
      return json({
        ok: false,
        err: "رمز عبور باید حداقل ۱۰ نویسه داشته باشد.",
      }, 400);
    }

    const phoneIndex = phoneId(phone);

    if (await env.BAGH_KV.get(phoneIndex)) {
      return json({
        ok: false,
        err: "این شماره قبلاً ثبت‌نام کرده است؛ وارد شوید.",
      }, 409);
    }

    const uid = crypto.randomUUID();
    const passwordData = await hashPassword(password);

    const user = {
      uid,
      phone,
      displayName: displayName || "کاربر باغ",
      passwordSalt: passwordData.salt,
      passwordHash: passwordData.hash,
      createdAt: Date.now(),
    };

    // Store the private account record.
    await env.BAGH_KV.put(
      "auth:user:" + uid,
      JSON.stringify(user)
    );

    await env.BAGH_KV.put(phoneIndex, uid);

    // Also write the public record used by discovery.
    await savePublicUser(env, user);

    const token = await makeSession(env, user);

    return json({
      ok: true,
      token,
      user: {
        uid,
        phone,
        displayName: user.displayName,
      },
    }, 201);
  }

  if (
    path === "/auth/login" &&
    req.method === "POST"
  ) {
    const body = await readJson(req);
    const phone = normalizePhone(body.phone);
    const password = String(body.password || "");

    if (!phone || !password) {
      return json({
        ok: false,
        err: "شماره موبایل و رمز عبور را وارد کنید.",
      }, 400);
    }

    const uid = await env.BAGH_KV.get(phoneId(phone));

    if (!uid) {
      return json({
        ok: false,
        err: "شماره یا رمز عبور اشتباه است.",
      }, 401);
    }

    const user = await readKV(
      env,
      "auth:user:" + uid
    );

    if (
      !user ||
      !await passwordMatches(
        password,
        user.passwordSalt,
        user.passwordHash
      )
    ) {
      return json({
        ok: false,
        err: "شماره یا رمز عبور اشتباه است.",
      }, 401);
    }

    await savePublicUser(env, user);

    const token = await makeSession(env, user);

    return json({
      ok: true,
      token,
      user: {
        uid: user.uid,
        phone: user.phone,
        displayName: user.displayName,
      },
    });
  }

  if (
    path === "/auth/profile" &&
    req.method === "GET"
  ) {
    const user = await currentUser(req, env);

    if (!user) {
      return json({
        ok: false,
        err: "نشست معتبر نیست؛ دوباره وارد شوید.",
      }, 401);
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

  if (
    path === "/auth/logout" &&
    req.method === "POST"
  ) {
    const authorization =
      req.headers.get("Authorization") || "";

    const match = authorization.match(
      /^Bearer\s+([A-Za-z0-9_-]+)$/
    );

    if (match) {
      await env.BAGH_KV.delete(
        "auth:session:" + match[1]
      );
    }

    return json({ ok: true });
  }

  if (
    path === "/auth/recovery" &&
    req.method === "POST"
  ) {
    const body = await readJson(req);
    const phone = normalizePhone(body.phone);

    if (!phone) {
      return json({
        ok: false,
        err: "شماره موبایل معتبر نیست.",
      }, 400);
    }

    const id = crypto.randomUUID();

    const ticket = {
      id,
      phone,
      message: String(body.message || "")
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

    return json({
      ok: true,
      message:
        "درخواست ثبت شد؛ برای پیگیری به پشتیبانی پیام بدهید.",
      support: "@mrmmdt",
      ticketId: id,
    }, 201);
  }

  if (
    path === "/auth/send" ||
    path === "/auth/verify"
  ) {
    return json({
      ok: false,
      err:
        "ورود با پیامک هنوز فعال نیست. از ورود با رمز عبور استفاده کنید.",
    }, 501);
  }

  return json({
    ok: false,
    err: "مسیر احراز هویت پیدا نشد.",
  }, 404);
}

// ---------- Database routes ----------

async function databaseRoute(req, env, path) {
  if (!env.DB_KEY) {
    return json({
      error: "DB_KEY secret is required",
    }, 503);
  }

  const prefix = "/db/" + env.DB_KEY;

  if (
    path !== prefix &&
    !path.startsWith(prefix + "/")
  ) {
    return json({ error: "forbidden" }, 403);
  }

  const remainder = path.slice(prefix.length);
  const segs = segments(remainder);

  if (!valid(segs)) {
    return json({ error: "forbidden" }, 403);
  }

  if (req.method === "GET") {
    if (
      segs.length === 1 &&
      segs[0] === "users"
    ) {
      return json(await getCombinedUsers(env));
    }

    if (segs.length === 1) {
      return json({ error: "forbidden" }, 403);
    }

    return json(await getValue(env, segs));
  }

  if (req.method === "DELETE") {
    await deleteValue(env, segs);
    return json(null);
  }

  const oldValue = await getValue(env, segs);

  const body = clean(
    applyServerValues(
      await readBody(req),
      oldValue
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

    const old =
      oldValue &&
      typeof oldValue === "object" &&
      !Array.isArray(oldValue)
        ? oldValue
        : {};

    const merged = { ...old, ...body };

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

  return json({ error: "method not allowed" }, 405);
}

// ---------- Worker entry ----------

export default {
  async fetch(req, env) {
    if (req.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: cors,
      });
    }

    if (!env.BAGH_KV) {
      return json({
        ok: false,
        error: "BAGH_KV binding is not configured",
      }, 500);
    }

    let url;
    let path;

    try {
      url = new URL(req.url);
      path = decodeURIComponent(url.pathname);
    } catch (error) {
      logError("BAGH_PATH_ERROR", error);
      return json({ error: "invalid path" }, 400);
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

        return json({
          ok: false,
          err: "خطای موقت سرور؛ دوباره تلاش کنید.",
        }, 500);
      }
    }

    if (
      path !== "/db" &&
      !path.startsWith("/db/")
    ) {
      return json({ error: "not found" }, 404);
    }

    try {
      return await databaseRoute(req, env, path);
    } catch (error) {
      logError("BAGH_DB_ROUTE_ERROR", error);

      return json({
        error: "database temporarily unavailable",
      }, 500);
    }
  },
};
