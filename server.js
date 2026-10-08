// سرور باغ — بدون وابستگی (فقط Node 14+)
// اجرا:  KEY=رمز-دلخواه node server.js
// متغیرها: PORT (3000)، KEY (رمز مسیر)، DATA (data.json)،
//          KAVENEGAR_KEY و KAVENEGAR_TEMPLATE (برای ارسال پیامک واقعی)
const http = require('http'), https = require('https'), fs = require('fs'), crypto = require('crypto');
const PORT = +process.env.PORT || 3000, KEY = process.env.KEY || '', FILE = process.env.DATA || 'data.json';
const KAV = process.env.KAVENEGAR_KEY || '', TPL = process.env.KAVENEGAR_TEMPLATE || 'verify';
const TOP = ['users', 'userchats', 'chats', 'calls', 'ans', 'ice'], BAD = ['__proto__', 'constructor', 'prototype'];

let db = {}; try { db = JSON.parse(fs.readFileSync(FILE, 'utf8')); } catch (e) {}
let dirty = 0, rdirty = 0;
setInterval(() => { if (dirty) { dirty = 0; fs.writeFile(FILE + '.tmp', JSON.stringify(db), e => { if (!e) fs.rename(FILE + '.tmp', FILE, () => {}); }); } }, 1500);

const isO = v => v && typeof v == 'object' && !Array.isArray(v);
const get = (s, o = db) => { for (const k of s) { if (o == null || typeof o != 'object') return null; o = o[k]; } return o === undefined ? null : o; };
function clean(v) { if (isO(v)) { const o = {}; for (const k in v) { const c = clean(v[k]); if (c != null) o[k] = c; } return Object.keys(o).length ? o : null; } return v; }
function sv(v, ex) {
  if (isO(v)) {
    if ('.sv' in v) { const s = v['.sv']; if (s == 'timestamp') return Date.now(); if (s && s.increment != null) return (typeof ex == 'number' ? ex : 0) + Number(s.increment); return null; }
    const o = {}; for (const k in v) o[k] = sv(v[k], isO(ex) ? ex[k] : undefined); return o;
  }
  return v;
}
function set(s, v) {
  if (!s.length) { db = isO(v) ? v : {}; dirty = rdirty = 1; return; }
  let o = db;
  for (let i = 0; i < s.length - 1; i++) { if (!isO(o[s[i]])) { if (v == null) return; o[s[i]] = {}; } o = o[s[i]]; }
  if (v == null) delete o[s[s.length - 1]]; else o[s[s.length - 1]] = v;
  for (let n = s.length - 1; n > 0; n--) { // پاک‌کردن والدهای خالی
    const p = get(s.slice(0, n)); if (isO(p) && !Object.keys(p).length) { const g = n - 1 ? get(s.slice(0, n - 1)) : db; delete g[s[n - 1]]; } else break;
  }
  dirty = rdirty = 1;
}
let ctr = 0; const push = () => Date.now().toString(36).padStart(9, '0') + (ctr++ % 1296).toString(36).padStart(2, '0') + crypto.randomBytes(3).toString('hex');

const LS = new Set();
const pre = (a, b) => a.length <= b.length && a.every((x, i) => x == b[i]);
const send = (l, ev, d) => { try { l.res.write('event: ' + ev + '\ndata: ' + JSON.stringify(d) + '\n\n'); } catch (e) {} };
function notify(w, type, val) {
  for (const l of LS) {
    if (pre(w, l.segs)) send(l, 'put', { path: '/', data: get(l.segs) });
    else if (pre(l.segs, w)) send(l, type, { path: '/' + w.slice(l.segs.length).join('/'), data: val });
  }
}
setInterval(() => LS.forEach(l => { try { l.res.write('event: keep-alive\ndata: null\n\n'); } catch (e) {} }), 25000);

const CORS = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET,PUT,POST,PATCH,DELETE,OPTIONS', 'Access-Control-Allow-Headers': '*' };
const out = (res, code, o) => { res.writeHead(code, { ...CORS, 'Content-Type': 'application/json; charset=utf-8' }); res.end(JSON.stringify(o)); };
const body = req => new Promise((ok, no) => { let b = '', n = 0; req.on('data', c => { n += c.length; if (n > 1e6) { no(new Error('big')); req.destroy(); } else b += c; }); req.on('end', () => { try { ok(b ? JSON.parse(b) : null); } catch (e) { no(e); } }); });

// ---- ذخیره‌ی پشتیبان روی GitHub Gist (برای هاست‌های رایگانی که دیسک ندارن) ----
// GIST_ID و GIST_TOKEN (توکن با دسترسی gist) رو بذار تا دیتا با ری‌استارت پاک نشه
const GID = process.env.GIST_ID || '', GTK = process.env.GIST_TOKEN || '';
function gh(method, path, b) {
  return new Promise(ok => {
    const d = b ? JSON.stringify(b) : null;
    const r = https.request({ hostname: 'api.github.com', path, method, headers: { 'User-Agent': 'bagh', Accept: 'application/vnd.github+json', Authorization: 'Bearer ' + GTK, ...(d ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(d) } : {}) } }, res => {
      let t = ''; res.on('data', c => t += c); res.on('end', () => { try { ok(JSON.parse(t)); } catch (e) { ok(null); } });
    });
    r.on('error', () => ok(null)); if (d) r.write(d); r.end();
  });
}
const raw = url => new Promise(ok => https.get(url, { headers: { 'User-Agent': 'bagh' } }, res => { let t = ''; res.on('data', c => t += c); res.on('end', () => ok(t)); }).on('error', () => ok(null)));
async function loadRemote() {
  if (!GID) return;
  const g = await gh('GET', '/gists/' + GID), f = g && g.files && g.files['data.json'];
  if (!f) return console.log('Gist load failed (check GIST_ID / GIST_TOKEN)');
  try { const o = JSON.parse(f.truncated ? await raw(f.raw_url) : f.content); if (isO(o)) { db = o; console.log('Loaded from Gist'); } } catch (e) { console.log('Gist data invalid'); }
}
let saving = 0;
async function saveRemote(force) {
  if (!GID || saving || (!rdirty && !force)) return; saving = 1; rdirty = 0;
  const r = await gh('PATCH', '/gists/' + GID, { files: { 'data.json': { content: JSON.stringify(db) } } });
  saving = 0; if (!r || !r.id) rdirty = 1;
}
setInterval(() => saveRemote(), 20000);
process.on('SIGTERM', async () => { await saveRemote(true); process.exit(0); });

// ---- احراز هویت با کد پیامکی ----
const otp = {}, hits = {};
setInterval(() => { for (const k in hits) delete hits[k]; }, 60000);
function kav(rcv, code) {
  return new Promise(ok => https.get(`https://api.kavenegar.com/v1/${KAV}/verify/lookup.json?receptor=${rcv}&token=${code}&template=${encodeURIComponent(TPL)}`, r => {
    let d = ''; r.on('data', c => d += c); r.on('end', () => { try { ok(JSON.parse(d).return.status == 200); } catch (e) { ok(false); } });
  }).on('error', () => ok(false)));
}
async function auth(req, res, p) {
  const ip = req.socket.remoteAddress; hits[ip] = (hits[ip] || 0) + 1; if (hits[ip] > 30) return out(res, 429, { ok: false, err: 'تعداد درخواست زیاد است' });
  let b; try { b = await body(req); } catch (e) { return out(res, 400, { ok: false }); }
  const ph = String((b && b.phone) || '').replace(/\D/g, '');
  if (!/^989\d{9}$/.test(ph)) return out(res, 200, { ok: false, err: 'شماره نامعتبره' });
  if (p == '/auth/send') {
    const o = otp[ph]; if (o && Date.now() - o.last < 55000) return out(res, 200, { ok: false, err: 'کمی صبر کن و دوباره امتحان کن' });
    const code = String(10000 + crypto.randomInt(90000)); otp[ph] = { code, exp: Date.now() + 120000, tries: 0, last: Date.now() };
    if (KAV) return out(res, 200, (await kav('0' + ph.slice(2), code)) ? { ok: true } : { ok: false, err: 'ارسال پیامک ناموفق بود' });
    console.log('OTP', ph, code); return out(res, 200, { ok: true, dev: code });
  }
  if (p == '/auth/verify') {
    const o = otp[ph]; if (!o || Date.now() > o.exp || ++o.tries > 5) return out(res, 200, { ok: false, err: 'کد منقضی شده' });
    if (o.code != String(b.code)) return out(res, 200, { ok: false, err: 'کد اشتباهه' });
    delete otp[ph]; return out(res, 200, { ok: true });
  }
  if (p == '/auth/profile') return out(res, 200, { ok: true });
  out(res, 404, { ok: false });
}

// ---- دیتابیس (سازگار با Firebase REST + SSE) ----
const server = http.createServer(async (req, res) => {
  if (req.method == 'OPTIONS') { res.writeHead(204, CORS); return res.end(); }
  let p; try { p = decodeURIComponent(new URL(req.url, 'http://x').pathname); } catch (e) { return out(res, 400, {}); }
  if (p == '/health') return out(res, 200, { ok: true, users: Object.keys(db.users || {}).length });
  if (p.startsWith('/auth/')) return auth(req, res, p);
  if (!p.startsWith('/db')) return out(res, 404, { error: 'not found' });
  p = p.slice(3);
  if (KEY) { if (p != '/' + KEY && !p.startsWith('/' + KEY + '/')) return out(res, 403, { error: 'forbidden' }); p = p.slice(KEY.length + 1); }
  const segs = p.replace(/\.json$/, '').split('/').filter(Boolean);
  if (!segs.length || !TOP.includes(segs[0]) || segs.some(s => BAD.includes(s))) return out(res, 403, { error: 'forbidden' });
  const m = req.method;
  try {
    if (m == 'GET') {
      if ((req.headers.accept || '').includes('text/event-stream')) {
        res.writeHead(200, { ...CORS, 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
        const l = { segs, res }; LS.add(l); req.on('close', () => LS.delete(l)); return send(l, 'put', { path: '/', data: get(segs) });
      }
      if (segs.length == 1 && segs[0] != 'users') return out(res, 403, { error: 'forbidden' });
      let d = get(segs);
      if (segs.length == 1 && isO(d)) { const o = {}; for (const k in d) { const { phone, bio, ...pub } = d[k]; o[k] = pub; } d = o; }
      return out(res, 200, d);
    }
    if (m == 'DELETE') { set(segs, null); notify(segs, 'put', null); return out(res, 200, null); }
    const b = await body(req);
    if (m == 'PUT') { const v = clean(sv(b, get(segs))); set(segs, v); notify(segs, 'put', v); return out(res, 200, v); }
    if (m == 'PATCH') {
      if (!isO(b)) return out(res, 400, {}); const ex = get(segs), f = {};
      for (const k in b) { if (BAD.includes(k)) continue; f[k] = sv(b[k], isO(ex) ? ex[k] : undefined); set(segs.concat(k), clean(f[k])); }
      notify(segs, 'patch', f); return out(res, 200, f);
    }
    if (m == 'POST') { const k = push(), v = clean(sv(b, null)), w = segs.concat(k); set(w, v); notify(w, 'put', v); return out(res, 200, { name: k }); }
    out(res, 405, {});
  } catch (e) { out(res, 400, { error: 'bad request' }); }
});
loadRemote().then(() => server.listen(PORT, () => console.log('Bagh server on :' + PORT + (KEY ? '  (key enabled)' : '  (no key!)'))));
