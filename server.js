// =====================================================================
//  Trade Copier Server
//
//  Plain Node, zero npm dependencies. Sits behind Caddy, which handles
//  HTTPS and renews the certificate on its own.
//
//  Trading endpoints (used by NinjaTrader)
//    POST /v1/enroll   code + machineId        -> issues a token
//    POST /v1/state    Bearer <leader token>   -> publish a snapshot
//    GET  /v1/stream   Bearer <follower token> -> long-poll for snapshots
//
//  Admin panel (used by a browser)
//    GET  /admin                 the control panel
//    POST /admin/api/setup       set the password on first run
//    POST /admin/api/login       sign in
//    GET  /admin/api/state       everything the panel renders
//    POST /admin/api/invite      mint a one-time code
//    POST /admin/api/revoke      cut someone off
//    POST /admin/api/halt        stop everyone / resume
//
//  Everything published is a FULL position snapshot, so a missed poll
//  costs nothing: the next one puts the follower right again.
// =====================================================================

const http   = require('http');
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');

const DIR        = __dirname;
const DATA_DIR   = process.env.DATA_DIR || DIR;   // a mounted volume in production
const DATA_FILE  = path.join(DATA_DIR, 'data.json');
const ADMIN_HTML = path.join(DIR, 'admin.html');
const PORT       = process.env.PORT || 8080;
const POLL_MS    = parseInt(process.env.POLL_MS || '20000', 10);  // poll hold time

let db = { invites: {}, members: {}, admin: null };
if (fs.existsSync(DATA_FILE)) db = { ...db, ...JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')) };

fs.mkdirSync(DATA_DIR, { recursive: true });
const save = () => fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2));
const log  = (...a) => console.log(new Date().toISOString(), ...a);

// ---------------------------------------------------------------- state

let seq           = 0;      // bumped only when what followers should see changes
let leaderPayload = '';     // what the leader says it holds
let broadcast     = '';     // what followers are actually told (empty while halted)
let stamped       = Date.now();
let halted        = false;
let waiters       = [];     // parked follower responses

function publish(next) {
  if (next === broadcast) { stamped = Date.now(); return; }

  seq += 1;
  broadcast = next;
  stamped = Date.now();

  const body = `${seq}|${stamped}|${broadcast}`;
  const flush = waiters;
  waiters = [];
  for (const w of flush) { try { send(w.res, 200, body); } catch (e) {} }
}

// ---------------------------------------------------------------- utils

function send(res, code, body, type) {
  res.writeHead(code, { 'Content-Type': type || 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(body);
}

const json = (res, code, obj) => send(res, code, JSON.stringify(obj), 'application/json');

function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const A = Buffer.from(a), B = Buffer.from(b);
  return A.length === B.length && crypto.timingSafeEqual(A, B);
}

function bearer(req) {
  const h = req.headers['authorization'] || '';
  return h.startsWith('Bearer ') ? h.slice(7).trim() : null;
}

function memberFor(token) {
  if (!token) return null;
  for (const name of Object.keys(db.members))
    if (safeEqual(db.members[name].token, token)) return { name, ...db.members[name] };
  return null;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let b = '';
    req.on('data', (c) => { b += c; if (b.length > 32768) { reject(new Error('too large')); req.destroy(); } });
    req.on('end', () => resolve(b));
    req.on('error', reject);
  });
}

// Human-friendly codes. No O/0/I/1, because these get read out loud.
function makeCode() {
  const A = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let out = '';
  for (let i = 0; i < 12; i++) { if (i && i % 4 === 0) out += '-'; out += A[crypto.randomInt(A.length)]; }
  return out;
}

// ---------------------------------------------------------------- admin auth

const sessions = new Map();               // token -> expiry
const SESSION_MS = 12 * 60 * 60 * 1000;
let failures = 0, lockedUntil = 0;

const hash  = (pw, salt) => crypto.scryptSync(pw, salt, 64).toString('hex');
const cookieOf = (req) => (req.headers.cookie || '').split(';')
  .map(s => s.trim().split('=')).find(p => p[0] === 'sid')?.[1] || null;

function signedIn(req) {
  const sid = cookieOf(req);
  if (!sid) return false;
  const exp = sessions.get(sid);
  if (!exp) return false;
  if (exp < Date.now()) { sessions.delete(sid); return false; }
  return true;
}

function startSession(res) {
  const sid = crypto.randomBytes(32).toString('hex');
  sessions.set(sid, Date.now() + SESSION_MS);
  res.setHeader('Set-Cookie', `sid=${sid}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${SESSION_MS / 1000}`);
  return sid;
}

// ---------------------------------------------------------------- routes

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const p   = url.pathname;

  try {
    if (p === '/v1/health') return send(res, 200, 'ok');

    // ======================= NinjaTrader =======================

    if (p === '/v1/enroll' && req.method === 'POST') {
      const body = new URLSearchParams(await readBody(req));
      const code = (body.get('code') || '').trim().toUpperCase();
      const mid  = (body.get('machineId') || '').trim();

      const inv = db.invites[code];
      if (!inv) return send(res, 403, 'error|Invite code not recognised.');
      if (!mid) return send(res, 400, 'error|Missing machine id.');

      if (inv.used && inv.machineId !== mid)
        return send(res, 403, 'error|This code was already used on another computer.');

      if (!inv.used) {
        inv.used = true; inv.machineId = mid; inv.enrolled = Date.now();
        db.members[inv.name] = { token: inv.token, machineId: mid, role: inv.role, enrolled: Date.now() };
        save();
        log('ENROLLED', inv.name, inv.role);
      }
      return send(res, 200, `ok|${inv.token}|${inv.name}|${inv.role}`);
    }

    if (p === '/v1/state' && req.method === 'POST') {
      const m = memberFor(bearer(req));
      if (!m || m.role !== 'leader') return send(res, 401, 'error|Not authorised.');

      const next = new URLSearchParams(await readBody(req)).get('payload') || '';
      leaderPayload = next;

      db.members[m.name].lastSeen = Date.now();
      if (!halted) publish(next);
      return send(res, 200, `ok|${seq}`);
    }

    if (p === '/v1/stream' && req.method === 'GET') {
      const m = memberFor(bearer(req));
      if (!m || m.role !== 'follower') return send(res, 401, 'error|Not authorised.');

      // Followers report their own sizing so the panel can show it.
      const mult = url.searchParams.get('mult');
      const cap  = url.searchParams.get('cap');
      db.members[m.name].lastSeen = Date.now();
      if (mult && cap) db.members[m.name].size = `${mult}x, max ${cap}`;

      const since = parseInt(url.searchParams.get('since') || '-1', 10);

      // seq 0 means nothing has ever been published. Park rather than send an
      // empty snapshot, which a follower would read as "go flat".
      if (seq > 0 && seq > since) return send(res, 200, `${seq}|${stamped}|${broadcast}`);

      const waiter = { res };
      waiters.push(waiter);
      const timer = setTimeout(() => {
        waiters = waiters.filter(w => w !== waiter);
        try { send(res, 204, ''); } catch (e) {}
      }, POLL_MS);
      res.on('close', () => { clearTimeout(timer); waiters = waiters.filter(w => w !== waiter); });
      return;
    }

    // ========================= admin ==========================

    if (p === '/admin' || p === '/admin/')
      return send(res, 200, fs.readFileSync(ADMIN_HTML, 'utf8'), 'text/html; charset=utf-8');

    if (p === '/admin/api/hello')
      return json(res, 200, { needsSetup: !db.admin, signedIn: signedIn(req) });

    if (p === '/admin/api/setup' && req.method === 'POST') {
      if (db.admin) return json(res, 403, { error: 'A password is already set.' });

      const { password } = JSON.parse(await readBody(req) || '{}');
      if (!password || password.length < 10)
        return json(res, 400, { error: 'Use at least 10 characters.' });

      const salt = crypto.randomBytes(16).toString('hex');
      db.admin = { salt, hash: hash(password, salt) };
      save();
      startSession(res);
      log('ADMIN password set');
      return json(res, 200, { ok: true });
    }

    if (p === '/admin/api/login' && req.method === 'POST') {
      if (Date.now() < lockedUntil)
        return json(res, 429, { error: 'Too many attempts. Wait a minute.' });
      if (!db.admin) return json(res, 400, { error: 'No password set yet.' });

      const { password } = JSON.parse(await readBody(req) || '{}');
      if (!password || !safeEqual(hash(password, db.admin.salt), db.admin.hash)) {
        if (++failures >= 5) { lockedUntil = Date.now() + 60000; failures = 0; }
        return json(res, 401, { error: 'Wrong password.' });
      }

      failures = 0;
      startSession(res);
      return json(res, 200, { ok: true });
    }

    if (p.startsWith('/admin/api/')) {
      if (p === '/admin/api/logout') {
        const sid = cookieOf(req);
        if (sid) sessions.delete(sid);
        return json(res, 200, { ok: true });
      }

      if (!signedIn(req)) return json(res, 401, { error: 'Sign in again.' });
      const now = Date.now();

      if (p === '/admin/api/state') {
        const members = Object.keys(db.members).map((name) => {
          const m = db.members[name];
          return {
            name, role: m.role, size: m.size || null, enrolled: !!m.enrolled,
            seen: m.lastSeen ? Math.round((now - m.lastSeen) / 1000) : -1,
          };
        });

        // Invites that nobody has redeemed yet still belong in the roster.
        for (const inv of Object.values(db.invites))
          if (!inv.used && !db.members[inv.name])
            members.push({ name: inv.name, role: inv.role, size: null, enrolled: false, seen: -1 });

        return json(res, 200, { payload: leaderPayload, halted, seq, members });
      }

      if (p === '/admin/api/invite' && req.method === 'POST') {
        const { name, role } = JSON.parse(await readBody(req) || '{}');
        const clean = String(name || '').trim().slice(0, 20);
        if (!clean) return json(res, 400, { error: 'Give them a name.' });
        if (db.members[clean]) return json(res, 400, { error: 'That name is already taken.' });

        const code = makeCode();
        db.invites[code] = {
          name: clean,
          role: role === 'leader' ? 'leader' : 'follower',
          token: crypto.randomBytes(32).toString('hex'),
          used: false, created: now,
        };
        save();
        log('INVITE', clean, db.invites[code].role);
        return json(res, 200, { code, name: clean });
      }

      if (p === '/admin/api/revoke' && req.method === 'POST') {
        const { name } = JSON.parse(await readBody(req) || '{}');
        delete db.members[name];
        for (const [c, i] of Object.entries(db.invites)) if (i.name === name) delete db.invites[c];
        save();
        log('REVOKED', name);
        return json(res, 200, { ok: true });
      }

      if (p === '/admin/api/halt' && req.method === 'POST') {
        const { halt } = JSON.parse(await readBody(req) || '{}');
        halted = !!halt;
        log(halted ? 'HALT - flattening everyone' : 'RESUME');

        // Halting publishes an empty snapshot, which every follower reads as
        // "go flat". Resuming publishes whatever the leader holds right now.
        publish(halted ? '' : leaderPayload);
        return json(res, 200, { ok: true, halted });
      }

      return json(res, 404, { error: 'Not found.' });
    }

    send(res, 404, 'error|Not found.');
  } catch (err) {
    log('ERR', err.message);
    try { send(res, 500, 'error|Server error.'); } catch (e) {}
  }
});

// Long polls must outlive the default socket timeouts.
server.headersTimeout = 0;
server.requestTimeout = 0;
server.setTimeout(0);

server.listen(PORT, '0.0.0.0', () => log('Copier server listening on ' + PORT + '  data=' + DATA_DIR));
