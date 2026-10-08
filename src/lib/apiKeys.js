// API keys for the public read-only API (/api/v1).
// - A key only exists once its owner presses "Reveal key" on the website, and it is shown that one time.
// - The database keeps the key's SHA-256 hash and a short prefix to find it, never the key itself.
// - Limits per key: requests per minute (counted in memory) and per UTC day (counted in memory, saved every few
//   seconds and read back from the database, so a restart or a second API instance still sees the day's total).
// - Keys are never logged, and no IP address is stored.
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { many, one } from '../db.js';
import { HttpError, bad } from './http.js';

export const KEY_PREFIX = 'qk_live_';
const KEY_CHARS = 40;
const PREFIX_LEN = KEY_PREFIX.length + 6; // qk_live_ + 6 characters, shown in the panels
const ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
export const KEY_RE = /^qk_live_[0-9A-Za-z]{40}$/;

export const STATUSES = ['pending', 'active', 'paused', 'rejected', 'revoked'];
export const TIERS = ['free', 'partner'];
/** Hard caps: nobody, not even an admin, can give a key more than this. */
export const CAPS = { perMinute: 600, perDay: 1_000_000 };
const envInt = (name, fallback, max) => {
  const n = Number.parseInt(String(process.env[name] ?? ''), 10);
  return Number.isFinite(n) && n >= 1 ? Math.min(n, max) : fallback;
};
/** Limits a new key gets unless the admin changes them when approving. */
export const DEFAULTS = {
  perMinute: envInt('API_FREE_PER_MINUTE', 60, CAPS.perMinute),
  perDay: envInt('API_FREE_PER_DAY', 10_000, CAPS.perDay),
};
/** Per wallet: one open request, and up to this many keys that are active or paused. */
export const MAX_KEYS = 3;

const CACHE_MS = 30_000;   // a key found in the database is trusted from memory for at most this long
const SYNC_MS = 5_000;     // usage is saved, and cached keys re-checked, this often
const TOUCH_MS = 60_000;   // last_used_at is written at most once a minute per key
const FAIL_LIMIT = 30;     // wrong keys per IP per minute before that IP is blocked for the rest of the minute

// ── Making keys ────────────────────────────────────────────────────────────────────────────────────

export const sha256 = (text) => createHash('sha256').update(String(text), 'utf8').digest('hex');

/** Random base62 text. Bytes of 248 or more are skipped (248 = 4 x 62), so every character is equally likely. */
function base62(length) {
  let out = '';
  while (out.length < length) {
    for (const b of randomBytes(length + 16)) {
      if (b >= 248) continue;
      out += ALPHABET[b % 62];
      if (out.length === length) break;
    }
  }
  return out;
}

export function newKey() {
  const key = KEY_PREFIX + base62(KEY_CHARS);
  return { key, prefix: key.slice(0, PREFIX_LEN), hash: sha256(key) };
}

/**
 * Calls `save({ prefix, hash })` with a fresh key and returns { key, prefix, row }, or null when `save` changed
 * nothing. A prefix that is already taken (about 1 in 56 billion) just gets another key.
 */
export async function withNewKey(save) {
  for (let i = 0; i < 5; i++) {
    const k = newKey();
    try {
      const row = await save({ prefix: k.prefix, hash: k.hash });
      return row ? { key: k.key, prefix: k.prefix, row } : null;
    } catch (e) {
      if (e?.code === '23505' && String(e.constraint || e.message).includes('api_keys_prefix')) continue;
      throw e;
    }
  }
  throw new HttpError(503, 'Could not create a key right now. Try again.', 'key_retry');
}

// ── Checking what people send ──────────────────────────────────────────────────────────────────────

const CONTROL = /[\u0000-\u001f\u007f]/;

export function cleanProject(v) {
  const s = String(v ?? '').replace(/\s+/g, ' ').trim();
  if (s.length < 3 || s.length > 60 || CONTROL.test(s)) throw bad('Project name must be 3-60 characters', 'invalid_project');
  return s;
}

export function cleanUseCase(v) {
  const s = String(v ?? '').replace(/\r\n?/g, '\n').trim();
  if (s.length < 20 || s.length > 1000 || /[\u0000-\u0009\u000b-\u001f\u007f]/.test(s)) {
    throw bad('Describe what the key is for in 20-1000 characters', 'invalid_use_case');
  }
  return s;
}

/** Website links: https only (plain http is upgraded, "site.com/x" gets https://), same rules as collection links. */
export function cleanWebsite(v) {
  if (v === undefined || v === null) return null;
  let s = String(v).trim();
  if (!s) return null;
  if (/^http:\/\//i.test(s)) s = `https://${s.slice(7)}`;
  else if (/^(www\.)?[a-z0-9-]+(\.[a-z0-9-]+)+(\/\S*)?$/i.test(s)) s = `https://${s}`;
  if (s.length > 300 || !/^https:\/\/[^\s"'<>\\]+$/i.test(s)) throw bad('Website must be a link that starts with https://', 'invalid_website');
  try { new URL(s); } catch { throw bad('That website link is not valid', 'invalid_website'); }
  return s;
}

/** Contact: an email address, or a Telegram / X handle such as @name. */
export function cleanContact(v) {
  if (v === undefined || v === null) return null;
  const s = String(v).trim();
  if (!s) return null;
  const email = /^[^\s@<>"'\\]{1,64}@[^\s@<>"'\\]{1,100}\.[A-Za-z]{2,24}$/.test(s);
  const handle = /^@?[A-Za-z0-9_]{2,32}$/.test(s);
  if (s.length > 120 || !(email || handle)) {
    throw bad('Contact must be an email address or a Telegram or X handle like @name (120 characters at most)', 'invalid_contact');
  }
  return s;
}

/** Limits typed by an admin, kept within the hard caps. */
export function cleanLimits(b, current = {}) {
  const pick = (v, cur, max, label) => {
    if (v === undefined || v === null || v === '') return cur;
    const n = Number(v);
    if (!Number.isInteger(n) || n < 1 || n > max) throw bad(`${label} must be a whole number from 1 to ${max.toLocaleString('en-US')}`, 'invalid_limit');
    return n;
  };
  const tier = b.tier === undefined || b.tier === null || b.tier === '' ? current.tier : String(b.tier);
  if (tier !== undefined && !TIERS.includes(tier)) throw bad('Tier must be free or partner', 'invalid_tier');
  return {
    per_minute: pick(b.per_minute ?? b.perMinute, current.per_minute, CAPS.perMinute, 'Requests per minute'),
    per_day: pick(b.per_day ?? b.perDay, current.per_day, CAPS.perDay, 'Requests per day'),
    tier,
  };
}

export const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// ── Usage counters ─────────────────────────────────────────────────────────────────────────────────

const utcDay = (ms = Date.now()) => new Date(ms).toISOString().slice(0, 10);
const nextUtcMidnight = (ms = Date.now()) => { const d = new Date(ms); return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate() + 1); };

const usage = new Map();      // key id -> { day, base }: the day's total in the database at the last sync
const unflushed = new Map();  // `${id}|${day}` -> requests not saved yet
const inflight = new Map();   // `${id}|${day}` -> requests being saved right now
const minute = new Map();     // key id -> { win, n }: requests in the current minute
const used = new Set();       // key ids used since their last_used_at was written
const touched = new Map();    // key id -> when last_used_at was last written

function setBase(id, day, n) {
  const u = usage.get(id);
  if (!u || u.day < day || (u.day === day && n > u.base)) usage.set(id, { day, base: Number(n) || 0 });
}

/** Requests counted in this process that the database does not have yet. */
export function localPending(id) {
  const k = `${id}|${utcDay()}`;
  return (unflushed.get(k) || 0) + (inflight.get(k) || 0);
}

/** Today's requests for a key (database total at the last sync + what this process counted since). */
export function usedToday(id) {
  const d = utcDay();
  const u = usage.get(id);
  return (u?.day === d ? u.base : 0) + localPending(id);
}

function minuteUsed(id) {
  const win = Math.floor(Date.now() / 60_000);
  const m = minute.get(id);
  return m && m.win === win ? m.n : 0;
}

function count(id) {
  const win = Math.floor(Date.now() / 60_000);
  const m = minute.get(id);
  if (m && m.win === win) m.n += 1;
  else minute.set(id, { win, n: 1 });
  const k = `${id}|${utcDay()}`;
  unflushed.set(k, (unflushed.get(k) || 0) + 1);
  used.add(id);
}

/** Limits and usage of a key as the public API reports them (GET /api/v1/me). */
export function limitState(row) {
  const now = Date.now();
  const minuteLeft = Math.max(0, row.per_minute - minuteUsed(row.id));
  const today = usedToday(row.id);
  return {
    per_minute: row.per_minute,
    per_day: row.per_day,
    used_this_minute: minuteUsed(row.id),
    remaining_this_minute: minuteLeft,
    used_today: today,
    remaining_today: Math.max(0, row.per_day - today),
    minute_resets_at: new Date((Math.floor(now / 60_000) + 1) * 60_000).toISOString(),
    day_resets_at: new Date(nextUtcMidnight(now)).toISOString(),
  };
}

// ── Looking keys up ────────────────────────────────────────────────────────────────────────────────

const cache = new Map(); // prefix -> { row, at }
const AUTH_COLS = `k.id, k.address, k.project, k.status, k.tier, k.per_minute, k.per_day, k.key_prefix, k.key_hash`;

/** Drops a key from this process's memory right away (status change, rotate, revoke). */
export function forgetKey(prefix) {
  if (prefix) cache.delete(prefix);
}

const DUMMY = Buffer.alloc(32);
function sameHash(hexA, hexB) {
  const a = /^[0-9a-f]{64}$/.test(hexA || '') ? Buffer.from(hexA, 'hex') : null;
  const b = /^[0-9a-f]{64}$/.test(hexB || '') ? Buffer.from(hexB, 'hex') : null;
  // Always one constant-time comparison, whether or not a row was found.
  const equal = timingSafeEqual(a || DUMMY, b || DUMMY);
  return Boolean(a && b && equal);
}

/** A valid key already known from the last 30 seconds, without asking the database (or null). */
function cachedKey(key) {
  const hit = cache.get(key.slice(0, PREFIX_LEN));
  return hit && Date.now() - hit.at < CACHE_MS && sameHash(sha256(key), hit.row.key_hash) ? hit.row : null;
}

async function findKey(key) {
  const prefix = key.slice(0, PREFIX_LEN);
  const hash = sha256(key);
  const hit = cache.get(prefix);
  if (hit && Date.now() - hit.at < CACHE_MS) return sameHash(hash, hit.row.key_hash) ? hit.row : null;
  const day = utcDay();
  const row = await one(
    `select ${AUTH_COLS}, coalesce(u.requests, 0)::int as used_today
     from app.api_keys k left join app.api_key_usage u on u.key_id = k.id and u.day = $2::date
     where k.key_prefix = $1`,
    [prefix, day],
  );
  if (!row || !sameHash(hash, row.key_hash)) return null;
  const { used_today, ...keyRow } = row;
  setBase(row.id, day, used_today);
  if (row.status === 'active') {
    if (cache.size > 20_000) cache.clear();
    cache.set(prefix, { row: keyRow, at: Date.now() });
  } else {
    cache.delete(prefix);
  }
  return keyRow;
}

// ── Wrong keys: blocked per IP after FAIL_LIMIT a minute, so keys can't be guessed ─────────────────

const fails = new Map(); // ip -> { win, n }
function failBlockedFor(ip) {
  const win = Math.floor(Date.now() / 60_000);
  const f = fails.get(ip);
  if (!f || f.win !== win || f.n < FAIL_LIMIT) return 0;
  return 60 - Math.floor((Date.now() % 60_000) / 1000);
}
function noteFailure(ip) {
  const win = Math.floor(Date.now() / 60_000);
  const f = fails.get(ip);
  if (f && f.win === win) f.n += 1;
  else {
    if (fails.size > 100_000) fails.clear();
    fails.set(ip, { win, n: 1 });
  }
}

// ── The middleware for /api/v1 ─────────────────────────────────────────────────────────────────────

/** The key from `X-API-Key: qk_live_...` or `Authorization: Bearer qk_live_...` (null when neither is sent). */
function keyFromHeaders(req) {
  const x = req.headers['x-api-key'];
  if (typeof x === 'string' && x.trim()) return x.trim();
  const auth = String(req.headers.authorization || '');
  if (/^Bearer\s+qk_/i.test(auth)) return auth.replace(/^Bearer\s+/i, '').trim();
  return null;
}

function setLimitHeaders(res, row, minuteCount, dayCount) {
  const now = Date.now();
  const minuteLeft = Math.max(0, row.per_minute - minuteCount);
  const dayLeft = Math.max(0, row.per_day - dayCount);
  const minuteReset = 60 - Math.floor((now % 60_000) / 1000);
  const dayReset = Math.ceil((nextUtcMidnight(now) - now) / 1000);
  // RateLimit-* describe whichever limit is closer to running out; the daily one also has its own headers.
  const dayBinds = dayLeft < minuteLeft;
  res.set('RateLimit-Policy', `${row.per_minute};w=60, ${row.per_day};w=86400`);
  res.set('RateLimit-Limit', String(dayBinds ? row.per_day : row.per_minute));
  res.set('RateLimit-Remaining', String(dayBinds ? dayLeft : minuteLeft));
  res.set('RateLimit-Reset', String(dayBinds ? dayReset : minuteReset));
  res.set('X-RateLimit-Day-Limit', String(row.per_day));
  res.set('X-RateLimit-Day-Remaining', String(dayLeft));
  return { minuteReset, dayReset };
}

export async function requireApiKey(req, res, next) {
  try {
    startSync();
    const ip = req.ip || 'unknown';
    const key = keyFromHeaders(req);
    if (!key) throw new HttpError(401, 'Send your API key in the X-API-Key header', 'api_key_required');
    // An address that sent many wrong keys is blocked for a while, but a valid key already in memory still works,
    // so a shared address (an office, a cloud host) can't lock out the good keys behind it.
    const blocked = failBlockedFor(ip);
    const known = blocked && KEY_RE.test(key) ? cachedKey(key) : null;
    if (blocked && !known) {
      res.set('Retry-After', String(blocked));
      throw new HttpError(429, `Too many wrong API keys from this address. Try again in ${blocked} seconds.`, 'too_many_failures');
    }
    const row = known || (KEY_RE.test(key) ? await findKey(key) : null);
    if (!row) {
      noteFailure(ip);
      throw new HttpError(401, 'This API key is not valid', 'invalid_key');
    }
    if (row.status === 'paused') throw new HttpError(403, 'This API key is paused. Contact the marketplace team.', 'key_paused');
    if (row.status !== 'active') throw new HttpError(401, 'This API key was revoked', 'key_revoked');

    const minuteCount = minuteUsed(row.id);
    const dayCount = usedToday(row.id);
    if (dayCount >= row.per_day) {
      const { dayReset } = setLimitHeaders(res, row, minuteCount, dayCount);
      res.set('Retry-After', String(dayReset));
      throw new HttpError(429, `Daily limit reached (${row.per_day.toLocaleString('en-US')} requests a day, UTC). It resets at midnight UTC.`, 'daily_limit');
    }
    if (minuteCount >= row.per_minute) {
      const { minuteReset } = setLimitHeaders(res, row, minuteCount, dayCount);
      res.set('Retry-After', String(minuteReset));
      throw new HttpError(429, `Too many requests: this key allows ${row.per_minute} a minute. Try again in ${minuteReset} seconds.`, 'rate_limited');
    }
    count(row.id);
    setLimitHeaders(res, row, minuteCount + 1, dayCount + 1);
    req.apiKey = row;
    next();
  } catch (e) {
    next(e);
  }
}

// ── Background sync: save usage, write last_used_at, re-check cached keys ──────────────────────────

let timer = null;
let syncing = false;

function startSync() {
  if (timer) return;
  timer = setInterval(() => { syncNow().catch((e) => console.error('[api-keys] sync failed:', e.message)); }, SYNC_MS);
  timer.unref?.();
}

async function flushUsage() {
  const entries = [...unflushed];
  if (!entries.length) return;
  unflushed.clear();
  for (const [k, n] of entries) inflight.set(k, (inflight.get(k) || 0) + n);
  try {
    const ids = entries.map(([k]) => k.split('|')[0]);
    const days = entries.map(([k]) => k.split('|')[1]);
    const counts = entries.map(([, n]) => n);
    const rows = await many(
      `insert into app.api_key_usage (key_id, day, requests)
       select * from unnest($1::uuid[], $2::date[], $3::int[])
       on conflict (key_id, day) do update set requests = app.api_key_usage.requests + excluded.requests
       returning key_id, to_char(day, 'YYYY-MM-DD') as day, requests`,
      [ids, days, counts],
    );
    for (const r of rows) setBase(r.key_id, r.day, r.requests);
  } catch (e) {
    // Kept for the next round (a key that no longer exists is dropped).
    if (e?.code !== '23503') for (const [k, n] of entries) unflushed.set(k, (unflushed.get(k) || 0) + n);
    throw e;
  } finally {
    for (const [k, n] of entries) {
      const left = (inflight.get(k) || 0) - n;
      if (left > 0) inflight.set(k, left);
      else inflight.delete(k);
    }
  }
}

async function touchLastUsed() {
  const now = Date.now();
  const due = [...used].filter((id) => now - (touched.get(id) || 0) >= TOUCH_MS);
  if (!due.length) return;
  await many(`update app.api_keys set last_used_at = now() where id = any($1::uuid[]) returning id`, [due]);
  for (const id of due) { used.delete(id); touched.set(id, now); }
}

/** Keys in memory are re-read from the database, so a pause or revoke made by another API instance applies within seconds. */
async function refreshCache() {
  const entries = [...cache].filter(([, v]) => Date.now() - v.at < CACHE_MS);
  if (!entries.length) return;
  const rows = await many(`select ${AUTH_COLS} from app.api_keys k where k.id = any($1::uuid[])`, [entries.map(([, v]) => v.row.id)]);
  const byId = new Map(rows.map((r) => [r.id, r]));
  for (const [prefix, v] of entries) {
    const fresh = byId.get(v.row.id);
    if (!fresh || fresh.status !== 'active' || fresh.key_prefix !== prefix || fresh.key_hash !== v.row.key_hash) cache.delete(prefix);
    else if (cache.get(prefix) === v) v.row = fresh;
  }
}

function sweep() {
  const now = Date.now();
  const win = Math.floor(now / 60_000);
  const today = utcDay(now);
  for (const [k, v] of cache) if (now - v.at >= CACHE_MS) cache.delete(k);
  for (const [k, v] of minute) if (v.win !== win) minute.delete(k);
  for (const [k, v] of fails) if (v.win !== win) fails.delete(k);
  for (const [k, v] of usage) if (v.day !== today) usage.delete(k);
  for (const [k, t] of touched) if (now - t > 10 * TOUCH_MS && !used.has(k)) touched.delete(k);
}

/** One sync round (also used by tests through the timer). Rounds never overlap. */
export async function syncNow() {
  if (syncing) return;
  syncing = true;
  try {
    await flushUsage();
    await touchLastUsed();
    await refreshCache();
    sweep();
  } finally {
    syncing = false;
  }
}
