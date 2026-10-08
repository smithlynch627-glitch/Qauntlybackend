// Admin panel: review and manage developer API keys. Same guards as every other admin route (admin site origin,
// rate limit, admin-site session, role looked up fresh) and an audit log entry for every change.
// Admins never see a usable key: only its prefix. The contact is decrypted here and nowhere else.
import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { config } from '../config.js';
import { many, one, tx } from '../db.js';
import { HttpError, ah, bad, notFound } from '../lib/http.js';
import { requireAdminSession } from '../lib/auth.js';
import { audit, requireRole } from '../lib/admin.js';
import { decrypt } from '../lib/crypto.js';
import { CAPS, DEFAULTS, MAX_KEYS, STATUSES, UUID_RE, cleanLimits, forgetKey, localPending } from '../lib/apiKeys.js';

const r = Router();
r.use((req, _res, next) => {
  const origin = req.headers.origin;
  if (!origin || !config.adminOrigins.includes(origin)) return next(new HttpError(403, 'Admin API is only available from the admin site', 'admin_origin'));
  next();
});
r.use(rateLimit({ windowMs: 60_000, limit: 120, standardHeaders: 'draft-7', legacyHeaders: false }));
r.use(requireAdminSession);
r.use(requireRole('admin'));

const ADMIN_COLS = `k.id, k.address, k.project, k.use_case, k.website, (k.contact_enc is not null) as has_contact, k.status, k.tier,
  k.per_minute, k.per_day, k.key_prefix as prefix, k.reject_reason, k.admin_note, k.created_at, k.updated_at,
  k.approved_at, k.approved_by, k.rejected_at, k.rejected_by, k.revealed_at, k.rotated_at, k.revoked_at, k.revoked_by, k.last_used_at,
  coalesce((select u.requests from app.api_key_usage u where u.key_id = k.id and u.day = (now() at time zone 'utc')::date), 0)::int as usage_today`;
const view = (row) => ({ ...row, usage_today: row.usage_today + localPending(row.id) });
const settings = () => ({ defaults: { per_minute: DEFAULTS.perMinute, per_day: DEFAULTS.perDay }, caps: { per_minute: CAPS.perMinute, per_day: CAPS.perDay }, max_keys: MAX_KEYS });

const idParam = (v) => {
  if (!UUID_RE.test(String(v || ''))) throw notFound('API key not found');
  return String(v).toLowerCase();
};
async function load(id) {
  const row = await one(`select ${ADMIN_COLS} from app.api_keys k where k.id = $1`, [id]);
  if (!row) throw notFound('API key not found');
  return view(row);
}
function cleanNote(v) {
  if (v === undefined) return undefined;
  const s = String(v ?? '').trim();
  if (s.length > 2000) throw bad('The note can be at most 2000 characters');
  return s || null;
}
const wrongStatus = (row, want) => new HttpError(409, `This key is ${row.status}, so it can't be ${want}.`, 'wrong_status');

async function counts() {
  const rows = await many(`select status, count(*)::int as n from app.api_keys group by status`);
  const out = Object.fromEntries(STATUSES.map((s) => [s, 0]));
  for (const x of rows) out[x.status] = x.n;
  return { ...out, all: rows.reduce((a, x) => a + x.n, 0) };
}

/** List with a status filter and a search over project, wallet and key prefix. Contacts are never in lists. */
r.get('/', ah(async (req, res) => {
  const status = STATUSES.includes(String(req.query.status)) ? String(req.query.status) : '';
  const term = String(req.query.q || '').trim().toLowerCase().slice(0, 80);
  const rows = await many(
    `select ${ADMIN_COLS} from app.api_keys k
     where ($1 = '' or k.status = $1)
       and ($2 = '' or strpos(lower(k.project), $2) > 0 or strpos(k.address, $2) > 0 or strpos(lower(coalesce(k.key_prefix, '')), $2) > 0)
     order by (k.status = 'pending') desc, k.created_at desc limit 300`,
    [status, term],
  );
  res.json({ keys: rows.map(view), counts: await counts(), ...settings() });
}));

/** Counts per status (the panel shows pending requests as a badge). */
r.get('/summary', ah(async (_req, res) => res.json({ counts: await counts() })));

/** One key with its contact (decrypted) and requests per day for the last 30 days (UTC). */
r.get('/:id', ah(async (req, res) => {
  const id = idParam(req.params.id);
  const key = await load(id);
  const enc = await one(`select contact_enc from app.api_keys where id = $1`, [id]);
  const usage = await many(
    `with days as (select generate_series((now() at time zone 'utc')::date - 29, (now() at time zone 'utc')::date, interval '1 day')::date as d)
     select to_char(days.d, 'YYYY-MM-DD') as day, coalesce(u.requests, 0)::int as requests
     from days left join app.api_key_usage u on u.key_id = $1 and u.day = days.d order by days.d`,
    [id],
  );
  if (usage.length) usage[usage.length - 1].requests = key.usage_today;
  const contact = enc?.contact_enc ? decrypt(enc.contact_enc) : null;
  if (enc?.contact_enc) await audit(req, 'apikey.view_contact', id, { project: key.project });
  res.json({ key: { ...key, contact, contact_unreadable: Boolean(enc?.contact_enc && !contact) }, usage, ...settings() });
}));

/** Approve a pending request with its limits. The owner then reveals the key on the website. */
r.post('/:id/approve', ah(async (req, res) => {
  const id = idParam(req.params.id);
  const b = req.body || {};
  const note = cleanNote(b.note);
  const details = await tx(async (db) => {
    const cur = await db.one(`select id, address, status, tier, per_minute, per_day from app.api_keys where id = $1 for update`, [id]);
    if (!cur) throw notFound('API key not found');
    if (cur.status !== 'pending') throw wrongStatus(cur, 'approved');
    const lim = cleanLimits(b, cur);
    const open = await db.one(`select count(*)::int as n from app.api_keys where address = $1 and status in ('active', 'paused')`, [cur.address]);
    if (open.n >= MAX_KEYS) throw new HttpError(409, `This wallet already has ${MAX_KEYS} keys. It must revoke one first.`, 'key_limit');
    await db.q(
      `update app.api_keys set status = 'active', per_minute = $2, per_day = $3, tier = $4, admin_note = coalesce($5, admin_note),
         approved_at = now(), approved_by = $6, updated_at = now() where id = $1`,
      [id, lim.per_minute, lim.per_day, lim.tier, note ?? null, req.user],
    );
    return { address: cur.address, per_minute: lim.per_minute, per_day: lim.per_day, tier: lim.tier };
  });
  await audit(req, 'apikey.approve', id, details);
  res.json({ key: await load(id) });
}));

/** Reject a pending request. The reason is shown to the requester. */
r.post('/:id/reject', ah(async (req, res) => {
  const id = idParam(req.params.id);
  const reason = String(req.body?.reason ?? '').trim();
  if (reason.length < 3 || reason.length > 500) throw bad('Write a reason for the requester (3-500 characters)', 'invalid_reason');
  const note = cleanNote(req.body?.note);
  const row = await one(
    `update app.api_keys set status = 'rejected', reject_reason = $2, admin_note = coalesce($3, admin_note), rejected_at = now(), rejected_by = $4, updated_at = now()
     where id = $1 and status = 'pending' returning id, address`,
    [id, reason, note ?? null, req.user],
  );
  if (!row) throw wrongStatus(await load(id), 'rejected');
  await audit(req, 'apikey.reject', id, { address: row.address, reason });
  res.json({ key: await load(id) });
}));

/** pause / resume / revoke: status changes that apply to this API instance at once (others within seconds). */
const MOVES = {
  pause: { from: ['active'], to: 'paused', verb: 'paused' },
  resume: { from: ['paused'], to: 'active', verb: 'resumed' },
  revoke: { from: ['pending', 'active', 'paused'], to: 'revoked', verb: 'revoked' },
};
for (const [action, m] of Object.entries(MOVES)) {
  r.post(`/:id/${action}`, ah(async (req, res) => {
    const id = idParam(req.params.id);
    const row = await one(
      `with old as (select id, key_prefix from app.api_keys where id = $1 for update)
       update app.api_keys k set status = $3, updated_at = now(),
         revoked_at = case when $3 = 'revoked' then now() else k.revoked_at end,
         revoked_by = case when $3 = 'revoked' then $4 else k.revoked_by end
       from old where k.id = old.id and k.status = any($2::text[])
       returning old.key_prefix as prefix, k.address`,
      [id, m.from, m.to, req.user],
    );
    if (!row) throw wrongStatus(await load(id), m.verb);
    forgetKey(row.prefix);
    await audit(req, `apikey.${action}`, id, { address: row.address, prefix: row.prefix });
    res.json({ key: await load(id) });
  }));
}

/** Change limits, tier or the internal note. */
r.patch('/:id', ah(async (req, res) => {
  const id = idParam(req.params.id);
  const b = req.body || {};
  const note = cleanNote(b.note);
  const changed = await tx(async (db) => {
    const cur = await db.one(`select id, status, tier, per_minute, per_day, key_prefix from app.api_keys where id = $1 for update`, [id]);
    if (!cur) throw notFound('API key not found');
    const lim = cleanLimits(b, cur);
    const limitsChanged = lim.per_minute !== cur.per_minute || lim.per_day !== cur.per_day || lim.tier !== cur.tier;
    if (limitsChanged && !['pending', 'active', 'paused'].includes(cur.status)) throw wrongStatus(cur, 'changed');
    if (!limitsChanged && note === undefined) throw bad('Nothing to update');
    await db.q(
      `update app.api_keys set per_minute = $2, per_day = $3, tier = $4, admin_note = case when $5 then $6 else admin_note end, updated_at = now() where id = $1`,
      [id, lim.per_minute, lim.per_day, lim.tier, note !== undefined, note ?? null],
    );
    forgetKey(cur.key_prefix);
    const details = {};
    if (lim.per_minute !== cur.per_minute) details.per_minute = lim.per_minute;
    if (lim.per_day !== cur.per_day) details.per_day = lim.per_day;
    if (lim.tier !== cur.tier) details.tier = lim.tier;
    if (note !== undefined) details.note = note ? 'changed' : 'cleared';
    return details;
  });
  await audit(req, 'apikey.update', id, changed);
  res.json({ key: await load(id) });
}));

export default r;
