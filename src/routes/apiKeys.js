// Developer API keys, as their owner sees them on the website: request a key, reveal it once, rotate or revoke it.
// Signed-in wallets only, from the website only, and only ever the caller's own keys.
// The key itself is returned exactly twice in its life at most: on reveal, and on each rotate (a new key).
import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { config } from '../config.js';
import { many, one, tx } from '../db.js';
import { HttpError, ah, bad, notFound } from '../lib/http.js';
import { requireAuth } from '../lib/auth.js';
import { audit } from '../lib/admin.js';
import { encrypt } from '../lib/crypto.js';
import {
  DEFAULTS, MAX_KEYS, UUID_RE, cleanContact, cleanProject, cleanUseCase, cleanWebsite, forgetKey, localPending, withNewKey,
} from '../lib/apiKeys.js';

const r = Router();
r.use((req, _res, next) => {
  const origin = String(req.headers.origin || '').replace(/\/+$/, '').toLowerCase();
  if (!config.corsOrigins.includes(origin)) return next(new HttpError(403, `Manage API keys on the ${config.brand} website`, 'origin'));
  next();
});
r.use(requireAuth);

const perWallet = (windowMs, limit) => rateLimit({ windowMs, limit, keyGenerator: (req) => req.user, standardHeaders: 'draft-7', legacyHeaders: false });
const requestLimit = perWallet(3600_000, 10);
const actionLimit = perWallet(60_000, 10);

// Owner actions are kept in the admin activity log too, without the visitor's IP address.
const ownerAudit = (req, action, id, details) => audit({ user: req.user, ip: null }, action, id, details);

const OWNER_COLS = `k.id, k.project, k.use_case, k.website, (k.contact_enc is not null) as has_contact, k.status, k.tier,
  k.key_prefix as prefix, k.per_minute, k.per_day, k.reject_reason, k.created_at, k.approved_at, k.rejected_at,
  k.revealed_at, k.rotated_at, k.revoked_at, k.last_used_at,
  coalesce((select u.requests from app.api_key_usage u where u.key_id = k.id and u.day = (now() at time zone 'utc')::date), 0)::int as usage_today`;

function ownerView(row) {
  const open = ['active', 'paused'].includes(row.status);
  return {
    ...row,
    usage_today: row.usage_today + localPending(row.id),
    can_reveal: row.status === 'active' && !row.revealed_at,
    can_rotate: open && Boolean(row.revealed_at),
    can_revoke: open || row.status === 'pending',
  };
}

const idParam = (v) => {
  if (!UUID_RE.test(String(v || ''))) throw notFound('API key not found');
  return String(v).toLowerCase();
};
async function ownKey(id, address) {
  const row = await one(`select ${OWNER_COLS} from app.api_keys k where k.id = $1 and k.address = $2`, [id, address]);
  if (!row) throw notFound('API key not found');
  return ownerView(row);
}

/** Why a reveal / rotate / revoke changed nothing, as an error the website can show. */
function refusal(key, action) {
  if (key.status === 'pending') return new HttpError(409, 'This request has not been approved yet', 'not_approved');
  if (key.status === 'rejected') return new HttpError(409, 'This request was not approved', 'key_closed');
  if (key.status === 'revoked') return new HttpError(409, 'This key was revoked', 'key_closed');
  if (action === 'reveal' && key.revealed_at) return new HttpError(409, 'This key was already shown once. Replace the key to get a new one.', 'already_revealed');
  if (action === 'reveal' && key.status === 'paused') return new HttpError(409, 'This key is paused. Contact the marketplace team.', 'key_paused');
  if (action === 'rotate' && !key.revealed_at) return new HttpError(409, 'Reveal the key first', 'not_revealed');
  return new HttpError(409, 'Nothing changed. Reload and try again.', 'conflict');
}

const SHOWN_ONCE = 'Copy this key now and keep it on your server. It is shown only once: if you lose it, replace the key to get a new one.';

/** My requests and keys, newest first. */
r.get('/', ah(async (req, res) => {
  const rows = await many(`select ${OWNER_COLS} from app.api_keys k where k.address = $1 order by k.created_at desc limit 50`, [req.user]);
  res.json({
    keys: rows.map(ownerView),
    limits: { max_pending: 1, max_keys: MAX_KEYS, default_per_minute: DEFAULTS.perMinute, default_per_day: DEFAULTS.perDay },
    contact_enabled: Boolean(config.encryptionKey),
  });
}));

/** Ask for a key. An admin reviews it; nothing is generated until it is approved and revealed. */
r.post('/', requestLimit, ah(async (req, res) => {
  const b = req.body || {};
  const project = cleanProject(b.project);
  const useCase = cleanUseCase(b.useCase ?? b.use_case);
  const website = cleanWebsite(b.website);
  const contact = cleanContact(b.contact);
  let contactEnc = null;
  if (contact) {
    contactEnc = encrypt(contact);
    // Never stored in plain text: without an encryption key on the server the field is refused.
    if (!contactEnc) throw bad('Contact details cannot be saved right now because encryption is not set up on the server. Leave the contact field empty and send the request again.', 'contact_unavailable');
  }
  const id = await tx(async (db) => {
    // One request at a time per wallet (also enforced by a unique index), and at most MAX_KEYS usable keys.
    await db.q(`select pg_advisory_xact_lock(hashtext('api_keys:' || $1))`, [req.user]);
    const c = await db.one(
      `select count(*) filter (where status = 'pending')::int as pending, count(*) filter (where status in ('active', 'paused'))::int as keys
       from app.api_keys where address = $1`,
      [req.user],
    );
    if (c.pending) throw new HttpError(409, 'You already have a request waiting for review', 'pending_exists');
    if (c.keys >= MAX_KEYS) throw new HttpError(409, `You already have ${MAX_KEYS} keys. Revoke one before asking for another.`, 'key_limit');
    const row = await db.one(
      `insert into app.api_keys (address, project, use_case, website, contact_enc, per_minute, per_day)
       values ($1,$2,$3,$4,$5,$6,$7) returning id`,
      [req.user, project, useCase, website, contactEnc, DEFAULTS.perMinute, DEFAULTS.perDay],
    );
    return row.id;
  }).catch((e) => {
    if (e?.code === '23505') throw new HttpError(409, 'You already have a request waiting for review', 'pending_exists');
    throw e;
  });
  res.status(201).json({ key: await ownKey(id, req.user) });
}));

/** Creates the key and returns it this one time. Only the hash and the prefix are stored. */
r.post('/:id/reveal', actionLimit, ah(async (req, res) => {
  const id = idParam(req.params.id);
  const out = await withNewKey(({ prefix, hash }) => one(
    `update app.api_keys set key_prefix = $3, key_hash = $4, revealed_at = now(), updated_at = now()
     where id = $1 and address = $2 and status = 'active' and key_hash is null and revealed_at is null returning id`,
    [id, req.user, prefix, hash],
  ));
  if (!out) throw refusal(await ownKey(id, req.user), 'reveal');
  await ownerAudit(req, 'apikey.reveal', id, { prefix: out.prefix });
  res.set('Cache-Control', 'no-store');
  res.json({ secret: out.key, key: await ownKey(id, req.user), warning: SHOWN_ONCE });
}));

/** New key, returned once; the old one stops working immediately. */
r.post('/:id/rotate', actionLimit, ah(async (req, res) => {
  const id = idParam(req.params.id);
  const out = await withNewKey(({ prefix, hash }) => one(
    `with old as (select id, key_prefix from app.api_keys where id = $1 and address = $2 for update)
     update app.api_keys k set key_prefix = $3, key_hash = $4, rotated_at = now(), updated_at = now()
     from old where k.id = old.id and k.status in ('active', 'paused') and k.key_hash is not null
     returning old.key_prefix as old_prefix`,
    [id, req.user, prefix, hash],
  ));
  if (!out) throw refusal(await ownKey(id, req.user), 'rotate');
  forgetKey(out.row.old_prefix);
  await ownerAudit(req, 'apikey.rotate', id, { old_prefix: out.row.old_prefix, prefix: out.prefix });
  res.set('Cache-Control', 'no-store');
  res.json({ secret: out.key, key: await ownKey(id, req.user), warning: SHOWN_ONCE });
}));

/** Revoke a key (or withdraw a request). Final: a revoked key can't be turned back on. */
r.post('/:id/revoke', actionLimit, ah(async (req, res) => {
  const id = idParam(req.params.id);
  const row = await one(
    `with old as (select id, key_prefix from app.api_keys where id = $1 and address = $2 for update)
     update app.api_keys k set status = 'revoked', revoked_at = now(), revoked_by = $2, updated_at = now()
     from old where k.id = old.id and k.status in ('pending', 'active', 'paused')
     returning old.key_prefix as prefix`,
    [id, req.user],
  );
  if (!row) throw refusal(await ownKey(id, req.user), 'revoke');
  forgetKey(row.prefix);
  await ownerAudit(req, 'apikey.revoke', id, { prefix: row.prefix, by: 'owner' });
  res.json({ key: await ownKey(id, req.user) });
}));

export default r;
