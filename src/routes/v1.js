// Public read-only API for developers and bots: /api/v1. Every request needs an approved API key in the
// X-API-Key header. GET only, JSON only, no CORS (keys belong on servers, never in a browser).
// Lists answer { data: [...], next } where `next` is passed back as ?cursor= (or ?after= / ?before= for activity).
// Hidden collections never appear. Numbers come from the same queries and columns the website uses.
import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { config } from '../config.js';
import { currentChainSchema, many, one } from '../db.js';
import { HttpError, addrParam, ah, bad, clampInt, notFound, tokenIdParam } from '../lib/http.js';
import { requireVisible } from '../lib/privacy.js';
import { ACTIVITY_SELECT, BEST_LISTING_JOIN, COLLECTION_COLS, TOKEN_COLS, loadCollection, loadDrop, traitCounts } from '../lib/queries.js';
import { dropState } from '../lib/drops.js';
import { limitState, requireApiKey } from '../lib/apiKeys.js';

const r = Router();

// Read-only, and never cached by a proxy (answers depend on the key).
r.use((req, res, next) => {
  res.set('Cache-Control', 'no-store');
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.set('Allow', 'GET, HEAD');
    return next(new HttpError(405, 'The public API is read-only. Use GET.', 'method_not_allowed'));
  }
  next();
});

// A key in the URL would end up in server, proxy and browser logs: refused before anything else.
const KEY_PARAMS = /^(api[_-]?key|apikey|key|x-api-key|access[_-]?token|token)$/i;
r.use((req, _res, next) => {
  if (/qk_live_/i.test(req.originalUrl || '') || Object.keys(req.query || {}).some((k) => KEY_PARAMS.test(k))) {
    return next(bad('Do not put an API key in the URL (URLs are logged). Send it in the X-API-Key header instead.', 'key_in_url'));
  }
  next();
});

// Generous backstop per IP. The real limits are per key (lib/apiKeys.js).
const ipPerMinute = (() => {
  const n = Number.parseInt(String(process.env.API_V1_IP_PER_MINUTE ?? ''), 10);
  return Number.isFinite(n) && n >= 60 ? n : 2400;
})();
r.use(rateLimit({
  windowMs: 60_000,
  limit: ipPerMinute,
  standardHeaders: false,
  legacyHeaders: false,
  handler: (req, res, next) => {
    const reset = req.rateLimit?.resetTime ? Math.ceil((req.rateLimit.resetTime.getTime() - Date.now()) / 1000) : 60;
    res.set('Retry-After', String(Math.max(1, reset)));
    next(new HttpError(429, 'Too many requests from this address', 'ip_limit'));
  },
}));

r.use(requireApiKey);

// ── Helpers ──────────────────────────────────────────────────────────────────────────────────────

const MAX_OFFSET = 10_000;
const limitOf = (req, d = 50) => clampInt(req.query.limit, 1, 100, d);
const flag = (v) => v === 'true' || v === '1';
const encode = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
function decode(v) {
  if (v === undefined || v === null || v === '') return null;
  try {
    const o = JSON.parse(Buffer.from(String(v).slice(0, 400), 'base64url').toString('utf8'));
    if (o && typeof o === 'object' && !Array.isArray(o)) return o;
  } catch {}
  throw bad('Invalid cursor. Pass back the `next` value from the previous page.', 'invalid_cursor');
}
const cursorText = (v, re) => {
  const s = String(v ?? '');
  // Times must also be real dates, so a made-up cursor is a 400 and never reaches the database.
  if (!re.test(s) || (re === TS && !Number.isFinite(Date.parse(s)))) throw bad('Invalid cursor. Pass back the `next` value from the previous page.', 'invalid_cursor');
  return s;
};
const WEI = /^\d{1,78}$/;
const HASH = /^0x[0-9a-fA-F]{1,128}$/;
const TS = /^[0-9 :.+\-TZ]{10,40}$/;
const ADDR = /^0x[0-9a-f]{40}$/;

/** { data, next }: one extra row is read to know whether another page exists. */
function page(res, rows, limit, nextOf, map = (x) => x) {
  const more = rows.length > limit;
  const data = rows.slice(0, limit);
  res.json({ data: data.map(map), next: more && data.length ? nextOf(data[data.length - 1]) : null });
}

/** Profile privacy (lib/privacy.js). API keys never act as a wallet, so hidden lists stay hidden here. */
const requirePublic = (address, what) => requireVisible(null, address, what);

// ── Key, marketplace ─────────────────────────────────────────────────────────────────────────────

r.get('/me', (req, res) => {
  const k = req.apiKey;
  const s = limitState(k);
  res.json({
    data: {
      project: k.project, status: k.status, tier: k.tier, prefix: k.key_prefix, owner: k.address,
      limits: { per_minute: s.per_minute, per_day: s.per_day },
      usage: {
        today: s.used_today, remaining_today: s.remaining_today, this_minute: s.used_this_minute,
        remaining_this_minute: s.remaining_this_minute, minute_resets_at: s.minute_resets_at, day_resets_at: s.day_resets_at,
      },
    },
  });
});

/** Same figures as the website's /api/stats. */
r.get('/stats', ah(async (_req, res) => {
  const s = await one(
    `select (select count(*) from collections)::int as collections,
            (select coalesce(sum(price_wei),0) from activity where type = 'sale' and created_at > now() - interval '24 hours') as volume_24h_wei,
            (select count(*) from activity where type = 'sale' and created_at > now() - interval '24 hours')::int as sales_24h,
            (select count(*) from activity where type = 'mint')::int as mints`,
  );
  res.json({ data: { ...s, chain_id: config.chainId, network: config.networkName, native_symbol: config.nativeSymbol, wrapped_symbol: config.wrappedSymbol } });
}));

// ── Collections ──────────────────────────────────────────────────────────────────────────────────

const COLLECTION_SORTS = {
  volume_24h: 'c.volume_24h_wei desc, c.volume_wei desc, c.address',
  volume: 'c.volume_wei desc, c.address',
  new: 'c.created_at desc, c.address',
  floor: 'c.floor_wei desc nulls last, c.address',
  sales: 'c.sales_count desc, c.address',
};

r.get('/collections', ah(async (req, res) => {
  const sort = COLLECTION_SORTS[req.query.sort] ? String(req.query.sort) : 'volume_24h';
  const limit = limitOf(req);
  const cur = decode(req.query.cursor);
  const offset = cur ? clampInt(cur.o, 0, MAX_OFFSET, 0) : 0;
  const params = [];
  const add = (v) => (params.push(v), `$${params.length}`);
  const where = ['not c.hidden'];
  if (flag(req.query.verified)) where.push('c.verified');
  if (flag(req.query.featured)) where.push('c.featured');
  if (req.query.creator) where.push(`c.creator = ${add(addrParam(req.query.creator, 'creator'))}`);
  const term = String(req.query.q || '').trim().slice(0, 64);
  if (term) where.push(`(c.name ilike ${add(`%${term.replace(/[%_\\]/g, '')}%`)} or c.symbol ilike $${params.length})`);
  const rows = await many(
    `select ${COLLECTION_COLS} from collections c where ${where.join(' and ')}
     order by ${COLLECTION_SORTS[sort]} limit ${limit + 1} offset ${offset}`,
    params,
  );
  page(res, rows, limit, () => (offset + limit <= MAX_OFFSET ? encode({ o: offset + limit }) : null));
}));

r.get('/collections/:key', ah(async (req, res) => {
  const col = await loadCollection(req.params.key);
  res.json({ data: { ...col, drop: await loadDrop(col) } });
}));

r.get('/collections/:key/tokens', ah(async (req, res) => {
  const col = await loadCollection(req.params.key);
  const limit = limitOf(req);
  const cur = decode(req.query.cursor);
  const params = [col.address];
  const add = (v) => (params.push(v), `$${params.length}`);
  const where = ['t.collection = $1', 't.owner is not null'];
  if (cur) where.push(`t.token_id > ${add(cursorText(cur.t, WEI))}`);
  if (req.query.owner) {
    const owner = addrParam(req.query.owner, 'owner');
    await requirePublic(owner, 'collected');
    where.push(`t.owner = ${add(owner)}`);
  }
  if (flag(req.query.listed)) where.push('l.hash is not null');
  const rows = await many(
    `select ${TOKEN_COLS} from tokens t ${BEST_LISTING_JOIN} where ${where.join(' and ')} order by t.token_id asc limit ${limit + 1}`,
    params,
  );
  page(res, rows, limit, (last) => encode({ t: last.token_id }));
}));

r.get('/tokens/:collection/:tokenId', ah(async (req, res) => {
  const col = await loadCollection(req.params.collection);
  const tokenId = tokenIdParam(req.params.tokenId);
  const token = await one(`select ${TOKEN_COLS} from tokens t ${BEST_LISTING_JOIN} where t.collection = $1 and t.token_id = $2`, [col.address, tokenId]);
  if (!token || !token.owner) throw notFound('Item not found');
  const [offers, traits, ranked] = await Promise.all([
    many(
      `select hash, kind, token_id::text as token_id, maker, price_wei, currency, end_time, created_at
       from orders where collection = $1 and status = 'active' and end_time > now()
         and ((kind = 'offer' and token_id = $2) or kind = 'collection_offer')
       order by price_wei desc limit 50`,
      [col.address, tokenId],
    ),
    traitCounts(col.address),
    one(`select count(*)::int as n from tokens where collection = $1 and rarity_rank is not null`, [col.address]),
  ]);
  const countOf = (type, value) => traits.find((t) => t.trait_type === type)?.values.find((v) => v.value === value)?.count ?? 0;
  const attributes = (Array.isArray(token.attributes) ? token.attributes : []).map((a) => ({ ...a, count: countOf(a.trait_type, String(a.value)) }));
  res.json({
    data: {
      ...token, attributes, rarity_of: ranked.n || null, offers,
      collection: { address: col.address, slug: col.slug, name: col.name, symbol: col.symbol, image_url: col.image_url, verified: col.verified, total_supply: col.total_supply, floor_wei: col.floor_wei },
    },
  });
}));

// ── Orders (signed EIP-712 orders, exactly as /api/orders/:hash shows them) ───────────────────────

const ORDER_SELECT = `select o.hash, o.kind, o.collection, o.token_id::text as token_id, o.maker, o.price_wei, o.currency, o.status,
  o.start_time, o.end_time, o.counter, o.created_at, o.order_json, o.created_at::text as _ts,
  c.name as collection_name, c.slug as collection_slug, t.name as token_name, t.image_url as token_image
  from orders o join collections c on c.address = o.collection
  left join tokens t on t.collection = o.collection and t.token_id = o.token_id`;
const orderOut = ({ order_json, _ts, ...o }) => ({ ...o, order: order_json?.order ?? null, signature: order_json?.signature ?? null });

async function orderList(req, res, kinds, sorts, defaultSort) {
  const sort = sorts[req.query.sort] ? String(req.query.sort) : defaultSort;
  const s = sorts[sort];
  const limit = limitOf(req);
  const cur = decode(req.query.cursor);
  const params = [kinds];
  const add = (v) => (params.push(v), `$${params.length}`);
  const where = ['o.kind = any($1)', `o.status = 'active'`, 'o.end_time > now()', 'not c.hidden'];
  if (req.query.collection) where.push(`o.collection = ${add((await loadCollection(req.query.collection)).address)}`);
  if (req.query.maker) {
    // A wallet's listings follow its "collected" setting; the offers it made follow its "activity" setting.
    const maker = addrParam(req.query.maker, 'maker');
    await requirePublic(maker, kinds.includes('listing') ? 'collected' : 'activity');
    where.push(`o.maker = ${add(maker)}`);
  }
  if (req.query.token_id !== undefined) {
    if (!req.query.collection) throw bad('token_id needs collection', 'bad_request');
    where.push(`o.token_id = ${add(tokenIdParam(req.query.token_id))}`);
  }
  if (cur) {
    const h = add(cursorText(cur.h, HASH));
    if (s.key === 'price') where.push(`(o.price_wei, o.hash) ${s.cmp} (${add(cursorText(cur.p, WEI))}::numeric, ${h})`);
    else where.push(`(o.created_at, o.hash) ${s.cmp} (${add(cursorText(cur.d, TS))}::timestamptz, ${h})`);
  }
  const rows = await many(`${ORDER_SELECT} where ${where.join(' and ')} order by ${s.order} limit ${limit + 1}`, params);
  page(res, rows, limit, (last) => encode(s.key === 'price' ? { p: last.price_wei, h: last.hash } : { d: last._ts, h: last.hash }), orderOut);
}

const NEWEST = { key: 'time', cmp: '<', order: 'o.created_at desc, o.hash desc' };
r.get('/listings', ah((req, res) => orderList(req, res, ['listing'], {
  price_asc: { key: 'price', cmp: '>', order: 'o.price_wei asc, o.hash asc' },
  newest: NEWEST,
}, 'price_asc')));

r.get('/offers', ah((req, res) => {
  const kind = String(req.query.kind || '');
  const kinds = kind === 'offer' || kind === 'collection_offer' ? [kind] : ['offer', 'collection_offer'];
  return orderList(req, res, kinds, {
    price_desc: { key: 'price', cmp: '<', order: 'o.price_wei desc, o.hash desc' },
    newest: NEWEST,
  }, 'price_desc');
}));

// ── Activity ─────────────────────────────────────────────────────────────────────────────────────

// Public names → stored types. `cancel` covers cancelled listings (delist) and cancelled offers.
const TYPE_GROUPS = {
  sale: ['sale'], mint: ['mint'], transfer: ['transfer'], list: ['list'], delist: ['delist'],
  offer: ['offer', 'collection_offer'], collection_offer: ['collection_offer'], offer_cancel: ['offer_cancel'], cancel: ['delist', 'offer_cancel'],
};
const activityOut = ({ art_style, token_attributes, collection_image, ...a }) => a;
const sleep = (ms) => new Promise((ok) => setTimeout(ok, ms));

/**
 * The highest activity id that can be handed to a poller: every id up to it is either saved or will never exist.
 * Ids come from a sequence before the row is saved, so a row with a lower id can still be on its way while a higher
 * one is already visible. Any insert holds a write lock on the table until it is saved, so: read the sequence, then
 * check that nobody holds a write lock. If someone does, try again briefly, else use the last value known to be safe.
 */
const settled = new Map(); // chain schema -> { id, at, samples }
async function settledActivityId() {
  const schema = currentChainSchema() || 'none';
  let s = settled.get(schema);
  if (!s) settled.set(schema, (s = { id: 0, at: 0, samples: [] }));
  if (Date.now() - s.at < 1000) return s.id;
  for (let i = 0; i < 5; i++) {
    const seq = await one(`select case when is_called then last_value else 0 end as v from activity_id_seq`);
    const v = Number(seq?.v || 0);
    let writers;
    try {
      writers = (await one(
        `select count(*)::int as n from pg_locks
         where locktype = 'relation' and database = (select oid from pg_database where datname = current_database())
           and relation = 'activity'::regclass and pid <> pg_backend_pid()
           and mode in ('RowExclusiveLock', 'ShareRowExclusiveLock', 'ExclusiveLock', 'AccessExclusiveLock')`,
      )).n;
    } catch {
      // No access to pg_locks: fall back to sequence values seen at least 5 seconds ago.
      const now = Date.now();
      s.samples = [...s.samples.filter((x) => now - x.at < 120_000), { at: now, v }];
      const old = s.samples.filter((x) => now - x.at >= 5_000).pop();
      if (old) s.id = Math.max(s.id, old.v);
      s.at = now;
      return s.id;
    }
    if (writers === 0) {
      s.id = Math.max(s.id, v);
      s.at = Date.now();
      return s.id;
    }
    await sleep(25 * (i + 1));
  }
  return s.id;
}

async function activityFeed(req, res, extra = null) {
  const limit = limitOf(req);
  const params = [];
  const add = (v) => (params.push(v), `$${params.length}`);
  const where = ['not c.hidden'];
  if (extra) where.push(extra(add));
  if (req.query.collection) where.push(`a.collection = ${add((await loadCollection(req.query.collection)).address)}`);
  if (req.query.token_id !== undefined) {
    if (!req.query.collection) throw bad('token_id needs collection', 'bad_request');
    where.push(`a.token_id = ${add(tokenIdParam(req.query.token_id))}`);
  }
  const wanted = String(req.query.type || req.query.types || '').split(',').map((t) => t.trim()).filter(Boolean);
  if (wanted.length) {
    const unknown = wanted.find((t) => !TYPE_GROUPS[t]);
    if (unknown) throw bad(`Unknown activity type "${unknown.slice(0, 30)}". Use ${Object.keys(TYPE_GROUPS).join(', ')}.`, 'invalid_type');
    where.push(`a.type = any(${add([...new Set(wanted.flatMap((t) => TYPE_GROUPS[t]))])})`);
  }
  if (req.query.since) {
    const t = Date.parse(String(req.query.since));
    if (!Number.isFinite(t)) throw bad('since must be a date and time, e.g. 2026-10-01T00:00:00Z', 'invalid_since');
    where.push(`a.created_at >= ${add(new Date(t).toISOString())}::timestamptz`);
  }
  const idOf = (v, name) => {
    if (!/^\d{1,15}$/.test(String(v))) throw bad(`${name} must be an activity id (a whole number)`, 'invalid_cursor');
    return Number(v);
  };

  if (req.query.after !== undefined) {
    // Forward feed for bots: oldest first, only events that can no longer be overtaken by a lower id.
    const horizon = await settledActivityId();
    const after = req.query.after === 'latest' ? horizon : idOf(req.query.after, 'after');
    where.push(`a.id > ${add(after)}`, `a.id <= ${add(horizon)}`);
    const rows = await many(`${ACTIVITY_SELECT} where ${where.join(' and ')} order by a.id asc limit ${limit + 1}`, params);
    const more = rows.length > limit;
    const data = rows.slice(0, limit);
    // Everything up to the horizon has been seen when there is no further page, so the cursor can jump there.
    const next = more ? data[data.length - 1].id : Math.max(after, horizon);
    return res.json({ data: data.map(activityOut), next: String(next), has_more: more });
  }

  // Browsing: newest first, older pages with ?before=<next> (or ?cursor=<next>, like every other list).
  const before = req.query.before ?? req.query.cursor;
  if (before !== undefined) where.push(`a.id < ${add(idOf(before, req.query.before !== undefined ? 'before' : 'cursor'))}`);
  const rows = await many(`${ACTIVITY_SELECT} where ${where.join(' and ')} order by a.id desc limit ${limit + 1}`, params);
  page(res, rows, limit, (last) => String(last.id), activityOut);
}

r.get('/activity', ah((req, res) => activityFeed(req, res)));

// ── Drops (launchpad) ────────────────────────────────────────────────────────────────────────────

const publicPhases = (phases) => (phases || []).map(({ allowlistId, merkleRoot, ...p }) => ({ ...p, hasAllowlist: Boolean(merkleRoot && !/^0x0+$/.test(merkleRoot)) }));
const DROP_ORDER = { live: 0, upcoming: 1, sold_out: 2, ended: 3 };

r.get('/drops', ah(async (req, res) => {
  const rows = await many(
    `select ${COLLECTION_COLS}, d.phases, d.platform_fee_bps, d.featured as drop_featured
     from drops d join collections c on c.address = d.collection where not c.hidden and not c.drop_hidden
     order by d.featured desc, c.featured desc, c.created_at desc, c.address limit 500`,
  );
  let drops = rows.map(({ phases, platform_fee_bps, drop_featured, ...collection }) => ({
    collection, featured: drop_featured, platformFeeBps: platform_fee_bps,
    ...dropState(publicPhases(phases), collection.total_supply, collection.max_supply),
  }));
  const status = String(req.query.status || '');
  if (status) {
    if (!['live', 'upcoming', 'ended', 'sold_out'].includes(status)) throw bad('status must be live, upcoming, ended or sold_out', 'bad_request');
    drops = drops.filter((d) => (status === 'ended' ? ['ended', 'sold_out'].includes(d.status) : d.status === status));
  }
  drops.sort((a, b) => DROP_ORDER[a.status] - DROP_ORDER[b.status] || Number(b.featured) - Number(a.featured));
  const limit = limitOf(req);
  const cur = decode(req.query.cursor);
  const offset = cur ? clampInt(cur.o, 0, MAX_OFFSET, 0) : 0;
  const slice = drops.slice(offset, offset + limit + 1);
  page(res, slice, limit, () => encode({ o: offset + limit }));
}));

// ── Wallets (respect profile privacy) ────────────────────────────────────────────────────────────

r.get('/users/:address/tokens', ah(async (req, res) => {
  const address = addrParam(req.params.address);
  await requirePublic(address, 'collected');
  const limit = limitOf(req);
  const cur = decode(req.query.cursor);
  const params = [address];
  const add = (v) => (params.push(v), `$${params.length}`);
  const where = ['t.owner = $1', 'not c.hidden'];
  if (req.query.collection) where.push(`t.collection = ${add((await loadCollection(req.query.collection)).address)}`);
  if (cur) where.push(`(t.collection, t.token_id) > (${add(cursorText(cur.c, ADDR))}, ${add(cursorText(cur.t, WEI))}::numeric)`);
  const rows = await many(
    `select ${TOKEN_COLS}, c.name as collection_name, c.slug as collection_slug
     from tokens t ${BEST_LISTING_JOIN} join collections c on c.address = t.collection
     where ${where.join(' and ')} order by t.collection asc, t.token_id asc limit ${limit + 1}`,
    params,
  );
  page(res, rows, limit, (last) => encode({ c: last.collection, t: last.token_id }));
}));

r.get('/users/:address/activity', ah(async (req, res) => {
  const address = addrParam(req.params.address);
  await requirePublic(address, 'activity');
  await activityFeed(req, res, (add) => { const a = add(address); return `(a.from_addr = ${a} or a.to_addr = ${a})`; });
}));

r.use((_req, _res, next) => next(new HttpError(404, 'Unknown API route. See the API documentation for the list of routes.', 'not_found')));

export default r;
