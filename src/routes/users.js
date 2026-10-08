import { Router } from 'express';
import { many, one } from '../db.js';
import { addrParam, ah, bad, clampInt } from '../lib/http.js';
import { optionalAuth, requireAuth } from '../lib/auth.js';
import { BEST_LISTING_JOIN, COLLECTION_COLS, TOKEN_COLS } from '../lib/queries.js';
import { isSelf, noSharedCache, privacyOf, requireVisible } from '../lib/privacy.js';

const r = Router();
r.use(noSharedCache);

const ORDER_SELECT = `select o.hash, o.kind, o.collection, o.token_id::text as token_id, o.maker, o.price_wei, o.currency,
  o.end_time, o.created_at, c.name as collection_name, c.slug as collection_slug, c.art_style,
  t.name as token_name, t.image_url as token_image, t.attributes as token_attributes
  from orders o join collections c on c.address = o.collection
  left join tokens t on t.collection = o.collection and t.token_id = o.token_id`;

r.put('/me', requireAuth, ah(async (req, res) => {
  const username = req.body?.username ? String(req.body.username).trim() : null;
  const bio = String(req.body?.bio || '').slice(0, 280);
  // Plain letters only (no look-alike characters from other alphabets), and nothing that looks like a wallet address.
  if (username && !/^[A-Za-z0-9_.-]{3,24}$/.test(username)) throw bad('Username must be 3–24 letters (a–z), numbers, _ . or -');
  if (username && /^0x/i.test(username)) throw bad('Usernames cannot start with 0x, so nobody can pass for a wallet address');
  try {
    const u = await one(
      `insert into app.users (address, username, bio) values ($1,$2,$3)
       on conflict (address) do update set username = excluded.username, bio = excluded.bio
       returning address, username, bio, created_at`,
      [req.user, username, bio],
    );
    res.json({ user: u });
  } catch (e) {
    if (e.code === '23505') throw bad('That username is taken');
    throw e;
  }
}));

/**
 * Profile privacy. Each switch is optional, so the page can flip one without knowing the other.
 * Only the signed-in wallet can change its own settings.
 */
r.put('/me/privacy', requireAuth, ah(async (req, res) => {
  const b = req.body || {};
  const flag = (k) => {
    if (!(k in b)) return null;
    if (typeof b[k] !== 'boolean') throw bad(`${k} must be true or false`);
    return b[k];
  };
  const hideCollected = flag('hideCollected');
  const hideActivity = flag('hideActivity');
  if (hideCollected === null && hideActivity === null) throw bad('Nothing to change');
  try {
    const u = await one(
      `insert into app.users (address, hide_collected, hide_activity) values ($1, coalesce($2, false), coalesce($3, false))
       on conflict (address) do update set
         hide_collected = coalesce($2, app.users.hide_collected),
         hide_activity = coalesce($3, app.users.hide_activity)
       returning hide_collected, hide_activity`,
      [req.user, hideCollected, hideActivity],
    );
    res.json({ privacy: u });
  } catch (e) {
    if (e.code === '42703') throw bad('Profile privacy is not set up on this server yet. Run backend/db/09_profile_privacy.sql.', 'privacy_unavailable');
    throw e;
  }
}));

r.get('/:address', optionalAuth, ah(async (req, res) => {
  const address = addrParam(req.params.address);
  const [user, counts, privacy] = await Promise.all([
    one(`select address, username, bio, created_at from app.users where address = $1`, [address]),
    one(
      `select (select count(*) from tokens where owner = $1)::int as owned,
              (select count(*) from orders where maker = $1 and kind = 'listing' and status = 'active')::int as listed,
              (select count(*) from orders where maker = $1 and kind <> 'listing' and status = 'active')::int as offers_made`,
      [address],
    ),
    privacyOf(address),
  ]);
  // Hidden lists also hide their counts for everyone except the wallet itself.
  const self = isSelf(req, address);
  if (!self && privacy.hide_collected) { counts.owned = null; counts.listed = null; }
  if (!self && privacy.hide_activity) counts.offers_made = null;
  const created = await many(`select ${COLLECTION_COLS} from collections c where c.creator = $1 and not c.hidden order by c.created_at desc limit 50`, [address]);
  res.json({ user: user || { address, username: null, bio: '' }, counts, collections: created, privacy, self });
}));

r.get('/:address/tokens', optionalAuth, ah(async (req, res) => {
  const address = addrParam(req.params.address);
  await requireVisible(req, address, 'collected');
  const limit = clampInt(req.query.limit, 1, 100, 60);
  const offset = clampInt(req.query.offset, 0, 1_000_000, 0);
  const rows = await many(
    `select ${TOKEN_COLS}, c.name as collection_name, c.slug as collection_slug, c.art_style, c.tradable, c.is_official, c.total_supply as collection_supply, count(*) over() as total_count
     from tokens t ${BEST_LISTING_JOIN} join collections c on c.address = t.collection
     where t.owner = $1 and not c.hidden order by t.minted_at desc, t.token_id asc limit ${limit} offset ${offset}`,
    [address],
  );
  res.json({ tokens: rows.map(({ total_count, ...t }) => t), total: rows[0]?.total_count ?? 0 });
}));

r.get('/:address/listings', optionalAuth, ah(async (req, res) => {
  const address = addrParam(req.params.address);
  await requireVisible(req, address, 'collected');
  res.json({ orders: await many(`${ORDER_SELECT} where o.maker = $1 and o.kind = 'listing' and o.status = 'active' order by o.created_at desc limit 200`, [address]) });
}));

r.get('/:address/offers-made', optionalAuth, ah(async (req, res) => {
  const address = addrParam(req.params.address);
  await requireVisible(req, address, 'activity');
  res.json({ orders: await many(`${ORDER_SELECT} where o.maker = $1 and o.kind <> 'listing' and o.status = 'active' order by o.created_at desc limit 200`, [address]) });
}));

r.get('/:address/offers-received', optionalAuth, ah(async (req, res) => {
  const address = addrParam(req.params.address);
  await requireVisible(req, address, 'collected');
  const orders = await many(
    `${ORDER_SELECT}
     where o.status = 'active' and o.maker <> $1 and (
       (o.kind = 'offer' and t.owner = $1) or
       (o.kind = 'collection_offer' and exists (select 1 from tokens x where x.collection = o.collection and x.owner = $1)))
     order by o.price_wei desc limit 200`,
    [address],
  );
  res.json({ orders });
}));

export default r;
