// Profile privacy: a wallet can hide its collected items (with its listings and offers received) and its
// activity (with the offers it made) on Quantly's pages and in the public API. The wallet itself, signed in,
// still sees everything. This only covers Quantly: the blockchain and its explorers stay public.
import { one } from '../db.js';
import { HttpError } from './http.js';

const PUBLIC = Object.freeze({ hide_collected: false, hide_activity: false });

/** The wallet's settings. A database without the columns yet (09_profile_privacy.sql not run) counts as public. */
export async function privacyOf(address) {
  const u = await one(
    `select coalesce((to_jsonb(u) ->> 'hide_collected')::boolean, false) as hide_collected,
            coalesce((to_jsonb(u) ->> 'hide_activity')::boolean, false) as hide_activity
     from app.users u where u.address = $1`,
    [address],
  );
  return u || PUBLIC;
}

/** Answers that can differ per signed-in wallet must never be stored by a shared cache or proxy. */
export function noSharedCache(_req, res, next) {
  res.set('Cache-Control', 'private, no-store');
  res.vary('Authorization');
  next();
}

/** True when the signed-in wallet is the profile's own wallet (it always sees its own lists). */
export const isSelf = (req, address) => Boolean(req?.user) && req.user === address;

/** Throws 403 "private" unless that list is public or the request comes from the wallet itself. */
export async function requireVisible(req, address, what) {
  if (isSelf(req, address)) return;
  const p = await privacyOf(address);
  if (what === 'collected' && p.hide_collected) throw new HttpError(403, 'This wallet keeps its collected items private', 'private');
  if (what === 'activity' && p.hide_activity) throw new HttpError(403, 'This wallet keeps its activity private', 'private');
}
