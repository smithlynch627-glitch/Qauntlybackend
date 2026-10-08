import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { connectedXLink, xReady } from './x.js';
import { StandardMerkleTree } from '@openzeppelin/merkle-tree';
import { config } from '../config.js';
import { many, one, tx } from '../db.js';
import { HttpError, addrParam, ah, bad, clampInt, forbidden } from '../lib/http.js';
import { requireAuth } from '../lib/auth.js';
import { COLLECTION_COLS, loadCollection, loadDrop } from '../lib/queries.js';
import { dropState } from '../lib/drops.js';
import { collectionContract, isLaunchpadCollection } from '../lib/chain.js';
import { maybeRepair, metadataQueueSize, phaseTxContext, queueMetadata, syncCollectionFromChain } from '../indexer/core.js';
import { cleanAbout, cleanAboutItems, cleanGallery, cleanMediaLink, cleanText, galleryReady } from '../lib/collectionMedia.js';

const r = Router();
const publicPhases = (phases) => phases.map(({ allowlistId, merkleRoot, ...p }) => ({ ...p, hasAllowlist: Boolean(merkleRoot && !/^0x0+$/.test(merkleRoot)) }));

r.get('/', ah(async (req, res) => {
  const rows = await many(
    `select ${COLLECTION_COLS}, d.phases, d.platform_fee_bps, d.featured
     from drops d join collections c on c.address = d.collection where not c.hidden and not c.drop_hidden
     order by d.featured desc, c.featured desc, c.created_at desc limit 200`,
  );
  const order = { live: 0, upcoming: 1, sold_out: 2, ended: 3 };
  let drops = rows.map(({ phases, platform_fee_bps, featured, ...collection }) => ({
    collection, featured, platformFeeBps: platform_fee_bps,
    ...dropState(publicPhases(phases), collection.total_supply, collection.max_supply),
  }));
  const status = String(req.query.status || '');
  if (status) drops = drops.filter((d) => (status === 'ended' ? ['ended', 'sold_out'].includes(d.status) : d.status === status));
  drops.sort((a, b) => order[a.status] - order[b.status] || Number(b.featured) - Number(a.featured));
  res.json({ drops: drops.slice(0, clampInt(req.query.limit, 1, 100, 50)) });
}));

r.get('/:key', ah(async (req, res) => {
  const col = await loadCollection(req.params.key);
  maybeRepair(col);
  const drop = await loadDrop(col);
  if (!drop) throw bad('This collection has no launchpad drop', 'no_drop');
  res.json({ collection: col, drop });
}));

/** Allowlist eligibility + Merkle proof per phase. Mint counts and prices are read from the contract by the UI. */
r.get('/:key/eligibility/:wallet', ah(async (req, res) => {
  const col = await loadCollection(req.params.key);
  const wallet = addrParam(req.params.wallet, 'wallet');
  const d = await one(`select phases from drops where collection = $1`, [col.address]);
  if (!d) throw bad('No drop');
  const out = [];
  for (const [index, p] of d.phases.entries()) {
    const gated = p.merkleRoot && !/^0x0+$/.test(p.merkleRoot);
    let eligible = !gated;
    let proof = [];
    if (gated && p.allowlistId) {
      const al = await one(`select tree from allowlists where id = $1`, [p.allowlistId]);
      if (al) {
        const tree = StandardMerkleTree.load(al.tree);
        if (tree.root.toLowerCase() === p.merkleRoot) {
          for (const [i, v] of tree.entries()) {
            if (String(v[0]).toLowerCase() === wallet) { eligible = true; proof = tree.getProof(i); break; }
          }
        }
      }
    }
    out.push({ index, eligible, proof, hasAllowlist: gated });
  }
  res.json({ phases: out });
}));

/** Creates an allowlist and returns its Merkle root (StandardMerkleTree, leaf = address). */
r.post('/allowlists', requireAuth, ah(async (req, res) => {
  const list = [...new Set((req.body?.addresses || []).map((a) => String(a).trim().toLowerCase()).filter(Boolean))];
  if (!list.length) throw bad('Add at least one wallet address');
  if (list.length > 20000) throw bad('Allowlists are limited to 20,000 wallets');
  const invalid = list.find((a) => !/^0x[0-9a-f]{40}$/.test(a));
  if (invalid) throw bad(`Invalid address in allowlist: ${invalid}`);
  const tree = StandardMerkleTree.of(list.map((a) => [a]), ['address']);
  const row = await one(
    `insert into allowlists (root, addresses, tree, created_by) values ($1,$2,$3,$4) returning id, root`,
    [tree.root.toLowerCase(), JSON.stringify(list), JSON.stringify(tree.dump()), req.user],
  );
  res.json({ id: row.id, root: row.root, count: list.length });
}));

/**
 * Registers display details for a launchpad collection (text, images, links, phase names, allowlists).
 * Only the on-chain owner can do this. Prices, times, limits and roots always come from the contract.
 * Images: logo (imageUrl), banner (bannerUrl) and up to three extra images (gallery) for the mint page.
 * About tab: story (about), its picture (aboutImageUrl) and up to 12 detail rows (aboutItems).
 */
r.post('/', requireAuth, ah(async (req, res) => {
  const b = req.body || {};
  const address = addrParam(b.collection, 'collection');
  if (!(await isLaunchpadCollection(address))) throw bad('This contract was not created by the launchpad');
  const owner = String(await collectionContract(address).owner()).toLowerCase();
  if (owner !== req.user) throw forbidden('Only the collection owner can edit this drop');

  await syncCollectionFromChain(address, owner, undefined, await phaseTxContext(address, b.txHash));
  // The X link is never typed: it is the owner's connected X account (Create / Studio → Connect X).
  if ('twitter' in b && xReady()) {
    b.twitter = await connectedXLink(req.user);
    if (!b.twitter) throw bad('Connect your X account first (Create → Details → Connect X).');
  }
  const page = await pageFields(b);
  const names = phaseNames(b.phases);

  // Everything is checked before anything is written, and both tables change together or not at all.
  const d = await one(`select phases from drops where collection = $1`, [address]);
  const phases = d.phases;
  const open = (p) => !p.merkleRoot || /^0x0+$/.test(p.merkleRoot);
  for (const [i, meta] of names.slice(0, phases.length).entries()) {
    if (meta.name) phases[i].name = meta.name;
    // "Public" is reserved for the last phase, which is open to everyone.
    if (/^public$/i.test(phases[i].name) && !(i === phases.length - 1 && open(phases[i]))) phases[i].name = `Phase ${i + 1}`;
    if (meta.allowlistId) {
      const al = await one(`select root from allowlists where id = $1`, [meta.allowlistId]);
      if (!al || al.root.toLowerCase() !== phases[i].merkleRoot) throw bad(`Phase ${i + 1}: allowlist does not match the on-chain root`);
      phases[i].allowlistId = meta.allowlistId;
    }
  }
  const last = phases[phases.length - 1];
  if (last && open(last)) last.name = 'Public';
  await tx(async (h) => {
    if (page.sets.length) await h.q(`update collections set ${page.sets.join(', ')} where address = $1`, [address, ...page.params]);
    await h.q(`update drops set phases = $2 where collection = $1`, [address, JSON.stringify(phases)]);
  });
  res.json({ collection: await loadCollection(address), ...(page.warnings.length ? { warnings: page.warnings } : {}) });
}));

/**
 * Checks the page details of a collection without saving anything. The Create page calls this before the
 * deploy transaction, so a link the API would refuse is found while it can still be fixed for free.
 */
r.post('/check', requireAuth, ah(async (req, res) => {
  const b = req.body || {};
  delete b.twitter; // set by the API from the connected X account, never typed
  await pageFields(b);
  phaseNames(b.phases);
  res.json({ ok: true });
}));

/**
 * The page details in a request, checked and ready to save: `sets` are "column = $n" pieces (numbered from $2,
 * $1 is the collection address) and `params` their values. Only the fields that were sent are changed, because
 * the Studio saves one section at a time. Nothing here touches the database except the gallery-column lookup.
 */
async function pageFields(b) {
  const sets = [];
  const params = [];
  const warnings = [];
  const set = (col, val) => { params.push(val); sets.push(`${col} = $${params.length + 1}`); };
  if ('description' in b) set('description', cleanText(b.description, 2000));
  // A collection always keeps a logo: an empty logo field changes nothing.
  if ('imageUrl' in b && String(b.imageUrl ?? '').trim()) set('image_url', cleanMediaLink(b.imageUrl, 'Logo'));
  if ('bannerUrl' in b) set('banner_url', cleanMediaLink(b.bannerUrl, 'Banner'));
  for (const [k, col] of [['twitter', 'twitter'], ['website', 'website'], ['discord', 'discord'], ['telegram', 'telegram']]) {
    if (k in b) set(col, safeLink(b[k]));
  }
  // Extra images need the gallery column (db/setup_all.sql). Without it the rest is still saved (a new collection
  // must never lose its details over this) and the reply says the extra images were skipped.
  if ('gallery' in b) {
    const gallery = cleanGallery(b.gallery);
    if (await galleryReady()) set('gallery', JSON.stringify(gallery));
    else if (gallery.length) warnings.push('gallery_not_ready');
  }
  if ('about' in b) set('about', cleanAbout(b.about));
  if ('aboutImageUrl' in b) set('about_image_url', cleanMediaLink(b.aboutImageUrl, 'About image'));
  if ('aboutItems' in b) set('about_items', JSON.stringify(cleanAboutItems(b.aboutItems)));
  return { sets, params, warnings };
}

/** Phase display names and allowlist ids sent with the page details: a list of at most 20 small objects. */
function phaseNames(list) {
  if (list === undefined || list === null) return [];
  if (!Array.isArray(list) || list.length > 20) throw bad('Phases must be a list');
  return list.map((m, i) => {
    const id = m?.allowlistId ?? null;
    if (id !== null && !(typeof id === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id))) throw bad(`Phase ${i + 1}: allowlist not found`);
    return { name: typeof m?.name === 'string' ? cleanText(m.name, 100).trim().slice(0, 32) : '', allowlistId: id };
  });
}

/** Social / website links: https only (no javascript:, data: or plain http links on the collection page). */
function safeLink(v) {
  if (!v) return null;
  let s = String(v).trim();
  if (!s) return null;
  if (/^http:\/\//i.test(s)) s = `https://${s.slice(7)}`; // upgrade plain http
  else if (/^(www\.)?[a-z0-9-]+(\.[a-z0-9-]+)+(\/\S*)?$/i.test(s)) s = `https://${s}`; // "x.com/name" → https://x.com/name
  if (s.length > 300 || !/^https:\/\/[^\s"'<>\\]+$/i.test(s)) throw bad('Links must start with https://');
  try { new URL(s); } catch { throw bad('That link is not valid'); }
  return s;
}

/**
 * "Refresh on Quantly": reloads every token's name, picture and traits from the link the contract uses now.
 * Useful when a creator changed files behind the same https link (IPFS links change when files change, and
 * those are picked up on their own). Only the on-chain owner, and once every 10 minutes per collection.
 */
const REFRESH_EVERY_MS = 10 * 60_000;
const REFRESH_QUEUE_MAX = 40_000; // metadata reads waiting, from every source, above which refreshes wait
const lastRefresh = new Map();
// Per wallet as well, so one creator with many collections can't fill the queue for everyone else.
const refreshPerWallet = rateLimit({ windowMs: 3600_000, limit: 6, keyGenerator: (req) => req.user, standardHeaders: 'draft-7', legacyHeaders: false,
  handler: (_req, _res, next) => next(new HttpError(429, 'You refreshed several collections in the last hour. Try again later.', 'refresh_wait')) });
r.post('/:address/refresh', requireAuth, refreshPerWallet, ah(async (req, res) => {
  const address = addrParam(req.params.address, 'collection');
  if (!(await isLaunchpadCollection(address))) throw bad('This contract was not created by the launchpad');
  const owner = String(await collectionContract(address).owner()).toLowerCase();
  if (owner !== req.user) throw forbidden('Only the collection owner can refresh it');
  const now = Date.now();
  for (const [k, at] of lastRefresh) if (now - at >= REFRESH_EVERY_MS) lastRefresh.delete(k);
  const wait = (lastRefresh.get(address) || 0) + REFRESH_EVERY_MS - now;
  if (wait > 0) throw new HttpError(429, `This collection was refreshed a moment ago. Try again in ${Math.ceil(wait / 60_000)} min.`, 'refresh_wait');
  if (metadataQueueSize() > REFRESH_QUEUE_MAX) throw new HttpError(503, 'Many pictures are being loaded right now. Try again in a few minutes.', 'busy');
  lastRefresh.set(address, now);
  try {
    await syncCollectionFromChain(address);
  } catch (e) {
    lastRefresh.delete(address); // a failed read does not use up the 10 minutes
    throw e;
  }
  const ids = await many(
    `select token_id::text as id from tokens where collection = $1 and owner is not null order by token_id limit 20000`,
    [address],
  );
  ids.forEach((t) => queueMetadata(address, t.id));
  res.json({ ok: true, tokens: ids.length });
}));

export default r;
