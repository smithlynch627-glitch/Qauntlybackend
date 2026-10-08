// Collection pictures set by the creator (Create / Studio) or an admin: logo, banner, the About picture and up
// to three extra images shown with the logo on the mint page. Pictures are links only (https://, ipfs:// or
// ar://). Nothing is uploaded here and the server never opens these links when they are saved. The file type is
// not restricted, so PNG, JPG, GIF, WebP, AVIF, SVG and BMP all work.
import net from 'node:net';
import { currentChainSchema, one } from '../db.js';
import { bad } from './http.js';

export const MAX_GALLERY = 3;
export const MAX_LINK = 500;

// Links are plain ASCII (other characters must be percent-encoded) and at most 500 characters.
const HTTPS = /^https:\/\/[A-Za-z0-9._~:/?#[\]@!$&()*+,;=%-]{4,492}$/;
// ipfs://<CID>[/path]  (an optional "ipfs/" before the CID is tolerated)
const IPFS = /^ipfs:\/\/(ipfs\/)?[A-Za-z0-9]{40,120}(\/[A-Za-z0-9._~!$&()*+,;=:@%-]+)*\/?(\?[A-Za-z0-9._~=&%-]*)?$/;
// ar://<transaction id or name>[/path]
const AR = /^ar:\/\/[A-Za-z0-9_-]{10,64}(\/[A-Za-z0-9._~-]+)*\/?$/;
// Host names that never belong to a public image host.
const PRIVATE_HOST = /(^|\.)(localhost|localdomain|local|internal|intranet|private|corp|lan|home|arpa|test|invalid|example|onion)$/;

/**
 * A web link is only accepted when it points to a normal public host: a domain name with a dot, the standard
 * https port, and no user name or password inside the link. Visitors' browsers load these pictures, so links to
 * "localhost", to a bare IP address or to another port are refused (they could poke at a device on a visitor's
 * own network).
 */
function assertPublicHttps(s, name) {
  let u;
  try { u = new URL(s); } catch { throw bad(`${name}: this link is not valid`); }
  const host = u.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  const plainHost = /^(?=.{4,253}$)([a-z0-9]([a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/.test(host);
  if (u.protocol !== 'https:' || u.username || u.password || s.slice(8).split(/[/?#]/)[0].includes('@') || (u.port && u.port !== '443')
    || net.isIP(host) || !plainHost || PRIVATE_HOST.test(host)) {
    throw bad(`${name}: use a public https:// link to the image`);
  }
}

/** A hosted image link, or null when the field is empty. */
export function cleanMediaLink(v, name = 'Image') {
  if (v === null || v === undefined) return null;
  const format = () => bad(`${name}: use an https://, ipfs:// or ar:// link to the image (letters, numbers and common symbols only)`);
  if (typeof v !== 'string') throw format();
  const s = v.trim();
  if (s === '') return null;
  if (s.length > MAX_LINK || !(HTTPS.test(s) || IPFS.test(s) || AR.test(s))) throw format();
  // No "go up a folder" steps, written plainly or percent-encoded, and no encoded slashes or backslashes.
  if (/(^|\/)\.{1,2}(\/|\?|#|$)/.test(s.replace(/^[a-z]+:\/\//, '')) || /%(2e|2f|5c|00)/i.test(s)) throw bad(`${name}: this link is not valid`);
  if (s.startsWith('https://')) assertPublicHttps(s, name);
  return s;
}

/** Up to three extra images. Empty rows and repeats are dropped. */
export function cleanGallery(list) {
  if (list === null || list === undefined) return [];
  if (!Array.isArray(list)) throw bad('Extra images must be a list of links');
  if (list.length > 12) throw bad(`You can add up to ${MAX_GALLERY} extra images`);
  const out = [];
  for (const [i, v] of list.entries()) {
    const s = cleanMediaLink(v, `Extra image ${i + 1}`);
    if (s && !out.includes(s)) out.push(s);
  }
  if (out.length > MAX_GALLERY) throw bad(`You can add up to ${MAX_GALLERY} extra images`);
  return out;
}

/** Plain text: control characters (other than line breaks and tabs) are removed, then the text is cut to `max`. */
// eslint-disable-next-line no-control-regex
export const cleanText = (v, max) => String(v ?? '').replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f‪-‮⁦-⁩]/g, '').slice(0, max);

/** The About tab's detail rows: up to 12 short label / value pairs, plain text only. */
export function cleanAboutItems(list) {
  if (!Array.isArray(list) || list.length > 12) throw bad('About details: up to 12 rows');
  return list
    .map((x) => ({ label: cleanText(x?.label, 200).replace(/\s+/g, ' ').trim().slice(0, 40), value: cleanText(x?.value, 1000).replace(/\s+/g, ' ').trim().slice(0, 300) }))
    .filter((x) => x.label && x.value);
}

/** The About story: plain text, up to 8,000 characters. */
export const cleanAbout = (v) => (v === null || v === undefined || String(v).trim() === '' ? null : cleanText(v, 8000));

// The "gallery" column comes with the current database script (db/setup_all.sql, or db/07_gallery.sql for a
// database made before it). Until that has run the API keeps working: collections simply have no extra images.
let seen = { schema: null, ok: false, at: 0 };
export async function galleryReady() {
  const schema = currentChainSchema();
  if (seen.schema === schema && (seen.ok || Date.now() - seen.at < 15_000)) return seen.ok;
  let ok = false;
  try {
    ok = !!(await one(
      `select 1 as ok from information_schema.columns where table_schema = $1 and table_name = 'collections' and column_name = 'gallery'`,
      [schema],
    ));
  } catch {
    return seen.schema === schema ? seen.ok : false; // a failed lookup is not an answer: nothing is remembered
  }
  seen = { schema, ok, at: Date.now() };
  return ok;
}

/** SQL for the gallery column (or an empty list while the column does not exist yet). */
export const galleryCol = async () => ((await galleryReady()) ? 'c.gallery' : `'[]'::jsonb as gallery`);

export async function requireGallery() {
  if (!(await galleryReady())) throw bad('Extra images are not set up yet: run db/setup_all.sql in the database once more.', 'gallery_not_ready');
}
