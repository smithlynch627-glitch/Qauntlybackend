import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import rateLimit from 'express-rate-limit';
import { config, contractsReady } from './config.js';
import { HttpError } from './lib/http.js';
import { getPool } from './db.js';
import { applyCollectionFlags } from './indexer/core.js';
import { chainFees } from './lib/chain.js';
import meta from './routes/meta.js';
import collections from './routes/collections.js';
import tokens from './routes/tokens.js';
import activity from './routes/activity.js';
import users from './routes/users.js';
import drops from './routes/drops.js';
import orders from './routes/orders.js';
import uploads, { media } from './routes/uploads.js';
import admin from './routes/admin.js';
import share from './routes/share.js';
import support from './routes/support.js';
import xConnect from './routes/x.js';
import apiKeys from './routes/apiKeys.js';
import adminApiKeys from './routes/adminApiKeys.js';
import v1 from './routes/v1.js';
import { loadNetwork, watchNetwork } from './lib/network.js';

const app = express();
const blockedOrigins = new Set();
// The public API (/api/v1) is for servers and bots with an API key: no CORS for it, and its limits are per key.
const isV1 = (req) => /^\/api\/v1(\/|\?|$)/.test(req.originalUrl || '');
// Railway puts one proxy in front of the API. Behind Cloudflare too, set TRUST_PROXY=2 so rate limits see the real visitor.
app.set('trust proxy', Math.max(0, Math.min(5, Number(process.env.TRUST_PROXY ?? 1))));
app.use(
  helmet({
    crossOriginResourcePolicy: { policy: 'cross-origin' },
    contentSecurityPolicy: { directives: { defaultSrc: ["'none'"], frameAncestors: ["'none'"] } }, // JSON API: nothing to render
    strictTransportSecurity: { maxAge: 63072000, includeSubDomains: true, preload: true },
    referrerPolicy: { policy: 'no-referrer' },
  }),
);
app.disable('x-powered-by');
const corsMiddleware = cors({
  origin: (origin, cb) => {
    const ok = !origin || config.corsOrigins.includes(origin) || config.adminOrigins.includes(origin);
    if (!ok && !blockedOrigins.has(origin) && blockedOrigins.size < 200) {
      blockedOrigins.add(origin);
      console.warn(`[cors] blocked ${origin}. Add it to CORS_ORIGINS (website) or ADMIN_ORIGINS (admin app) in .env and restart.`);
    }
    cb(null, ok);
  },
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
  allowedHeaders: ['content-type', 'authorization'],
  maxAge: 600,
});
// Requests without an Origin header (servers, scripts) pass; /api/v1 never gets CORS headers, so browsers can't use keys.
app.use((req, res, next) => (isV1(req) ? next() : corsMiddleware(req, res, next)));
app.use(compression());
app.use(express.json({ limit: '1mb' }));
app.use('/api/auth', rateLimit({ windowMs: 60_000, limit: 20, standardHeaders: 'draft-7', legacyHeaders: false }));

// /api/v1 has its own per-key limits and a per-IP backstop (routes/v1.js), so it is not counted here.
app.use('/api', rateLimit({ windowMs: 60_000, limit: 600, standardHeaders: 'draft-7', legacyHeaders: false, skip: isV1 }));
const writeLimit = rateLimit({ windowMs: 60_000, limit: 60, standardHeaders: 'draft-7', legacyHeaders: false });
app.use((req, res, next) => (req.method === 'GET' ? next() : writeLimit(req, res, next)));

app.use('/api/v1', v1);
app.use('/api', meta);
app.use('/api/collections', collections);
app.use('/api/tokens', tokens);
app.use('/api/activity', activity);
app.use('/api/users', users);
app.use('/api/drops', drops);
app.use('/api/orders', orders);
app.use('/api/uploads', uploads);
app.use('/api/media', media);
app.use('/api/keys', apiKeys);
app.use('/api/admin/api-keys', adminApiKeys);
app.use('/api/admin', admin);
app.use('/api/share', share);
app.use('/api/support', support);
app.use('/api/x', xConnect);

app.use((_req, res) => res.status(404).json({ error: 'Route not found', code: 'not_found' }));

// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  if (err instanceof HttpError) return res.status(err.status).json({ error: err.message, code: err.code });
  if (err?.type === 'entity.too.large') return res.status(413).json({ error: 'Request is too large', code: 'too_large' });
  if (err?.code === 'LIMIT_FILE_SIZE') return res.status(413).json({ error: 'File is too large', code: 'too_large' });
  // The database enforces its own size limits; a value that breaks one is a bad request, not a server fault.
  if (['23514', '22001', '22P05', '22007', '22008', '22P02'].includes(err?.code)) return res.status(400).json({ error: 'Some of these details are too long or not in the expected format', code: 'bad_request' });
  const db = describeDbError(err);
  if (db) {
    console.error(`[db] ${db}`);
    return res.status(503).json({ error: db, code: 'database' });
  }
  console.error(err);
  res.status(500).json({ error: 'Something went wrong on the server', code: 'server_error' });
});

/** Turns Postgres/connection failures into a message that says what to fix. */
function describeDbError(err) {
  const code = err?.code;
  const msg = String(err?.message || '');
  if (code === '42P01' && /safe_proposals|safe_signatures|treasury_events|treasury_cursor/.test(msg)) {
    return 'The admin v2 tables are missing. Run backend/db/04_admin_v2.sql once in Supabase → SQL Editor, then reload the admin page.';
  }
  if (code === '42P01' && /api_keys|api_key_usage/.test(msg)) {
    return 'The API key tables are missing. Run backend/db/setup_all.sql again in Supabase → SQL Editor (or only db/08_api_keys.sql).';
  }
  if (code === '42P01') return 'Database tables are missing. Run db/01_schema.sql (npm run db:init)';
  if (code === 'ECONNRESET' || /Connection terminated unexpectedly/i.test(msg))
    return 'The database pooler closed the connection. Copy the host exactly from Supabase → Connect → Direct → Session pooler, use user quantly_api.<project-ref> and port 5432';
  if (code === 'ECONNREFUSED' || code === 'ENOTFOUND' || code === 'ETIMEDOUT' || code === 'EAI_AGAIN')
    return `Cannot reach the database (${code}). Check DATABASE_URL in backend/.env`;
  if (code === '28P01' || /password authentication failed/i.test(msg)) return 'Database password is wrong. Check DATABASE_URL';
  if (/Tenant or user not found/i.test(msg)) return 'Supabase pooler user is wrong. Use the Session pooler string (user looks like postgres.<project-ref>)';
  if (/self.signed|certificate/i.test(msg)) return 'Database SSL error. Check DATABASE_URL';
  if (/database .* does not exist/i.test(msg)) return 'Database name in DATABASE_URL does not exist';
  return null;
}

async function checkDatabase() {
  const host = (() => { try { return new URL(config.databaseUrl).host; } catch { return 'invalid DATABASE_URL'; } })();
  try {
    await getPool().query('select 1');
    const { rows } = await getPool().query(`select to_regclass('app.networks') as t`);
    if (!rows[0].t) {
      console.error(`[db] Connected to ${host}, but tables are missing. Run db/01_schema.sql (npm run db:init)`);
      return;
    }
    const v2 = await getPool().query(`select to_regclass('app.safe_proposals') as t`);
    if (!v2.rows[0].t) console.warn('[db] Admin v2 tables are missing: run backend/db/04_admin_v2.sql in the Supabase SQL editor (Treasury and Multisig need them).');
    const keys = await getPool().query(`select to_regclass('app.api_keys') as t`);
    if (!keys.rows[0].t) console.warn('[db] API key tables are missing: run backend/db/setup_all.sql again in the Supabase SQL editor (API keys and /api/v1 need them).');
    const pv = await getPool().query(
      `select count(*)::int as n from information_schema.columns
       where table_schema = 'app' and table_name = 'users' and column_name in ('hide_collected', 'hide_activity')`,
    );
    if (pv.rows[0].n < 2) console.warn('[db] Profile privacy columns are missing: run backend/db/setup_all.sql again in the Supabase SQL editor (until then every profile is public and the switches cannot be saved).');
    console.log(`[db] Connected to ${host} over ${/localhost|127\.0\.0\.1/.test(config.databaseUrl) ? 'a local socket' : config.databaseCa ? 'verified TLS' : 'TLS'}.`);
  } catch (e) {
    console.error(`[db] ${describeDbError(e) || e.message} (host: ${host})`);
  }
}

async function checkChain() {
  if (!contractsReady()) return;
  const fees = await chainFees();
  if (fees.marketFeeBps === null) console.error(`[chain] Cannot read the contracts through ${config.rpcUrl}. Check RPC_URL and the addresses.`);
  else console.log(`[chain] market fee ${fees.marketFeeBps / 100}%, mint fee ${fees.mintFeeBps / 100}%`);
  await applyCollectionFlags().catch(() => {});
}

async function start() {
  await checkDatabase();
  try {
    await loadNetwork();
    watchNetwork();
    console.log(`[network] ${config.networkName} (chain ${config.chainId})`);
  } catch (e) {
    console.error(`[network] ${describeDbError(e) || e.message}`);
  }
  app.listen(config.port, () => {
    console.log(`API listening on :${config.port}`);
    checkChain();
  });
}
start();
