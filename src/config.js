import 'dotenv/config';
import { readFileSync, existsSync } from 'node:fs';

const addr = (v) => (v ? String(v).trim().toLowerCase() : '');
const list = (v) => String(v || '').split(',').map(addr).filter(Boolean);
// Site addresses: a trailing "/" or capital letters would never match the browser's Origin header, so normalise them.
const origins = (v, fallback) => String(v || fallback).split(',').map((s) => s.trim().replace(/\/+$/, '').toLowerCase()).filter(Boolean);

function readCa(v) {
  if (!v) return null;
  if (v.includes('BEGIN CERTIFICATE')) return v.replace(/\\n/g, '\n');
  return existsSync(v) ? readFileSync(v, 'utf8') : null;
}

/**
 * Server settings come from env. Network settings (chain, RPC, contracts) are loaded from
 * app.networks at startup and whenever an admin switches network; env values only seed the first network.
 */
export const config = {
  port: Number(process.env.PORT || 8080),
  env: process.env.NODE_ENV || 'development',
  databaseUrl: process.env.DATABASE_URL || 'postgresql://postgres:postgres@localhost:5432/quantly',
  databaseCa: readCa(process.env.DATABASE_CA_CERT),
  jwtSecret: process.env.JWT_SECRET || '',
  corsOrigins: origins(process.env.CORS_ORIGINS, 'http://localhost:5173'),
  // The separate admin site(s). /api/admin only answers requests coming from these origins.
  adminOrigins: origins(process.env.ADMIN_ORIGINS, 'http://localhost:5174'),
  apiPublicUrl: (process.env.API_PUBLIC_URL || `http://localhost:${process.env.PORT || 8080}`).replace(/\/$/, ''),
  rootAdmins: list(process.env.ADMIN_ADDRESSES).filter((a) => /^0x[0-9a-f]{40}$/.test(a)),
  encryptionKey: process.env.DATA_ENCRYPTION_KEY || '',
  pinataJwt: process.env.PINATA_JWT || '',
  // X (Twitter) account connection for creators. OAuth 2.0 with PKCE; only @username is read, then the token is revoked.
  x: {
    clientId: (process.env.X_CLIENT_ID || '').trim(),
    clientSecret: (process.env.X_CLIENT_SECRET || '').trim(),
    redirectUri: (process.env.X_REDIRECT_URI || '').trim(),
    authUrl: (process.env.X_AUTH_URL || 'https://x.com/i/oauth2/authorize').trim(),
    apiBase: (process.env.X_API_BASE || 'https://api.x.com').trim().replace(/\/$/, ''),
  },
  verifiedCollections: list(process.env.VERIFIED_COLLECTIONS),
  officialSlug: 'official',
  // QMS blocks are proof-of-work, about 10 s apart, and the public RPC is rate limited: no need to ask more often.
  indexerPollMs: Number(process.env.INDEXER_POLL_MS || 5000),
  // Shown in sign-in messages, link previews and error texts.
  brand: (process.env.BRAND_NAME || 'Quantly').trim(),
  // Native coin of the chain and its wrapped form (offers are paid in the wrapped coin).
  nativeSymbol: (process.env.NATIVE_SYMBOL || 'QMS').trim(),
  wrappedSymbol: (process.env.WRAPPED_SYMBOL || `W${(process.env.NATIVE_SYMBOL || 'QMS').trim()}`).trim(),
  // EIP-712 domain name of the marketplace contract. Fixed in the contract's constructor, so it must match the
  // deployed contract exactly ("Quantly Market" in QuantlyMarket.sol).
  marketDomainName: (process.env.MARKET_DOMAIN_NAME || 'Quantly Market').trim(),

  // ── active network (mutated by lib/network.js) ──
  networkKey: 'qms-testnet',
  networkName: 'QMS Testnet',
  isTestnet: true,
  chainId: Number(process.env.CHAIN_ID || 19480),
  rpcUrl: process.env.RPC_URL || 'https://rpc.testnet.qms.finance',
  publicRpcUrl: process.env.PUBLIC_RPC_URL || process.env.RPC_URL || 'https://rpc.testnet.qms.finance',
  explorerUrl: process.env.EXPLORER_URL || 'https://testnet.qmsscan.io',
  explorerApiUrl: process.env.EXPLORER_API_URL || 'https://testnet.qmsscan.io/api/v2',
  market: addr(process.env.MARKET_ADDRESS),
  factory: addr(process.env.LAUNCHPAD_FACTORY_ADDRESS),
  feeVault: addr(process.env.FEE_VAULT_ADDRESS),
  // Wrapped QMS (WQMS) on QMS Testnet, verified on QMSScan. Offers are paid in it.
  wrapped: addr(process.env.WRAPPED_ADDRESS || '0x9aa510295ac664a3d5a3182a3efe959de2b12c34'),
  officialCollection: addr(process.env.OFFICIAL_COLLECTION_ADDRESS),
  indexerStartBlock: Number(process.env.INDEXER_START_BLOCK || 0),
};

export const contractsReady = () => Boolean(config.market && config.factory && config.feeVault);

if (!config.jwtSecret || config.jwtSecret.length < 32) {
  if (config.env === 'production') throw new Error('JWT_SECRET must be at least 32 characters');
  console.warn('[config] JWT_SECRET is missing or short. Using an insecure development secret.');
  config.jwtSecret = config.jwtSecret || 'dev-only-secret-dev-only-secret-000';
}
{
  const raw = list(process.env.ADMIN_ADDRESSES);
  const invalid = raw.filter((a) => !/^0x[0-9a-f]{40}$/.test(a));
  if (invalid.length) console.warn(`[config] ADMIN_ADDRESSES has invalid entries (ignored): ${invalid.join(', ')}`);
  const shown = config.rootAdmins.map((a) => `${a.slice(0, 6)}…${a.slice(-4)}`).join(', ');
  console.log(`[config] root admin wallets from ADMIN_ADDRESSES: ${shown || 'none set'}`);
  console.log(`[config] website origins: ${config.corsOrigins.join(', ')} | admin origins: ${config.adminOrigins.join(', ')}`);
}
if (config.env === 'production' && !config.databaseCa && !/localhost|127\.0\.0\.1/.test(config.databaseUrl)) {
  console.warn('[config] DATABASE_CA_CERT is not set: the database connection is encrypted but the server certificate is not verified. Paste the Supabase CA certificate into DATABASE_CA_CERT.');
}
if (!config.encryptionKey) console.warn('[config] DATA_ENCRYPTION_KEY is not set. Support contact details will not be stored.');

export const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000';
