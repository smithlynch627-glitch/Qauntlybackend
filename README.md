# Backend: Quantly NFT Launchpad & Marketplace (QMS)

Node.js + Express API and a chain indexer for QMS Testnet (chain 19480). Postgres (Supabase) stores what the indexer reads
from the chain plus signed orders. **Nothing is simulated:** mints, sales, offers and cancels only appear after
their transaction is confirmed on QMS.

## Order of setup

1. Deploy the contracts (`contracts/README.md`) and copy the printed addresses.
2. **Supabase SQL** (SQL Editor, in this order):
   - `db/01_schema.sql`: all tables, RLS, the locked-down API role, and the QMS Testnet network
   - `db/02_api_role.sql`: gives `quantly_api` a password (change it first)
   - `db/03_first_admin.sql`: optional, adds panel admins (or use `ADMIN_ADDRESSES`)
   - `db/04_admin_v2.sql`: multisig proposals and treasury history for the admin panel (existing databases: run it once)
   - `db/05_x_connect.sql`: creators' connected X accounts (existing databases: run it once)
   - `db/06_wrapped_address.sql`: only for a database created before this file existed (renames one column; safe to run again)
3. Fill `backend/.env` from `.env.example`. `DATABASE_URL` uses the `quantly_api` user. Network values in `.env`
   stay in control until someone edits the network in the admin panel; after that the panel is the source of truth.
4. Start the API and the indexer.
5. Deploy the separate admin app (`admin/README.md`), add its URL to `ADMIN_ORIGINS`, and sign in with an admin wallet.

## Run locally (PowerShell)

```powershell
cd backend
npm install
Copy-Item .env.example .env   # then edit it
npm run dev                   # API on http://localhost:8080
# second terminal
npm run indexer
```

`npm run db:init` applies `db/01_schema.sql` if `DATABASE_URL` uses the `postgres` user (local setup).

## Admin panel (separate app in `admin/`)

The admin panel is its own site. `/api/admin/*` only answers requests from `ADMIN_ORIGINS` **and** from a signed-in
wallet with a role. Requests from the public site's origin get 403.

| Tab | Role | What it does |
|---|---|---|
| Overview | support | Volume, fees earned, users, open tickets |
| Collections | admin | Verify, feature, hide, edit, refresh metadata; block or enable trading on-chain |
| Import from QMS | admin | Lists existing ERC-721 collections from QMSScan (Blockscout) and imports them |
| Contracts & fees | admin | Trading fee, mint fee, pause, fee vault balances and withdrawals |
| Network | owner | Edit RPC and addresses, test them, switch the whole marketplace to mainnet |
| Support tickets | support | Read (contacts decrypted), reply, set status and priority |
| Team | owner | Add or remove admins and support staff |
| Audit log | admin | Every admin action, with wallet and IP |

On-chain buttons send the transaction when your wallet owns the contract. If a Safe multisig owns it, they copy
the calldata for the Safe Transaction Builder instead.

### Switching to a new network (QMS mainnet, or a new testnet after a reset)

1. Deploy the contracts on the new network (same scripts).
2. Admin → Network → Add network: key, chain ID, RPC, explorer, addresses, start block.
3. Press **Test**. The RPC must return that chain ID, and every address must hold a contract.
4. Press **Activate** and type the key to confirm.

Every API instance, the indexer and the website follow within about 10 seconds. Each chain ID keeps its data in its own
schema (`chain_<id>`). No env change or redeploy is needed for the backend; the website and admin builds pin the chain,
RPC and contract addresses, so update their Netlify variables and redeploy them.

## Railway (two services, same folder)

| Service | Root directory | Start command |
|---|---|---|
| API | `backend` | `npm start` |
| Indexer | `backend` | `npm run indexer` |

Same environment variables on both. Run exactly **one** indexer. Add your Netlify URL to `CORS_ORIGINS`.
There are no third-party RPC providers for QMS Testnet yet, so the API and the indexer share the public endpoint (50 requests a second per address).

## How trading stays honest

- **Orders:** the browser signs an EIP-712 order. `POST /api/orders` recomputes the hash and asks the
  marketplace contract itself (`checkOrder`) whether the order is valid: signature, counter, expiry, fee cap,
  royalty cap, ownership, approval and WQMS balance. Invalid orders are rejected before they are ever shown.
- **Settlement:** buying, accepting and cancelling happen on-chain. The contract re-checks everything, so a
  tampered API response can never change what anyone pays.
- **Prices and fees:** drop prices, times, limits and allowlist roots are read from the collection contract. Fees
  come from the contracts (`/api/config`), never from env files.
- **Allowlists:** a creator's allowlist is stored only if its Merkle root matches the one deployed on-chain.
- **Official and verified badges** come from server env only (`OFFICIAL_COLLECTION_ADDRESS`, `VERIFIED_COLLECTIONS`).
- **Live updates:** after each user transaction the site calls `POST /api/orders/sync`, so the UI updates
  immediately. The indexer catches everything else, including transfers made outside the site, which
  deactivate stale listings.

## API

| Method | Path | Notes |
|---|---|---|
| GET | `/api/config` | chain, contract addresses, live fees, official collection address |
| POST | `/api/auth/nonce`, `/api/auth/verify` | wallet sign-in (free signature) for creator tools and profile edits |
| GET | `/api/collections`, `/api/collections/:slugOrAddress` | |
| GET | `/api/collections/:key/tokens` | `status=listed`, `min`, `max`, `traits`, `sort`, `q`, `owner`, `offset` |
| GET | `/api/collections/:key/traits`, `/offers`, `/sweep?count=` | |
| GET | `/api/tokens/:collection/:tokenId` | item + offers + trait counts |
| GET | `/api/activity` | `collection`, `token`, `address`, `types`, `before` |
| GET | `/api/users/:address` (+ `/tokens`, `/listings`, `/offers-made`, `/offers-received`) | |
| GET | `/api/drops`, `/api/drops/:key`, `/api/drops/:key/eligibility/:wallet` | Merkle proofs |
| POST | `/api/drops/allowlists` | returns the Merkle root to deploy with (auth) |
| POST | `/api/drops` | owner-only display details for a launchpad collection (auth) |
| POST | `/api/orders` · GET `/api/orders/:hash` · POST `/api/orders/sync` | signed orders, tx sync |
| POST | `/api/uploads` | images; IPFS via Pinata if `PINATA_JWT` is set, otherwise hosted by the API (auth) |
| POST | `/api/uploads/prereveal` | one image → placeholder metadata URI (auth) |
| POST | `/api/uploads/ipfs-key` | single-use, upload-only Pinata key for folder uploads (auth) |
| GET | `/api/media/:id` | hosted images |
| GET/POST | `/api/support`, `/api/support/mine`, `/api/support/:id`, `/api/support/:id/reply` | user tickets (auth) |
| * | `/api/admin/*` | admin app only (`ADMIN_ORIGINS` + auth + role) |

Security details: see `../SECURITY.md`.

## Scaling to ~100k users

The API is stateless: scale it horizontally on Railway and keep one indexer. Put Cloudflare in front and cache
`GET /api/collections*` and `/api/drops` for 10–30 s. Use a dedicated RPC for the indexer once one exists for QMS. Reads are
indexed, and stats are cached on each collection row.

## QMS-specific behaviour

- **No finality yet.** On the current QMS testnet the `safe` and `finalized` block tags return the genesis block, and
  blocks come from proof-of-work, so the newest block can still be replaced. The indexer never uses those tags: it
  stays `INDEXER_CONFIRMATIONS` blocks behind the head (default 3, about 30 s) and re-reads the last 30 blocks every
  round. The website waits 2 confirmations before it reports a transaction as done.
- **Testnet resets.** The QMS team has announced that the testnet will be reset. After a reset: redeploy the contracts,
  then in Supabase run `drop schema chain_19480 cascade; select app.ensure_chain_schema(19480);` if the chain ID stays
  the same (or add the new chain as a network), set the new addresses and `INDEXER_START_BLOCK`, and redeploy the
  website and admin with the new pins.
- **Coin.** QMS is the only coin: gas, mints and listings are paid in QMS, offers in WQMS (wrapped QMS,
  `WRAPPED_ADDRESS`). The API calls them `native` and `wrapped` everywhere. A database created before
  `db/06_wrapped_address.sql` existed needs that file run once (it renames one column).
- **Safe multisig.** The Safe contracts are not deployed on QMS Testnet yet (checked on QMSScan, 2 Oct 2026), so the
  contracts are owned by a single wallet until you deploy Safe v1.3.0 there. The admin panel works with either.
