-- =====================================================================================
-- Quantly: complete database setup, and updates, for a Supabase project (Postgres 15 or newer).
--
-- How to use
--   1. Put your backend database password on the line marked  <<< PASSWORD  below.
--      Use letters and numbers only, 32 characters or more.
--   2. Supabase → SQL Editor → paste this whole file → Run.
--   3. Read the table that appears at the end: every row must say PASS.
--   4. Do not save the query with the password in it. Close the tab or delete the password line text.
--
-- Everything runs in one transaction: if any part fails, nothing is changed.
-- Safe to run again, and running it again is how a database gets updates (new columns, new limits).
-- The password is only applied the first time: on a later run you can leave the password line as it is.
--
-- What it does
--   Part 1  password check
--   Part 2  tables, row level security, the limited `quantly_api` role, QMS Testnet (chain 19480)
--   Part 3  login for `quantly_api`, with query time limits
--   Part 4  lock-down: nothing for PUBLIC or the Supabase API roles (anon, authenticated, service_role)
--   Part 5  security report (also in verify_security.sql, to run again at any time)
-- =====================================================================================

begin;

set local quantly.api_password = 'PASTE_YOUR_PASSWORD_HERE';   -- <<< PASSWORD

-- ── Part 1: password check ─────────────────────────────────────────────────────────
-- Stops here, before anything is created, if the role still needs a password and the one above is weak.
do $$
declare pw text := current_setting('quantly.api_password');
begin
  if exists (select 1 from pg_roles where rolname = 'quantly_api' and rolcanlogin) then
    return;   -- already has a password from an earlier run; the line above is ignored
  end if;
  if pw !~ '^[A-Za-z0-9]{32,}$' then
    raise exception 'Put your password on the line marked <<< PASSWORD (32 or more characters, letters and numbers only), then run again. Nothing was changed.';
  end if;
end $$;

-- ── Part 2: schema ─────────────────────────────────────────────────────────────────
-- =====================================================================================
-- Quantly: NFT Launchpad & Marketplace — database schema (Supabase / Postgres 15+)
-- Run in Supabase: SQL Editor → paste → Run.  Safe to run again (idempotent).
--
-- Security model
--  • The website never talks to the database. Only the backend API does, over TLS.
--  • Data lives in private schemas (`app`, `chain_<id>`) that Supabase's public REST API
--    does not expose. RLS is enabled on every table and only the `quantly_api` role has a policy,
--    so the `anon` / `authenticated` keys can read or write nothing, even if leaked.
--  • `quantly_api` is a least-privilege login for the backend (no DDL, no superuser).
--    New chain schemas are created only through app.ensure_chain_schema() (SECURITY DEFINER).
--  • Sensitive fields (support contact details) are encrypted by the backend (AES-256-GCM)
--    before they reach the database.
-- =====================================================================================

create extension if not exists pgcrypto;

-- ── Roles ──────────────────────────────────────────────────────────────────────────
do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'quantly_api') then
    create role quantly_api nologin noinherit;   -- 02_api_role.sql gives it a password and LOGIN
  end if;
end $$;

-- ── Global schema ──────────────────────────────────────────────────────────────────
create schema if not exists app;
revoke all on schema app from public;
grant usage on schema app to quantly_api;

-- Networks: the admin panel switches the whole marketplace by activating another row.
create table if not exists app.networks (
  key               text primary key check (key ~ '^[a-z0-9-]{3,40}$'),
  chain_id          integer not null unique check (chain_id > 0),
  name              text not null,
  rpc_url           text not null check (rpc_url ~ '^https?://'),       -- server RPC (can be private)
  public_rpc_url    text check (public_rpc_url ~ '^https?://'),         -- RPC the browser uses (https in production)
  explorer_url      text not null check (explorer_url ~ '^https?://'),
  explorer_api_url  text,                                               -- Blockscout API v2 base (for importing collections)
  is_testnet        boolean not null default true,
  market_address    text check (market_address ~ '^0x[0-9a-f]{40}$'),
  factory_address   text check (factory_address ~ '^0x[0-9a-f]{40}$'),
  fee_vault_address text check (fee_vault_address ~ '^0x[0-9a-f]{40}$'),
  wrapped_address   text not null default '0x9aa510295ac664a3d5a3182a3efe959de2b12c34' check (wrapped_address ~ '^0x[0-9a-f]{40}$'),
  official_collection text check (official_collection ~ '^0x[0-9a-f]{40}$'),
  start_block       bigint not null default 0 check (start_block >= 0),
  is_active         boolean not null default false,
  updated_by        text,
  updated_at        timestamptz not null default now()
);
create unique index if not exists networks_single_active on app.networks (is_active) where is_active;

create table if not exists app.admins (
  address    text primary key check (address ~ '^0x[0-9a-f]{40}$'),
  role       text not null check (role in ('owner', 'admin', 'support')),
  added_by   text,
  created_at timestamptz not null default now()
);

create table if not exists app.users (
  address    text primary key check (address ~ '^0x[0-9a-f]{40}$'),
  username   text check (username ~ '^[[:alnum:]_.-]{3,24}$'),
  bio        text not null default '' check (char_length(bio) <= 280),
  is_banned  boolean not null default false,
  created_at timestamptz not null default now()
);
create unique index if not exists users_username_ci on app.users (lower(username)) where username is not null;

create table if not exists app.auth_nonces (
  address    text primary key,
  nonce      text not null,
  expires_at timestamptz not null
);

create table if not exists app.support_tickets (
  id              uuid primary key default gen_random_uuid(),
  ref             text not null unique,
  address         text not null check (address ~ '^0x[0-9a-f]{40}$'),
  category        text not null check (category in ('general','mint','trade','listing','offer','collection','wallet','bug','report','other')),
  subject         text not null check (char_length(subject) between 3 and 140),
  contact_enc     text,                          -- AES-256-GCM ciphertext, never plaintext
  status          text not null default 'open' check (status in ('open','waiting','resolved','closed')),
  priority        text not null default 'normal' check (priority in ('low','normal','high','urgent')),
  chain_id        integer,
  collection      text,
  token_id        text,
  tx_hash         text check (tx_hash ~ '^0x[0-9a-fA-F]{64}$'),
  assigned_to     text,
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now(),
  last_message_at timestamptz not null default now()
);
create index if not exists tickets_status_idx on app.support_tickets (status, last_message_at desc);
create index if not exists tickets_address_idx on app.support_tickets (address, created_at desc);

create table if not exists app.ticket_messages (
  id         bigserial primary key,
  ticket_id  uuid not null references app.support_tickets(id) on delete cascade,
  author     text not null,
  is_staff   boolean not null default false,
  body       text not null check (char_length(body) between 1 and 4000),
  created_at timestamptz not null default now()
);
create index if not exists ticket_messages_idx on app.ticket_messages (ticket_id, id);

create table if not exists app.audit_log (
  id         bigserial primary key,
  actor      text not null,
  action     text not null,
  target     text,
  details    jsonb not null default '{}',
  ip         text,
  created_at timestamptz not null default now()
);
create index if not exists audit_time_idx on app.audit_log (created_at desc);

-- Small images hosted by the API when IPFS is not configured (e.g. a pre-reveal image).
create table if not exists app.media (
  id         uuid primary key default gen_random_uuid(),
  owner      text not null,
  mime       text not null check (mime in ('image/png','image/jpeg','image/gif','image/webp')),
  bytes      bytea not null,
  size       integer not null check (size between 1 and 2097152),
  sha256     text not null,
  created_at timestamptz not null default now()
);
create unique index if not exists media_dedupe on app.media (owner, sha256);

-- Site settings editable in the admin panel (e.g. community links shown in the footer).
create table if not exists app.settings (
  key        text primary key check (key ~ '^[a-z0-9_.]{2,60}$'),
  value      jsonb not null,
  updated_by text,
  updated_at timestamptz not null default now()
);

-- Safe transactions proposed in the admin panel. QMS has no Safe web app, so owners sign here (EIP-712 SafeTx)
-- and any owner executes once enough have signed. The Safe re-checks every signature on-chain.
create table if not exists app.safe_proposals (
  id            bigserial primary key,
  chain_id      integer not null,
  safe          text not null check (safe ~ '^0x[0-9a-f]{40}$'),
  to_address    text not null check (to_address ~ '^0x[0-9a-f]{40}$'),
  value_wei     numeric(78,0) not null default 0 check (value_wei >= 0),
  data          text not null check (data ~ '^0x([0-9a-f]{2})*$' and char_length(data) <= 20000),
  nonce         bigint not null check (nonce >= 0),
  safe_tx_hash  text not null check (safe_tx_hash ~ '^0x[0-9a-f]{64}$'),
  kind          text not null check (char_length(kind) between 1 and 40),
  label         text not null check (char_length(label) between 1 and 200),
  status        text not null default 'pending' check (status in ('pending', 'executed', 'failed', 'replaced', 'discarded')),
  created_by    text not null,
  created_at    timestamptz not null default now(),
  executed_tx   text,
  executed_by   text,
  executed_at   timestamptz,
  updated_at    timestamptz not null default now()
);
create index if not exists safe_proposals_queue on app.safe_proposals (chain_id, safe, status, nonce);
create unique index if not exists safe_proposals_hash on app.safe_proposals (chain_id, safe_tx_hash) where status <> 'discarded';

create table if not exists app.safe_signatures (
  proposal_id  bigint not null references app.safe_proposals (id) on delete cascade,
  signer       text not null check (signer ~ '^0x[0-9a-f]{40}$'),
  signature    text not null check (signature ~ '^0x[0-9a-f]{130}$'),
  created_at   timestamptz not null default now(),
  primary key (proposal_id, signer)
);

-- On-chain history of the FeeVault and the Safe (withdrawals, executed Safe transactions, owner changes),
-- read from the chain by the API so it also shows actions done outside the panel (e.g. safe-tx.ps1).
create table if not exists app.treasury_events (
  chain_id   integer not null,
  address    text not null,
  block      bigint not null,
  log_index  integer not null,
  tx_hash    text not null,
  name       text not null,
  args       jsonb not null default '{}',
  block_time timestamptz,
  primary key (chain_id, tx_hash, log_index)
);
create index if not exists treasury_events_idx on app.treasury_events (chain_id, name, block desc);

create table if not exists app.treasury_cursor (
  chain_id   integer not null,
  scope      text not null,
  scanned_to bigint not null,
  updated_at timestamptz not null default now(),
  primary key (chain_id, scope)
);

-- Creators' connected X accounts (05_x_connect.sql for existing databases).
alter table app.users add column if not exists x_user_id text;
alter table app.users add column if not exists x_username text check (x_username is null or x_username ~ '^[A-Za-z0-9_]{1,15}$');
alter table app.users add column if not exists x_connected_at timestamptz;

-- Profile privacy (09_profile_privacy.sql for existing databases): a wallet can hide its collected items and
-- its activity on Quantly's pages and API. The wallet itself still sees everything; the blockchain stays public.
alter table app.users add column if not exists hide_collected boolean not null default false;
alter table app.users add column if not exists hide_activity boolean not null default false;

-- Pending "Connect X" attempts (10 minutes, used once).
create table if not exists app.x_oauth (
  state      text primary key check (char_length(state) between 20 and 100),
  address    text not null check (address ~ '^0x[0-9a-f]{40}$'),
  verifier   text not null,
  return_to  text not null,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null
);

-- Developer API keys (08_api_keys.sql for existing databases). A developer asks for a key on the website, an
-- admin approves it, and the owner sees it once. Only a SHA-256 hash and a short prefix are stored, never the
-- key; the optional contact is encrypted by the backend first; usage is one counter per key per day (no IPs).
create table if not exists app.api_keys (
  id            uuid primary key default gen_random_uuid(),
  address       text not null check (address ~ '^0x[0-9a-f]{40}$'),               -- wallet that owns the key
  project       text not null check (char_length(project) between 3 and 60),
  use_case      text not null check (char_length(use_case) between 20 and 1000),
  website       text check (website is null or (website ~ '^https://' and char_length(website) <= 300)),
  contact_enc   text check (contact_enc is null or (contact_enc like 'v1:%' and char_length(contact_enc) <= 600)), -- ciphertext only
  status        text not null default 'pending' check (status in ('pending', 'active', 'paused', 'rejected', 'revoked')),
  tier          text not null default 'free' check (tier in ('free', 'partner')),
  per_minute    integer not null default 60 check (per_minute between 1 and 600),          -- hard caps, whatever the API sends
  per_day       integer not null default 10000 check (per_day between 1 and 1000000),
  key_prefix    text check (key_prefix ~ '^qk_live_[0-9A-Za-z]{6}$'),
  key_hash      text check (key_hash ~ '^[0-9a-f]{64}$'),                                 -- SHA-256 of the key, hex
  reject_reason text check (reject_reason is null or char_length(reject_reason) <= 500),
  admin_note    text check (admin_note is null or char_length(admin_note) <= 2000),     -- internal, never shown to the owner
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now(),
  approved_at   timestamptz,
  approved_by   text,
  rejected_at   timestamptz,
  rejected_by   text,
  revealed_at   timestamptz,                                                             -- first time the owner saw the key
  rotated_at    timestamptz,
  revoked_at    timestamptz,
  revoked_by    text,
  last_used_at  timestamptz,                                                             -- updated at most once a minute
  check (key_hash is null or key_prefix is not null)
);
-- Keys are looked up by their prefix, then the hash is compared in constant time.
create unique index if not exists api_keys_prefix on app.api_keys (key_prefix) where key_prefix is not null;
-- At most one open request per wallet (checked by the database, so two quick clicks can't create two).
create unique index if not exists api_keys_one_pending on app.api_keys (address) where status = 'pending';
create index if not exists api_keys_address_idx on app.api_keys (address, created_at desc);
create index if not exists api_keys_status_idx on app.api_keys (status, created_at desc);

-- Requests per key per UTC day. The API adds to it in small batches every few seconds.
create table if not exists app.api_key_usage (
  key_id    uuid not null references app.api_keys (id) on delete cascade,
  day       date not null,
  requests  integer not null default 0 check (requests >= 0),
  primary key (key_id, day)
);

-- Lock every app table: RLS on, only quantly_api allowed.
do $$
declare t text;
begin
  foreach t in array array['networks','admins','users','auth_nonces','support_tickets','ticket_messages','audit_log','media','settings',
                        'safe_proposals','safe_signatures','treasury_events','treasury_cursor','x_oauth',
                        'api_keys','api_key_usage'] loop
    execute format('alter table app.%I enable row level security', t);
    execute format('drop policy if exists api_all on app.%I', t);
    execute format('create policy api_all on app.%I for all to quantly_api using (true) with check (true)', t);
  end loop;
end $$;
grant select, insert, update, delete on all tables in schema app to quantly_api;
grant usage, select on all sequences in schema app to quantly_api;
revoke update, delete on app.audit_log from quantly_api;  -- audit log is append-only for the API
revoke delete, truncate on app.api_keys, app.api_key_usage from quantly_api;  -- API keys are revoked, never deleted

-- ── Per-chain data schema (one per network) ────────────────────────────────────────
create or replace function app.ensure_chain_schema(p_chain_id integer)
returns text
language plpgsql
security definer
set search_path = pg_catalog, pg_temp
as $fn$
declare
  s text := 'chain_' || p_chain_id::text;
  t text;
begin
  if p_chain_id is null or p_chain_id <= 0 then
    raise exception 'invalid chain id';
  end if;
  execute format('create schema if not exists %I', s);

  execute format($ddl$
    create table if not exists %1$I.collections (
      address          text primary key check (address ~ '^0x[0-9a-f]{40}$'),
      chain_id         integer not null default %2$s,
      slug             text unique not null,
      name             text not null,
      symbol           text,
      description      text not null default '',
      image_url        text,
      banner_url       text,
      art_style        text not null default 'tile',
      creator          text,
      royalty_bps      integer not null default 0,
      royalty_receiver text,
      max_supply       integer,
      total_supply     integer not null default 0,
      contract_uri     text,
      twitter          text,
      website          text,
      discord          text,
      telegram         text,
      verified         boolean not null default false,
      is_official      boolean not null default false,
      is_external      boolean not null default false,
      featured         boolean not null default false,
      hidden           boolean not null default false,
      tradable         boolean not null default true,
      revealed         boolean,
      metadata_frozen  boolean not null default false,
      mint_paused      boolean not null default false,
      drop_hidden      boolean not null default false,
      floor_wei        numeric(78,0),
      best_offer_wei   numeric(78,0),
      volume_wei       numeric(78,0) not null default 0,
      volume_24h_wei   numeric(78,0) not null default 0,
      sales_count      integer not null default 0,
      owners_count     integer not null default 0,
      listed_count     integer not null default 0,
      created_at       timestamptz not null default now()
    )$ddl$, s, p_chain_id);
  -- upgrades for schemas created by an earlier version
  execute format('alter table %I.collections add column if not exists discord text', s);
  execute format('alter table %I.collections add column if not exists telegram text', s);
  -- About tab (written by the creator in the Studio, or by an admin)
  execute format('alter table %I.collections add column if not exists about text', s);
  execute format('alter table %I.collections add column if not exists about_image_url text', s);
  execute format($a$alter table %I.collections add column if not exists about_items jsonb not null default '[]'$a$, s);
  execute format('alter table %I.collections add column if not exists drop_hidden boolean not null default false', s);
  -- up to three extra images shown with the logo on the mint page (set by the creator or an admin)
  execute format($a$alter table %I.collections add column if not exists gallery jsonb not null default '[]'$a$, s);
  -- limits on the extra images and the About fields, enforced by the database itself whatever the API sends
  if not exists (select 1 from pg_constraint where conname = 'collections_gallery_check' and conrelid = format('%I.collections', s)::regclass) then
    execute format($a$alter table %I.collections add constraint collections_gallery_check
      check (jsonb_typeof(gallery) = 'array' and jsonb_array_length(gallery) <= 3 and pg_column_size(gallery) <= 4096
         and not jsonb_path_exists(gallery, '$[*] ? (@.type() != "string")'))$a$, s);
  end if;
  if not exists (select 1 from pg_constraint where conname = 'collections_about_check' and conrelid = format('%I.collections', s)::regclass) then
    execute format($a$alter table %I.collections add constraint collections_about_check
      check ((about is null or char_length(about) <= 8000)
         and (about_image_url is null or char_length(about_image_url) <= 500)
         and jsonb_typeof(about_items) = 'array' and jsonb_array_length(about_items) <= 12 and pg_column_size(about_items) <= 32768)$a$, s);
  end if;
  execute format('create index if not exists collections_volume_idx on %I.collections (volume_24h_wei desc)', s);
  execute format('create index if not exists collections_created_idx on %I.collections (created_at desc)', s);

  execute format($ddl$
    create table if not exists %1$I.tokens (
      collection    text not null references %1$I.collections(address) on delete cascade,
      token_id      numeric(78,0) not null,
      owner         text,
      name          text,
      image_url     text,
      attributes    jsonb not null default '[]',
      rarity_rank   integer,
      last_sale_wei numeric(78,0),
      hidden        boolean not null default false,
      minted_at     timestamptz default now(),
      primary key (collection, token_id)
    )$ddl$, s);
  execute format('create index if not exists tokens_owner_idx on %I.tokens (owner)', s);
  execute format('create index if not exists tokens_attr_idx on %I.tokens using gin (attributes jsonb_path_ops)', s);

  execute format($ddl$
    create table if not exists %1$I.orders (
      hash       text primary key,
      chain_id   integer not null default %2$s,
      kind       text not null check (kind in ('listing','offer','collection_offer')),
      collection text not null references %1$I.collections(address) on delete cascade,
      token_id   numeric(78,0),
      maker      text not null,
      price_wei  numeric(78,0) not null check (price_wei > 0),
      currency   text not null default 'QMS',
      status     text not null default 'active' check (status in ('active','filled','cancelled','expired','inactive')),
      start_time timestamptz not null default now(),
      end_time   timestamptz not null,
      counter    numeric(78,0) not null default 0,
      order_json jsonb,
      tx_hash    text,
      created_at timestamptz not null default now(),
      updated_at timestamptz not null default now()
    )$ddl$, s, p_chain_id);
  execute format('create index if not exists orders_floor_idx on %I.orders (collection, kind, status, price_wei)', s);
  execute format('create index if not exists orders_token_idx on %I.orders (collection, token_id, kind, status)', s);
  execute format('create index if not exists orders_maker_idx on %I.orders (maker, status)', s);

  execute format($ddl$
    create table if not exists %1$I.activity (
      id         bigserial primary key,
      chain_id   integer not null default %2$s,
      type       text not null,
      collection text not null references %1$I.collections(address) on delete cascade,
      token_id   numeric(78,0),
      from_addr  text,
      to_addr    text,
      price_wei  numeric(78,0),
      tx_hash    text,
      order_hash text,
      log_index  integer,
      created_at timestamptz not null default now()
    )$ddl$, s, p_chain_id);
  execute format('create index if not exists activity_collection_idx on %I.activity (collection, created_at desc)', s);
  execute format('create index if not exists activity_token_idx on %I.activity (collection, token_id, created_at desc)', s);
  execute format('create index if not exists activity_from_idx on %I.activity (from_addr, created_at desc)', s);
  execute format('create index if not exists activity_to_idx on %I.activity (to_addr, created_at desc)', s);
  execute format('create index if not exists activity_time_idx on %I.activity (created_at desc)', s);
  execute format('create unique index if not exists activity_log_uniq on %I.activity (tx_hash, log_index, type) where tx_hash is not null and log_index is not null', s);

  execute format($ddl$
    create table if not exists %1$I.drops (
      collection       text primary key references %1$I.collections(address) on delete cascade,
      phases           jsonb not null default '[]',
      platform_fee_bps integer not null default 1000,
      featured         boolean not null default false,
      created_at       timestamptz not null default now()
    )$ddl$, s);

  execute format($ddl$
    create table if not exists %1$I.allowlists (
      id         uuid primary key default gen_random_uuid(),
      root       text not null,
      addresses  jsonb not null,
      tree       jsonb not null,
      created_by text,
      created_at timestamptz not null default now()
    )$ddl$, s);

  execute format($ddl$
    create table if not exists %1$I.fee_ledger (
      id         bigserial primary key,
      source     text not null check (source in ('mint','trade')),
      collection text,
      amount_wei numeric(78,0) not null,
      tx_hash    text,
      created_at timestamptz not null default now()
    )$ddl$, s);

  -- Fee ledger rows are keyed by log so re-indexing a block range never counts a fee twice.
  execute format('alter table %I.fee_ledger add column if not exists log_index integer', s);
  execute format('create unique index if not exists fee_ledger_log_uniq on %I.fee_ledger (tx_hash, log_index) where tx_hash is not null and log_index is not null', s);

  -- Mint configuration edits made after minting started (shown as an alert on the mint page).
  execute format($ddl$
    create table if not exists %1$I.phase_changes (
      id         bigserial primary key,
      collection text not null references %1$I.collections(address) on delete cascade,
      tx_hash    text,
      changes    jsonb not null,
      changed_at timestamptz not null default now()
    )$ddl$, s);
  execute format('create unique index if not exists phase_changes_tx on %I.phase_changes (collection, tx_hash) where tx_hash is not null', s);
  execute format('create index if not exists phase_changes_time on %I.phase_changes (collection, changed_at desc)', s);

  -- Hourly snapshots for analytics charts (floor history etc.).
  execute format($ddl$
    create table if not exists %1$I.snapshots (
      collection     text not null references %1$I.collections(address) on delete cascade,
      taken_at       timestamptz not null,
      floor_wei      numeric(78,0),
      best_offer_wei numeric(78,0),
      listed_count   integer not null default 0,
      owners_count   integer not null default 0,
      volume_wei     numeric(78,0) not null default 0,
      sales_count    integer not null default 0,
      primary key (collection, taken_at)
    )$ddl$, s);

  execute format('create table if not exists %I.indexer_state (key text primary key, value text not null)', s);

  -- Lock it down exactly like the app schema.
  execute format('revoke all on schema %I from public', s);
  execute format('grant usage on schema %I to quantly_api', s);
  foreach t in array array['collections','tokens','orders','activity','drops','allowlists','fee_ledger','indexer_state','phase_changes','snapshots'] loop
    execute format('alter table %I.%I enable row level security', s, t);
    execute format('drop policy if exists api_all on %I.%I', s, t);
    execute format('create policy api_all on %I.%I for all to quantly_api using (true) with check (true)', s, t);
  end loop;
  execute format('grant select, insert, update, delete on all tables in schema %I to quantly_api', s);
  execute format('grant usage, select on all sequences in schema %I to quantly_api', s);
  return s;
end
$fn$;
revoke all on function app.ensure_chain_schema(integer) from public;
grant execute on function app.ensure_chain_schema(integer) to quantly_api;

-- Belt and braces for Supabase: the public API roles get nothing in our schemas.
do $$
begin
  if exists (select 1 from pg_roles where rolname = 'anon') then
    execute 'revoke all on schema app from anon, authenticated';
    execute 'revoke all on all tables in schema app from anon, authenticated';
    execute 'revoke execute on function app.ensure_chain_schema(integer) from anon, authenticated';
  end if;
end $$;

-- ── Default network: QMS Testnet (contract addresses are filled in the admin panel or from env) ──
insert into app.networks (key, chain_id, name, rpc_url, public_rpc_url, explorer_url, explorer_api_url, is_testnet, is_active)
values ('qms-testnet', 19480, 'QMS Testnet', 'https://rpc.testnet.qms.finance', 'https://rpc.testnet.qms.finance',
        'https://testnet.qmsscan.io', 'https://testnet.qmsscan.io/api/v2', true,
        not exists (select 1 from app.networks where is_active))
on conflict (key) do nothing;

select app.ensure_chain_schema(19480);

-- ── Part 3: backend login ──────────────────────────────────────────────────────────
do $$
begin
  if not (select rolcanlogin from pg_roles where rolname = 'quantly_api') then
    execute format('alter role quantly_api with login password %L', current_setting('quantly.api_password'));
  end if;
end $$;
alter role quantly_api set statement_timeout = '15s';
alter role quantly_api set idle_in_transaction_session_timeout = '30s';

-- ── Part 4: lock-down ──────────────────────────────────────────────────────────────
-- Our schemas give nothing to PUBLIC or to the roles behind Supabase's public API keys.
-- Only quantly_api keeps the exact rights granted in Part 2.
do $$
declare s text; r text;
begin
  for s in select nspname from pg_namespace where nspname = 'app' or nspname ~ '^chain_[0-9]+$' loop
    execute format('revoke all on schema %I from public', s);
    execute format('revoke all on all tables in schema %I from public', s);
    execute format('revoke all on all sequences in schema %I from public', s);
    execute format('revoke all on all functions in schema %I from public', s);
    foreach r in array array['anon', 'authenticated', 'service_role'] loop
      if exists (select 1 from pg_roles where rolname = r) then
        execute format('revoke all on schema %I from %I', s, r);
        execute format('revoke all on all tables in schema %I from %I', s, r);
        execute format('revoke all on all sequences in schema %I from %I', s, r);
        execute format('revoke all on all functions in schema %I from %I', s, r);
      end if;
    end loop;
    execute format('revoke truncate, references, trigger on all tables in schema %I from quantly_api', s);
  end loop;
end $$;
revoke update, delete on app.audit_log from quantly_api;   -- the audit log can only be added to
revoke delete on app.api_keys, app.api_key_usage from quantly_api;   -- API keys are revoked, never deleted

commit;

-- ── Part 5: security report (every row must say PASS) ──────────────────────────────
with
scope as (select oid, nspname from pg_namespace where nspname = 'app' or nspname ~ '^chain_[0-9]+$'),
tabs  as (select c.oid, s.nspname, c.relname, c.relrowsecurity, c.relowner, c.relacl
          from pg_class c join scope s on s.oid = c.relnamespace where c.relkind in ('r', 'p')),
seqs  as (select c.oid, c.relacl from pg_class c join scope s on s.oid = c.relnamespace where c.relkind = 'S'),
api   as (select * from pg_roles where rolname = 'quantly_api'),
outsiders as (select oid, rolname from pg_roles where rolname in ('anon', 'authenticated', 'service_role')),
checks (n, what, bad, detail) as (
  select 1, 'Tables exist (app and chain_19480)',
         (select case when count(*) filter (where nspname = 'app') >= 14
                       and count(*) filter (where nspname = 'chain_19480') >= 10 then 0 else 1 end from tabs),
         (select count(*) || ' tables' from tabs)
  union all
  select 2, 'Row level security is on for every table',
         (select count(*) from tabs where not relrowsecurity),
         (select coalesce(string_agg(nspname || '.' || relname, ', '), 'all on') from tabs where not relrowsecurity)
  union all
  select 3, 'Every table has a policy, and only for quantly_api',
         (select count(*) from tabs t where not exists (select 1 from pg_policies p where p.schemaname = t.nspname and p.tablename = t.relname))
       + (select count(*) from pg_policies p join scope s on s.nspname = p.schemaname where p.roles <> '{quantly_api}'),
         (select count(*) || ' policies' from pg_policies p join scope s on s.nspname = p.schemaname)
  union all
  select 4, 'PUBLIC has no rights on the schemas, tables, sequences or functions',
         (select count(*) from scope s, aclexplode(coalesce((select nspacl from pg_namespace where oid = s.oid), '{}')) a where a.grantee = 0)
       + (select count(*) from tabs t, aclexplode(coalesce(t.relacl, '{}')) a where a.grantee = 0)
       + (select count(*) from seqs q, aclexplode(coalesce(q.relacl, '{}')) a where a.grantee = 0)
       + (select count(*) from pg_proc f join scope s on s.oid = f.pronamespace where f.proacl is null)
       + (select count(*) from pg_proc f join scope s on s.oid = f.pronamespace, aclexplode(coalesce(f.proacl, '{}')) a where a.grantee = 0),
         'schemas, tables, sequences and functions checked'
  union all
  select 5, 'Supabase API roles (anon, authenticated, service_role) cannot enter the schemas',
         (select count(*) from scope s, outsiders o where has_schema_privilege(o.oid, s.oid, 'usage') or has_schema_privilege(o.oid, s.oid, 'create')),
         (select count(*) || ' of these roles exist here' from outsiders)
  union all
  select 6, 'Supabase API roles have no rights on any table, sequence or function',
         (select count(*) from tabs t, outsiders o where has_table_privilege(o.oid, t.oid, 'select, insert, update, delete, truncate, references, trigger'))
       + (select count(*) from seqs q, outsiders o where has_sequence_privilege(o.oid, q.oid, 'usage, select, update'))
       + (select count(*) from pg_proc f join scope s on s.oid = f.pronamespace, outsiders o where has_function_privilege(o.oid, f.oid, 'execute')),
         'checked every object'
  union all
  select 7, 'quantly_api can log in and is a plain role (no superuser, createdb, createrole, replication, bypass RLS)',
         (select case when count(*) = 1 and bool_and(rolcanlogin and not rolsuper and not rolcreatedb and not rolcreaterole
                                                      and not rolreplication and not rolbypassrls) then 0 else 1 end from api),
         (select 'login=' || rolcanlogin || ' super=' || rolsuper || ' bypassrls=' || rolbypassrls from api)
  union all
  select 8, 'quantly_api belongs to no other role and owns nothing',
         (select count(*) from pg_auth_members m join api on api.oid = m.member)
       + (select count(*) from pg_class c join api on api.oid = c.relowner)
       + (select count(*) from pg_namespace n join api on api.oid = n.nspowner)
       + (select count(*) from pg_proc f join api on api.oid = f.proowner),
         'role memberships and owned objects checked'
  union all
  select 9, 'quantly_api cannot create, alter or drop tables (no CREATE on app, chain_* or public)',
         (select count(*) from scope s where has_schema_privilege('quantly_api', s.oid, 'create'))
       + (select case when has_schema_privilege('quantly_api', 'public', 'create') then 1 else 0 end),
         'app, chain_* and public checked'
  union all
  select 10, 'quantly_api cannot TRUNCATE, add triggers or add foreign keys on any table',
         (select count(*) from tabs t where has_table_privilege('quantly_api', t.oid, 'truncate, references, trigger')),
         'every table checked'
  union all
  select 11, 'Audit log is append-only (quantly_api cannot update, delete or truncate it)',
         (select case when has_table_privilege('quantly_api', 'app.audit_log', 'update, delete, truncate') then 1 else 0 end),
         (select 'insert=' || has_table_privilege('quantly_api', 'app.audit_log', 'insert')
              || ' select=' || has_table_privilege('quantly_api', 'app.audit_log', 'select'))
  union all
  select 12, 'Schema function is pinned (security definer with a fixed search_path)',
         (select count(*) from pg_proc f join scope s on s.oid = f.pronamespace
           where f.prosecdef and not exists (select 1 from unnest(coalesce(f.proconfig, '{}')) c where c like 'search_path=%')),
         (select count(*) || ' functions' from pg_proc f join scope s on s.oid = f.pronamespace)
  union all
  select 13, 'Query time limits are set for quantly_api',
         (select case when count(*) filter (where c like 'statement_timeout=%') = 1
                       and count(*) filter (where c like 'idle_in_transaction_session_timeout=%') = 1 then 0 else 1 end
            from pg_db_role_setting d join api on api.oid = d.setrole, unnest(d.setconfig) c where d.setdatabase = 0),
         (select coalesce(string_agg(c, ', '), 'none') from pg_db_role_setting d join api on api.oid = d.setrole, unnest(d.setconfig) c where d.setdatabase = 0)
  union all
  select 14, 'QMS Testnet (19480) is registered and active',
         (select case when count(*) = 1 then 0 else 1 end from app.networks where chain_id = 19480 and is_active),
         (select coalesce(string_agg(key || ' active=' || is_active, ', '), 'missing') from app.networks where chain_id = 19480)
  union all
  select 15, 'Collection extra images are installed, with size limits enforced by the database',
         (select count(*) from scope s where s.nspname <> 'app'
            and (not exists (select 1 from pg_attribute a join pg_class c on c.oid = a.attrelid
                              where c.relnamespace = s.oid and c.relname = 'collections' and a.attname = 'gallery' and not a.attisdropped)
              or (select count(*) from pg_constraint k join pg_class c on c.oid = k.conrelid
                   where c.relnamespace = s.oid and c.relname = 'collections'
                     and k.conname in ('collections_gallery_check', 'collections_about_check')) <> 2)),
         'gallery column and 2 limits per chain'
  union all
  select 16, 'Developer API key tables are installed, and quantly_api can never delete them',
         (select case when to_regclass('app.api_keys') is null or to_regclass('app.api_key_usage') is null then 1
                 else (case when has_table_privilege('quantly_api', 'app.api_keys', 'delete, truncate') then 1 else 0 end)
                    + (case when has_table_privilege('quantly_api', 'app.api_key_usage', 'delete, truncate') then 1 else 0 end) end),
         'keys are stored as hashes; revoked, never deleted'
  union all
  select 17, 'Profile privacy settings are installed',
         2 - (select count(*)::int from pg_attribute where attrelid = 'app.users'::regclass
                and attname in ('hide_collected', 'hide_activity') and not attisdropped),
         'hide collected items / hide activity'
)
select n as "#", what as "check", case when bad = 0 then 'PASS' else 'FAIL' end as result, bad as problems, detail
from checks order by n;
