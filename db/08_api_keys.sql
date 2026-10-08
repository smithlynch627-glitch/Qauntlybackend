-- =====================================================================================
-- Quantly API keys: developers request a key on the website, an admin approves it, and the owner reveals it once.
-- The keys give read-only access to the public API (/api/v1).
-- Run once in Supabase: SQL Editor → paste → Run. Safe to run again (idempotent).
--
-- What is stored
--   • Never the key itself: only its SHA-256 hash and a short public prefix (qk_live_ + 6 characters) to find it.
--   • The optional contact (email or handle) is encrypted by the backend (AES-256-GCM) before it gets here.
--   • Usage is one counter per key per UTC day. No IP addresses are stored.
-- =====================================================================================

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

-- Lock both tables like every other app table: RLS on, one policy for quantly_api, nothing for anyone else.
do $$
declare t text; r text;
begin
  foreach t in array array['api_keys', 'api_key_usage'] loop
    execute format('alter table app.%I enable row level security', t);
    execute format('drop policy if exists api_all on app.%I', t);
    execute format('create policy api_all on app.%I for all to quantly_api using (true) with check (true)', t);
    execute format('revoke all on app.%I from public', t);
    execute format('grant select, insert, update on app.%I to quantly_api', t);   -- rows are never deleted by the API
    execute format('revoke delete, truncate, references, trigger on app.%I from quantly_api', t);
    foreach r in array array['anon', 'authenticated', 'service_role'] loop
      if exists (select 1 from pg_roles where rolname = r) then
        execute format('revoke all on app.%I from %I', t, r);
      end if;
    end loop;
  end loop;
end $$;
