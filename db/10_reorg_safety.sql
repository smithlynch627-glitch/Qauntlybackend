-- =====================================================================================
-- Quantly: reorg protection for the indexer, and the team-reserve column (9 October version).
--
-- QMS makes blocks by proof-of-(useful-)work and has no finality layer yet, so a recent block can be replaced.
-- The indexer now remembers the block every processed transaction came from (indexed_txs). When that block is
-- replaced, it undoes what the transaction wrote and reads it again, so sales, fees and owners always match the chain.
-- collections.mint_cap: how far mints can go once a team reserve is set aside, so drops show "sold out" correctly.
--
-- Only for a database created BEFORE this file existed. Running db/setup_all.sql again does the same thing and also
-- updates the security report (row 18), so prefer that. Safe to run more than once.
-- Until one of them has run, the site keeps working; the indexer logs that reorg protection is off.
-- =====================================================================================

do $$
declare s text;
begin
  for s in select nspname from pg_namespace where nspname ~ '^chain_[0-9]+$' loop
    if to_regclass(format('%I.collections', s)) is not null then
      execute format('alter table %I.collections add column if not exists mint_cap integer check (mint_cap is null or mint_cap >= 0)', s);
    end if;
    execute format($ddl$
      create table if not exists %1$I.indexed_txs (
        tx_hash             text primary key check (tx_hash ~ '^0x[0-9a-f]{64}$'),
        block_number        bigint not null check (block_number >= 0),
        block_hash          text not null check (block_hash ~ '^0x[0-9a-f]{64}$'),
        created_collections text[] not null default '{}'
      )$ddl$, s);
    execute format('create index if not exists indexed_txs_block on %I.indexed_txs (block_number)', s);
    execute format('alter table %I.indexed_txs enable row level security', s);
    execute format('drop policy if exists api_all on %I.indexed_txs', s);
    execute format('create policy api_all on %I.indexed_txs for all to quantly_api using (true) with check (true)', s);
    execute format('revoke all on %I.indexed_txs from public', s);
    execute format('grant select, insert, update, delete on %I.indexed_txs to quantly_api', s);
  end loop;
end $$;
