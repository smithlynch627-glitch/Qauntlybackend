-- Only for a database that was created BEFORE this file existed.
-- Renames the networks column that holds the wrapped coin (WQMS) address. Safe to run more than once;
-- a database created from the current 01_schema.sql already has the new name and nothing changes.
do $$
begin
  if exists (select 1 from information_schema.columns where table_schema = 'app' and table_name = 'networks' and column_name = 'weth_address')
     and not exists (select 1 from information_schema.columns where table_schema = 'app' and table_name = 'networks' and column_name = 'wrapped_address') then
    execute 'alter table app.networks rename column ' || quote_ident('weth_address') || ' to wrapped_address';
  end if;
end $$;
