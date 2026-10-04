-- Run once in the Supabase SQL Editor, AFTER 01_schema.sql.
-- Gives the backend its own least-privilege login.
--
-- Safe to re-run: the password below is only applied the FIRST time (while quantly_api cannot log in yet).
-- It never overwrites a password you already set. To change the password later, run on its own:
--   alter role quantly_api with login password 'your-new-long-random-password';
do $$
begin
  if not (select rolcanlogin from pg_roles where rolname = 'quantly_api') then
    alter role quantly_api with login password 'CHANGE_ME_TO_A_LONG_RANDOM_PASSWORD';
    raise notice 'quantly_api can now log in. Set a real password with: alter role quantly_api with login password ''...'';';
  end if;
end $$;
alter role quantly_api set statement_timeout = '15s';
alter role quantly_api set idle_in_transaction_session_timeout = '30s';

-- Backend DATABASE_URL (Supabase → Connect → Direct → Session pooler), user is quantly_api.<project-ref>:
-- postgresql://quantly_api.<project-ref>:<password>@aws-0-<region>.pooler.supabase.com:5432/postgres
