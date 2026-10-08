-- Quantly: security report for the database. Read-only, changes nothing.
-- Supabase → SQL Editor → paste → Run. Every row must say PASS.
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
