-- SPDX-License-Identifier: FSL-1.1-ALv2
-- Deny by default, version 4. The broker connects as the role that owns these tables (the owner isn't subject to
-- row-level security), and nothing else should read or write them. On Supabase, the `anon` and `authenticated` roles
-- reach whatever the REST API exposes: this schema isn't exposed, and in case someone exposes it or grants it later,
-- every table has row-level security on with no policy, so those roles see no rows and can write none. Roles with
-- BYPASSRLS (Supabase's `postgres` and `service_role`) and superusers aren't stopped by it, and neither are backups.
-- A later migration that adds a table must enable it too: storage/hosted-db.test.ts fails on any table without it.

do $$
declare
  s text := current_schema();
  t record;
  r text;
begin
  for t in select c.relname from pg_class c join pg_namespace n on n.oid = c.relnamespace
           where n.nspname = s and c.relkind in ('r', 'p') loop
    execute format('alter table %I.%I enable row level security', s, t.relname);
  end loop;
  execute format('revoke all on schema %I from public', s);
  execute format('revoke all on all tables in schema %I from public', s);
  foreach r in array array['anon', 'authenticated'] loop
    if exists (select 1 from pg_roles where rolname = r) then
      execute format('revoke all on all tables in schema %I from %I', s, r);
      execute format('revoke all on schema %I from %I', s, r);
      execute format('alter default privileges in schema %I revoke all on tables from %I', s, r);
    end if;
  end loop;
end
$$;
