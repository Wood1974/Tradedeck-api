-- Minimal stand-in for the Supabase pieces the messaging migrations touch, in the
-- shape production had before the consent migration. Test-only; never run on Supabase.
do $$ begin
  if not exists (select from pg_roles where rolname = 'anon') then create role anon nologin; end if;
  if not exists (select from pg_roles where rolname = 'authenticated') then create role authenticated nologin; end if;
  if not exists (select from pg_roles where rolname = 'service_role') then create role service_role nologin bypassrls; end if;
end $$;
create schema auth;
create function auth.uid() returns uuid language sql stable
  as $$ select nullif(current_setting('request.jwt.claim.sub', true), '')::uuid $$;
create function auth.role() returns text language sql stable
  as $$ select nullif(current_setting('request.jwt.claim.role', true), '') $$;
create publication supabase_realtime;

create table public.profiles (id uuid primary key, full_name text, company text, trade text, tier int default 1, is_admin boolean default false);
create table public.jobs (id uuid primary key default gen_random_uuid(), title text, owner_id uuid references public.profiles(id));
create table public.conversations (id uuid primary key default gen_random_uuid(), created_at timestamptz default now());
create table public.conversation_members (
  conversation_id uuid references public.conversations(id) on delete cascade, user_id uuid, last_read_at timestamptz,
  primary key (conversation_id, user_id));
create table public.messages (
  id uuid primary key default gen_random_uuid(), conversation_id uuid references public.conversations(id) on delete cascade,
  sender_id uuid, body text not null, created_at timestamptz default now());
alter table public.conversations enable row level security;
alter table public.conversation_members enable row level security;
alter table public.messages enable row level security;

grant usage on schema public to anon, authenticated, service_role;
grant all on all tables in schema public to anon, authenticated, service_role;
-- Supabase's default: every new table in public is born open to anon and authenticated.
alter default privileges for role postgres in schema public grant all on tables to anon, authenticated, service_role;

create function public.is_admin() returns boolean language sql stable security definer set search_path to 'public'
  as $$ select coalesce((select is_admin from profiles where id = auth.uid()), false); $$;

create policy "Members can read conversations" on public.conversations for select to authenticated using (true);
create policy "Members can read messages" on public.messages for select to authenticated using (true);
create policy "Members can send messages" on public.messages for insert to authenticated with check (auth.uid() = sender_id);
create policy "Admins have full access to conversations" on public.conversations for all using (is_admin()) with check (is_admin());
create policy "Admins have full access to conversation_members" on public.conversation_members for all using (is_admin()) with check (is_admin());
create policy "Admins have full access to messages" on public.messages for all using (is_admin()) with check (is_admin());
