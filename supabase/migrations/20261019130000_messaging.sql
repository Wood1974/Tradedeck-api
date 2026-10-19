-- STATUS: NOT YET APPLIED to production (apply was declined 2026-10-19, pending owner approval).
-- Remove this line once applied.

-- Direct messaging between any two TradeDeck members, before or after a hire.
--
-- Fixes the existing (unused) messaging tables:
--  * conversations / messages SELECT policies subqueried conversation_members,
--    which itself had no member-readable policy, so members could see nothing.
--    Replaced with a SECURITY DEFINER membership check.
--  * messages INSERT only checked sender_id = auth.uid(), so anyone could post
--    into any conversation id. Now requires membership.
--  * there was no way for a user to create a conversation. start_conversation()
--    finds-or-creates the 1:1 thread between the caller and one other user.
-- Adds: optional job context on a conversation, inbox + mark-read RPCs, body
-- length check, per-user rate limits, and realtime on messages.

alter table public.conversations add column if not exists job_id uuid references public.jobs(id) on delete set null;
alter table public.conversations add column if not exists last_message_at timestamptz default now();

alter table public.messages drop constraint if exists messages_body_length;
alter table public.messages add constraint messages_body_length check (char_length(btrim(body)) between 1 and 4000);

create index if not exists conversation_members_user_idx on public.conversation_members(user_id);
create index if not exists messages_conversation_created_idx on public.messages(conversation_id, created_at);
create index if not exists messages_sender_created_idx on public.messages(sender_id, created_at);

-- membership check that does not recurse through RLS
create or replace function public.is_conversation_member(cid uuid)
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from conversation_members where conversation_id = cid and user_id = auth.uid());
$$;
revoke all on function public.is_conversation_member(uuid) from public, anon;
grant execute on function public.is_conversation_member(uuid) to authenticated;

drop policy if exists "Members can read conversations" on public.conversations;
create policy "Members can read conversations" on public.conversations
  for select to authenticated using (public.is_conversation_member(id));

drop policy if exists "Members can read conversation members" on public.conversation_members;
create policy "Members can read conversation members" on public.conversation_members
  for select to authenticated using (public.is_conversation_member(conversation_id));

drop policy if exists "Members can read messages" on public.messages;
create policy "Members can read messages" on public.messages
  for select to authenticated using (public.is_conversation_member(conversation_id));

drop policy if exists "Members can send messages" on public.messages;
create policy "Members can send messages" on public.messages
  for insert to authenticated
  with check (auth.uid() = sender_id and public.is_conversation_member(conversation_id));

-- rate limit + bump conversation recency on every message
create or replace function public.messages_before_insert()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if auth.role() <> 'service_role' and not public.is_admin() then
    if (select count(*) from messages where sender_id = new.sender_id and created_at > now() - interval '1 minute') >= 20 then
      raise exception 'Slow down -- too many messages in a minute' using errcode = 'P0001';
    end if;
  end if;
  new.body := btrim(new.body);
  new.created_at := now();
  return new;
end $$;

create or replace function public.messages_after_insert()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  update conversations set last_message_at = new.created_at where id = new.conversation_id;
  update conversation_members set last_read_at = new.created_at
   where conversation_id = new.conversation_id and user_id = new.sender_id;
  return null;
end $$;

drop trigger if exists messages_before_insert on public.messages;
create trigger messages_before_insert before insert on public.messages
  for each row execute function public.messages_before_insert();
drop trigger if exists messages_after_insert on public.messages;
create trigger messages_after_insert after insert on public.messages
  for each row execute function public.messages_after_insert();

-- find or create the 1:1 conversation with another user
create or replace function public.start_conversation(p_other uuid, p_job_id uuid default null)
returns uuid language plpgsql security definer set search_path = public as $$
declare me uuid := auth.uid(); cid uuid;
begin
  if me is null then raise exception 'Sign in required' using errcode = '42501'; end if;
  if p_other is null or p_other = me then raise exception 'Pick someone else to message' using errcode = '22023'; end if;
  if not exists (select 1 from profiles where id = p_other) then raise exception 'User not found' using errcode = 'P0002'; end if;

  select m1.conversation_id into cid
    from conversation_members m1
    join conversation_members m2 on m2.conversation_id = m1.conversation_id and m2.user_id = p_other
   where m1.user_id = me
     and (select count(*) from conversation_members m3 where m3.conversation_id = m1.conversation_id) = 2
   limit 1;

  if cid is not null then
    if p_job_id is not null then
      update conversations set job_id = p_job_id where id = cid and job_id is null;
    end if;
    return cid;
  end if;

  if (select count(*) from conversations c join conversation_members m on m.conversation_id = c.id
       where m.user_id = me and c.created_at > now() - interval '1 day') >= 30 then
    raise exception 'Too many new conversations today' using errcode = 'P0001';
  end if;

  insert into conversations(job_id) values (p_job_id) returning id into cid;
  insert into conversation_members(conversation_id, user_id, last_read_at) values (cid, me, now()), (cid, p_other, null);
  return cid;
end $$;
revoke all on function public.start_conversation(uuid, uuid) from public, anon;
grant execute on function public.start_conversation(uuid, uuid) to authenticated;

-- inbox: one row per conversation, newest first, with the other person's
-- public profile fields only (same set as profiles_public), last message and unread count
create or replace function public.my_conversations()
returns table (
  conversation_id uuid, other_id uuid, other_name text, other_company text, other_trade text, other_tier int,
  job_id uuid, job_title text, last_body text, last_sender uuid, last_at timestamptz, unread int
) language sql stable security definer set search_path = public as $$
  select c.id, p.id, p.full_name, p.company, p.trade, p.tier::int,
         j.id, j.title, lm.body, lm.sender_id, coalesce(lm.created_at, c.created_at),
         (select count(*)::int from messages x
           where x.conversation_id = c.id and x.sender_id <> auth.uid()
             and x.created_at > coalesce(me.last_read_at, 'epoch'::timestamptz))
    from conversation_members me
    join conversations c on c.id = me.conversation_id
    join conversation_members o on o.conversation_id = c.id and o.user_id <> me.user_id
    join profiles p on p.id = o.user_id
    left join jobs j on j.id = c.job_id
    left join lateral (select body, sender_id, created_at from messages
                        where conversation_id = c.id order by created_at desc limit 1) lm on true
   where me.user_id = auth.uid()
   order by coalesce(lm.created_at, c.created_at) desc;
$$;
revoke all on function public.my_conversations() from public, anon;
grant execute on function public.my_conversations() to authenticated;

create or replace function public.mark_conversation_read(p_conversation_id uuid)
returns void language sql security definer set search_path = public as $$
  update conversation_members set last_read_at = now()
   where conversation_id = p_conversation_id and user_id = auth.uid();
$$;
revoke all on function public.mark_conversation_read(uuid) from public, anon;
grant execute on function public.mark_conversation_read(uuid) to authenticated;

-- realtime: postgres_changes on messages (RLS above decides who receives what)
do $$ begin
  if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and tablename = 'messages') then
    alter publication supabase_realtime add table public.messages;
  end if;
end $$;
