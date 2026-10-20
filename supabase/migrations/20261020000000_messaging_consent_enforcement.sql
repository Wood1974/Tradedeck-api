-- Messaging: make mutual opt-in a database rule, not just a UI hint.
--
-- Closes the findings in the 2026-10-19 messaging review:
--  1. Sending required only "sender is me and I am a member". A member could post
--     into a pending or declined thread straight through the API, and new threads
--     defaulted to accepted. Now: new threads are pending with a requester, and
--     the INSERT policy requires status = 'accepted'.
--  5. Rate limits and find-or-create were check-then-act and could race. Now
--     serialized with transaction advisory locks; a unique pair key is the backstop.
--  6. start_conversation accepted any job id. Now the job must exist and belong to
--     the caller or the other person, and an existing thread's job is never replaced.
--  7. anon and authenticated held every table privilege (incl. TRUNCATE, TRIGGER)
--     on the three messaging tables. Now: SELECT, plus INSERT of three columns on
--     messages. Everything else goes through the RPCs below.
--  + conversations is published to Realtime so accept/decline reach open clients.
--
-- Not changed here: the "Admins have full access" policies (finding 4). Who may
-- read messages is the owner's decision. Admins lose client UPDATE/DELETE through
-- the grant change in step 6; their SELECT is unchanged.
--
-- Supersedes pending/20261019_messaging_mutual_opt_in.sql in the frontend repo.
-- Idempotent. Safe on production as it stands (status/requested_by already exist
-- there, created by hand) and on a database built from the repo.
--
-- DO NOT replay 20261019130000_messaging.sql after this file: it recreates the
-- consent-free send policy and start_conversation.

-- 1. Schema the repo never recorded ---------------------------------------------

alter table public.conversations add column if not exists status text not null default 'accepted';
alter table public.conversations add column if not exists requested_by uuid references public.profiles(id) on delete set null;
alter table public.conversations add column if not exists pair_key text;

-- Threads created from here on must say what they are. Existing rows keep their value.
alter table public.conversations alter column status set default 'pending';

do $$ begin
  if not exists (select 1 from pg_constraint where conname = 'conversations_status_check'
                  and conrelid = 'public.conversations'::regclass) then
    alter table public.conversations
      add constraint conversations_status_check check (status in ('pending', 'accepted', 'declined'));
  end if;
end $$;

-- One thread per pair. Backfill from members, then enforce.
update public.conversations c
   set pair_key = (select least(min(user_id::text), max(user_id::text)) || ':' || greatest(min(user_id::text), max(user_id::text))
                     from public.conversation_members m where m.conversation_id = c.id)
 where c.pair_key is null
   and (select count(*) from public.conversation_members m where m.conversation_id = c.id) = 2;

create unique index if not exists conversations_pair_key_uidx on public.conversations(pair_key) where pair_key is not null;

-- 2. start_conversation -----------------------------------------------------------

create or replace function public.start_conversation(p_other uuid, p_job_id uuid default null)
returns uuid
language plpgsql
security definer
set search_path to 'public'
as $function$
declare me uuid := auth.uid(); cid uuid; pk text; job_owner uuid;
begin
  if me is null then raise exception 'Sign in required' using errcode = '42501'; end if;
  if p_other is null or p_other = me then raise exception 'Pick someone else to message' using errcode = '22023'; end if;
  if not exists (select 1 from profiles where id = p_other) then raise exception 'User not found' using errcode = 'P0002'; end if;

  -- Job context is only allowed for a job that one of the two people owns.
  if p_job_id is not null then
    select owner_id into job_owner from jobs where id = p_job_id;
    if not found or job_owner is null or job_owner not in (me, p_other) then
      raise exception 'That job is not shared between you' using errcode = '42501';
    end if;
  end if;

  -- Serialize per pair so two simultaneous starts cannot both create a thread.
  -- Always pair lock first, user lock second: no lock cycle is possible.
  pk := least(me::text, p_other::text) || ':' || greatest(me::text, p_other::text);
  perform pg_advisory_xact_lock(hashtextextended('conv-pair:' || pk, 0));

  select id into cid from conversations where pair_key = pk;
  if cid is not null then
    if p_job_id is not null then
      update conversations set job_id = p_job_id where id = cid and job_id is null;
    end if;
    return cid;
  end if;

  -- Only requests this person started count toward their daily limit. Being
  -- messaged by others must not use up someone's allowance.
  perform pg_advisory_xact_lock(hashtextextended('conv-user:' || me::text, 0));
  if (select count(*) from conversations where requested_by = me and created_at > now() - interval '1 day') >= 30 then
    raise exception 'Too many new conversations today' using errcode = 'P0001';
  end if;

  insert into conversations(job_id, status, requested_by, pair_key) values (p_job_id, 'pending', me, pk) returning id into cid;
  insert into conversation_members(conversation_id, user_id, last_read_at) values (cid, me, now()), (cid, p_other, null);
  return cid;
end $function$;

-- 3. Requests: current live bodies, now recorded in the repo ------------------------

create or replace function public.respond_to_request(p_conversation_id uuid, p_accept boolean)
returns text
language plpgsql
security definer
set search_path to 'public'
as $function$
declare me uuid := auth.uid(); c conversations%rowtype;
begin
  if me is null then raise exception 'Sign in required' using errcode = '42501'; end if;
  select * into c from conversations where id = p_conversation_id for update;
  if not found or not exists (select 1 from conversation_members where conversation_id = c.id and user_id = me) then
    raise exception 'Not found' using errcode = 'P0002';
  end if;
  if c.status <> 'pending' then raise exception 'Request already answered' using errcode = '22023'; end if;
  if c.requested_by = me then raise exception 'You cannot answer your own request' using errcode = '42501'; end if;
  update conversations set status = case when p_accept then 'accepted' else 'declined' end where id = c.id;
  return case when p_accept then 'accepted' else 'declined' end;
end $function$;

create or replace function public.my_message_requests()
returns table (
  conversation_id uuid, direction text, other_id uuid, other_name text, other_company text, other_trade text,
  other_tier integer, job_id uuid, job_title text, status text, created_at timestamptz
)
language sql
stable
security definer
set search_path to 'public'
as $function$
  select c.id,
         case when c.requested_by = auth.uid() then 'outgoing' else 'incoming' end,
         p.id, p.full_name, p.company, p.trade, p.tier::int,
         j.id, j.title, c.status, c.created_at
    from conversation_members me
    join conversations c on c.id = me.conversation_id
    join conversation_members o on o.conversation_id = c.id and o.user_id <> me.user_id
    join profiles p on p.id = o.user_id
    left join jobs j on j.id = c.job_id
   where me.user_id = auth.uid() and c.status <> 'accepted'
   order by c.created_at desc;
$function$;

create or replace function public.my_conversations()
returns table (
  conversation_id uuid, other_id uuid, other_name text, other_company text, other_trade text, other_tier integer,
  job_id uuid, job_title text, last_body text, last_sender uuid, last_at timestamptz, unread integer
)
language sql
stable
security definer
set search_path to 'public'
as $function$
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
   where me.user_id = auth.uid() and c.status = 'accepted'
   order by coalesce(lm.created_at, c.created_at) desc;
$function$;

-- 4. Sending requires an accepted thread ----------------------------------------------
-- Admins keep their ALL policy (owner's decision, see header), so they are not bound by this.

alter policy "Members can send messages" on public.messages
  to authenticated
  with check (
    auth.uid() = sender_id
    and public.is_conversation_member(conversation_id)
    and exists (select 1 from public.conversations c where c.id = conversation_id and c.status = 'accepted')
  );

create or replace function public.messages_before_insert()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if auth.role() <> 'service_role' and not public.is_admin() then
    -- Serialize this sender's inserts so the count below cannot be raced past.
    perform pg_advisory_xact_lock(hashtextextended('msg-user:' || new.sender_id::text, 0));
    if (select count(*) from messages where sender_id = new.sender_id and created_at > now() - interval '1 minute') >= 20 then
      raise exception 'Slow down -- too many messages in a minute' using errcode = 'P0001';
    end if;
  end if;
  new.body := btrim(new.body);
  new.created_at := now();
  return new;
end $$;

-- 5. Realtime: accept/decline must reach open clients -------------------------------------

do $$ begin
  if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime'
                  and schemaname = 'public' and tablename = 'conversations') then
    alter publication supabase_realtime add table public.conversations;
  end if;
end $$;

-- 6. Grants: only what the client uses -----------------------------------------------------
-- RLS limits rows, not TRUNCATE or TRIGGER. The app only reads these tables and
-- inserts messages (conversation_id, sender_id, body); id, created_at come from defaults/trigger.

revoke all on public.conversations, public.conversation_members, public.messages from anon, authenticated;
grant select on public.conversations, public.conversation_members, public.messages to authenticated;
grant insert (conversation_id, sender_id, body) on public.messages to authenticated;

revoke all on function public.start_conversation(uuid, uuid) from public, anon;
grant execute on function public.start_conversation(uuid, uuid) to authenticated;
revoke all on function public.respond_to_request(uuid, boolean) from public, anon;
grant execute on function public.respond_to_request(uuid, boolean) to authenticated;
revoke all on function public.my_message_requests() from public, anon;
grant execute on function public.my_message_requests() to authenticated;
revoke all on function public.my_conversations() from public, anon;
grant execute on function public.my_conversations() to authenticated;
