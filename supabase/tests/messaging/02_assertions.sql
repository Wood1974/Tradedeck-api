-- Assertions for 20261020000000_messaging_consent_enforcement.sql. Any failure aborts the run.
\set ON_ERROR_STOP on
\set A '''00000000-0000-0000-0000-0000000000a1'''
\set B '''00000000-0000-0000-0000-0000000000b2'''
\set C '''00000000-0000-0000-0000-0000000000c3'''
\set D '''00000000-0000-0000-0000-0000000000d4'''
\set E '''00000000-0000-0000-0000-0000000000e5'''
\set F '''00000000-0000-0000-0000-0000000000f6'''

create schema t;
grant usage on schema t to public;
create function t.fails(q text, code text) returns void language plpgsql as $$
begin
  begin
    execute q;
  exception when others then
    if sqlstate = code then return; end if;
    raise exception 'FAIL: raised % (%), expected %: %', sqlstate, sqlerrm, code, q;
  end;
  raise exception 'FAIL: expected % but it succeeded: %', code, q;
end $$;
create function t.ok(q text) returns void language plpgsql as $$
begin execute q; end $$;
create function t.eq(label text, got anyelement, want anyelement) returns void language plpgsql as $$
begin
  if got is distinct from want then raise exception 'FAIL %: got %, want %', label, got, want; end if;
  raise notice 'ok   %', label;
end $$;
create function t.as(uid uuid, r text default 'authenticated') returns void language sql as $$
  select set_config('request.jwt.claim.sub', coalesce(uid::text, ''), false), set_config('request.jwt.claim.role', r, false);
$$;
grant execute on all functions in schema t to public;

insert into public.profiles(id, full_name, is_admin) values
  (:A, 'A', false), (:B, 'B', false), (:C, 'C', false), (:D, 'D admin', true), (:E, 'E', false), (:F, 'F', false);
insert into public.jobs(id, title, owner_id) values
  ('00000000-0000-0000-0000-00000000aaa1', 'job A', :A),
  ('00000000-0000-0000-0000-00000000ccc1', 'job C', :C),
  ('00000000-0000-0000-0000-00000000fff1', 'orphan job', null);

-- 1. A asks B: the thread is a pending request from A -------------------------------
set role authenticated; select t.as(:A);
select public.start_conversation(:B) as cid1 \gset
reset role;
select t.eq('new thread is pending', (select status from conversations where id = :'cid1'), 'pending');
select t.eq('requester recorded', (select requested_by from conversations where id = :'cid1'), :A::uuid);
select t.eq('pair key set', (select pair_key is not null from conversations where id = :'cid1'), true);

-- 2. Finding 1: no sending while pending, from either side, straight through the API
set role authenticated; select t.as(:A);
select t.fails(format($q$insert into messages(conversation_id, sender_id, body) values (%L, %L, 'hi')$q$, :'cid1', :A), '42501');
select t.as(:B);
select t.fails(format($q$insert into messages(conversation_id, sender_id, body) values (%L, %L, 'hi')$q$, :'cid1', :B), '42501');

-- 3. Outsider C sees and sends nothing
select t.as(:C);
select t.eq('C sees no conversations', (select count(*) from conversations), 0::bigint);
select t.eq('C sees no members', (select count(*) from conversation_members), 0::bigint);
select t.fails(format($q$insert into messages(conversation_id, sender_id, body) values (%L, %L, 'hi')$q$, :'cid1', :C), '42501');

-- 4. Self-accept, wrong responder, forged sender
select t.as(:A);
select t.fails(format($q$select respond_to_request(%L, true)$q$, :'cid1'), '42501');
select t.as(:C);
select t.fails(format($q$select respond_to_request(%L, true)$q$, :'cid1'), 'P0002');
select t.as(:A);
select t.fails(format($q$insert into messages(conversation_id, sender_id, body) values (%L, %L, 'forged')$q$, :'cid1', :B), '42501');

-- 5. B asking A returns the same thread (no duplicate pair); then B declines
select t.as(:B);
select public.start_conversation(:A) as cid1b \gset
select t.eq('reverse start returns same thread', :'cid1b'::uuid, :'cid1'::uuid);
select respond_to_request(:'cid1', false);
select t.fails(format($q$select respond_to_request(%L, true)$q$, :'cid1'), '22023');
select t.fails(format($q$insert into messages(conversation_id, sender_id, body) values (%L, %L, 'hi')$q$, :'cid1', :B), '42501');
select t.as(:A);
select t.fails(format($q$insert into messages(conversation_id, sender_id, body) values (%L, %L, 'hi')$q$, :'cid1', :A), '42501');
select public.start_conversation(:B) as cid1c \gset
select t.eq('declined thread is not reopened by asking again', :'cid1c'::uuid, :'cid1'::uuid);
reset role;
select t.eq('still declined', (select status from conversations where id = :'cid1'), 'declined');

-- 6. Accept path: A asks C, C accepts, both can send; whitespace and empty bodies
set role authenticated; select t.as(:A);
select public.start_conversation(:C) as cid2 \gset
select t.as(:C);
select respond_to_request(:'cid2', true);
select t.ok(format($q$insert into messages(conversation_id, sender_id, body) values (%L, %L, '  hello  ')$q$, :'cid2', :C));
select t.as(:A);
select t.ok(format($q$insert into messages(conversation_id, sender_id, body) values (%L, %L, 'reply')$q$, :'cid2', :A));
select t.fails(format($q$insert into messages(conversation_id, sender_id, body) values (%L, %L, '   ')$q$, :'cid2', :A), '23514');
select t.eq('body trimmed', (select body from messages where sender_id = :C), 'hello');
select t.eq('A inbox lists accepted thread', (select count(*) from my_conversations()), 1::bigint);
select t.eq('A has no open requests', (select count(*) from my_message_requests()), 1::bigint);  -- the declined A-B one
select t.as(:B);
select t.eq('B outgoing/incoming shows declined', (select status from my_message_requests() limit 1), 'declined');

-- 8. Finding 6: job context
set role authenticated; select t.as(:A);
select t.fails(format($q$select start_conversation(%L, %L)$q$, :D, '00000000-0000-0000-0000-00000000ccc1'), '42501'); -- someone else's job
select t.fails(format($q$select start_conversation(%L, %L)$q$, :D, '00000000-0000-0000-0000-00000000fff1'), '42501'); -- no owner
select t.fails(format($q$select start_conversation(%L, %L)$q$, :D, gen_random_uuid()), '42501');                    -- no such job
select t.ok(format($q$select start_conversation(%L, %L)$q$, :D, '00000000-0000-0000-0000-00000000aaa1'));             -- my own job
select public.start_conversation(:C, '00000000-0000-0000-0000-00000000aaa1') as cid2b \gset
select t.eq('empty job filled once', (select job_id from conversations where id = :'cid2'), '00000000-0000-0000-0000-00000000aaa1'::uuid);
select public.start_conversation(:C, '00000000-0000-0000-0000-00000000ccc1');
select t.eq('existing job not replaced', (select job_id from conversations where id = :'cid2'), '00000000-0000-0000-0000-00000000aaa1'::uuid);

-- 9. Finding 7: grants
reset role;
select t.eq('anon: no table privileges', (
  select count(*) from (values ('conversations'), ('conversation_members'), ('messages')) v(tb),
         unnest(array['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','TRIGGER','REFERENCES']) p
   where has_table_privilege('anon', 'public.' || tb, p)), 0::bigint);
select t.eq('authenticated: only SELECT on tables', (
  select count(*) from (values ('conversations'), ('conversation_members'), ('messages')) v(tb),
         unnest(array['INSERT','UPDATE','DELETE','TRUNCATE','TRIGGER','REFERENCES']) p
   where has_table_privilege('authenticated', 'public.' || tb, p)), 0::bigint);
select t.eq('authenticated: can select', has_table_privilege('authenticated', 'public.messages', 'SELECT'), true);
select t.eq('insert limited to 3 columns', (select array_agg(c order by c) from unnest(array['id','conversation_id','sender_id','body','created_at']) c
   where has_column_privilege('authenticated', 'public.messages', c, 'INSERT')), array['body','conversation_id','sender_id']);
select t.eq('anon cannot call RPCs', (select count(*) from unnest(array[
   'public.start_conversation(uuid,uuid)','public.respond_to_request(uuid,boolean)',
   'public.my_message_requests()','public.my_conversations()']) f
   where has_function_privilege('anon', f, 'EXECUTE')), 0::bigint);
set role authenticated; select t.as(:A);
select t.fails($q$update conversations set status = 'accepted'$q$, '42501');
select t.fails($q$insert into conversations(status) values ('accepted')$q$, '42501');
select t.fails($q$insert into conversation_members(conversation_id, user_id) values (gen_random_uuid(), gen_random_uuid())$q$, '42501');
select t.fails($q$truncate messages$q$, '42501');
select t.fails($q$delete from messages$q$, '42501');
select t.fails($q$update messages set body = 'edited'$q$, '42501');
select t.as(null, 'anon'); reset role; set role anon;
select t.fails($q$select count(*) from messages$q$, '42501');
reset role;

-- 10. Realtime
select t.eq('conversations published', (select count(*) from pg_publication_tables where pubname = 'supabase_realtime' and tablename = 'conversations'), 1::bigint);
select t.eq('messages published', (select count(*) from pg_publication_tables where pubname = 'supabase_realtime' and tablename = 'messages'), 1::bigint);

-- 11. Rate limits
-- 20 messages a minute: the 21st is refused.
set role authenticated; select t.as(:E);
select public.start_conversation(:F) as cid3 \gset
select t.as(:F);
select respond_to_request(:'cid3', true);
select t.as(:E);
select format($q$insert into messages(conversation_id, sender_id, body) values (%L, %L, 'm%s')$q$, :'cid3', :E, i)
  from generate_series(1, 20) i \gexec
select t.fails(format($q$insert into messages(conversation_id, sender_id, body) values (%L, %L, 'm21')$q$, :'cid3', :E), 'P0001');
reset role;

-- 30 new conversations a day, counted only for the person who asked.
insert into public.profiles(id) select ('00000000-0000-0000-0001-' || lpad(i::text, 12, '0'))::uuid from generate_series(1, 31) i;
set role authenticated;
do $$ declare i int; u uuid; begin
  perform set_config('request.jwt.claim.sub', '00000000-0000-0000-0000-0000000000f6', false);
  for i in 1..30 loop
    perform public.start_conversation(('00000000-0000-0000-0001-' || lpad(i::text, 12, '0'))::uuid);
  end loop;
end $$;
select t.fails(format($q$select start_conversation(%L)$q$, '00000000-0000-0000-0001-000000000031'), 'P0001');
-- Being asked by many people does not use up your own allowance.
do $$ declare i int; begin
  for i in 1..30 loop
    perform set_config('request.jwt.claim.sub', ('00000000-0000-0000-0001-' || lpad(i::text, 12, '0')), false);
    perform public.start_conversation('00000000-0000-0000-0000-0000000000d4');
  end loop;
end $$;
select t.as(:D);
select t.ok(format($q$select start_conversation(%L)$q$, :B));
reset role;

\echo ALL ASSERTIONS PASSED
