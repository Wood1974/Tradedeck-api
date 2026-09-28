-- Close two live holes in the browser-facing RLS policies.
--
-- The frontend talks to Postgres directly with the anon key, so these policies
-- are the whole authorisation boundary for anything the browser does. Flask's
-- checks never run on that path. Both problems below were reachable from a
-- free self-serve signup.
--
-- 1. PRIVILEGE ESCALATION.  `profiles_update` is USING (auth.uid() = id) with
--    no WITH CHECK, so Postgres reuses USING as the check and a user may write
--    ANY column on their own row -- including `is_admin`. `is_admin()` reads
--    exactly that column, and every table carries an "Admins have full access"
--    policy for ALL commands. So:
--
--        update profiles set is_admin = true where id = auth.uid();
--
--    turned any account into full read/write on every table, from the browser.
--
-- 2. ESCROW IS WORLD-WRITABLE TO ANY LOGGED-IN USER.  `Authenticated update
--    escrow` is USING (auth.role() = 'authenticated') with no WITH CHECK, so
--    any account could rewrite any row of stripe_escrow -- including
--    `payee_id`. release_escrow() in escrow.py reads payee_id from that row and
--    transfers to whatever Stripe account it names. The owner-approval gate
--    stays intact and stops mattering: the homeowner still clicks approve, the
--    money just goes elsewhere.
--
-- Nothing here is exploitable *today* -- stripe_escrow, draws and
-- draw_schedules are all empty and there are 4 profiles. That is timing, not
-- design. The escalation works right now.
--
-- WHAT THIS DELIBERATELY DOES NOT DO
-- `profiles_select` stays USING (true), so every profile -- including email,
-- phone, and checkr_status -- is still readable by anyone, logged in or not.
-- That is a real exposure and it is left alone on purpose: index.html reads
-- other users' profiles in three places, the tier display is meant to be
-- public, and narrowing it is a product decision about what a visitor may see,
-- not a lock to quietly turn. It needs a view or column grants plus a frontend
-- change. Raised separately.
--
-- Written to be applied by the owner. Idempotent; safe to run twice.

begin;

-- ---------------------------------------------------------------------------
-- 1. profiles: a row you own is not a row you may rewrite freely
-- ---------------------------------------------------------------------------

-- A WITH CHECK, so the row you write must still be your own. Without it the
-- USING clause is reused and `id` itself is writable.
drop policy if exists profiles_update on public.profiles;
create policy profiles_update on public.profiles
  for update
  using  (auth.uid() = id)
  with check (auth.uid() = id);

-- The privileged columns need old-vs-new comparison, which a policy cannot do:
-- USING sees the old row, WITH CHECK sees the new one, and neither sees both.
-- A trigger does, which is why this is a trigger and not more policy.
create or replace function public.profiles_guard_privileged_columns()
returns trigger
language plpgsql
security definer
set search_path to 'public'
as $$
begin
  -- Flask holds the service-role key and already bypasses RLS entirely.
  -- Anything it writes has been through the API's own authorisation.
  if auth.role() = 'service_role' then
    return new;
  end if;

  -- is_admin may change, but only when an EXISTING admin is making the change.
  -- This keeps the admin panel working (index.html toggles is_admin directly)
  -- while removing the self-promotion path, because is_admin() is evaluated
  -- against the caller, not the target row.
  if new.is_admin is distinct from old.is_admin and not public.is_admin() then
    raise exception 'is_admin may only be changed by an admin'
      using errcode = '42501';
  end if;

  -- Trust and verification state is computed from platform activity or written
  -- by the backend. A user asserting their own tier, rating or cleared
  -- background check is the product's central claim being edited by the party
  -- it is about.
  if not public.is_admin() then
    if new.tier               is distinct from old.tier
    or new.jobs_completed     is distinct from old.jobs_completed
    or new.rating             is distinct from old.rating
    or new.repeat_hire_rate   is distinct from old.repeat_hire_rate
    or new.is_pro             is distinct from old.is_pro
    or new.tradedeck_verified is distinct from old.tradedeck_verified
    or new.verified_at        is distinct from old.verified_at
    or new.verification_status is distinct from old.verification_status
    or new.checkr_cleared_at  is distinct from old.checkr_cleared_at
    then
      raise exception 'trust and verification fields are set by the platform, not the subject'
        using errcode = '42501';
    end if;

    -- index.html starts a background check by writing candidate id and a
    -- 'pending' status from the browser. That stays allowed; declaring your
    -- own check CLEAR does not.
    if new.checkr_status is distinct from old.checkr_status
       and coalesce(new.checkr_status, '') not in ('pending', '')
    then
      raise exception 'checkr_status may only be set to pending from a client'
        using errcode = '42501';
    end if;
  end if;

  return new;
end;
$$;

comment on function public.profiles_guard_privileged_columns() is
  'Blocks self-escalation via profiles.is_admin and self-asserted trust or '
  'verification state. A trigger rather than a policy because it needs to '
  'compare OLD and NEW, which RLS cannot.';

drop trigger if exists profiles_guard_privileged on public.profiles;
create trigger profiles_guard_privileged
  before update on public.profiles
  for each row execute function public.profiles_guard_privileged_columns();

-- ---------------------------------------------------------------------------
-- 2. stripe_escrow: participants only
-- ---------------------------------------------------------------------------
-- Permissive policies OR together, so the three broad `auth.role() =
-- 'authenticated'` policies made the narrow "Participants can view their
-- escrow" policy beside them dead weight. They go.
--
-- No client write path is lost. index.html only ever reads escrow
-- (select('draw_id,status')); every write comes from Flask on the service-role
-- key, which bypasses RLS and is unaffected by any of this.

drop policy if exists "Authenticated read escrow"   on public.stripe_escrow;
drop policy if exists "Authenticated update escrow" on public.stripe_escrow;
drop policy if exists "Authenticated insert escrow" on public.stripe_escrow;

drop policy if exists "Participants can view their escrow" on public.stripe_escrow;
create policy "Participants can view their escrow" on public.stripe_escrow
  for select
  using (auth.uid() = payer_id or auth.uid() = payee_id);

-- Deliberately no client INSERT or UPDATE policy. Money rows are written by
-- the service role after the API has authorised the action. A browser has no
-- business writing one, and the absence of a policy is how that is stated.

-- ---------------------------------------------------------------------------
-- 3. draws: submitting is the payee's move, not everyone's
-- ---------------------------------------------------------------------------
-- `draws_submit` allowed any authenticated user to flip any draw from pending
-- to submitted, with no link to the job at all. It cannot move money -- release
-- is gated on the schedule owner in Flask -- but it drives someone else's
-- workflow and stamps submitted_at on their record.

-- The payee also needs to SEE the draw. `UPDATE ... WHERE` must locate the row
-- first, which means passing the SELECT policies too -- and `draws` has none
-- that matches a payee. Only the schedule owner and admins can read a draw.
--
-- So the submit flow has never worked: a contractor pressing Submit in
-- index.html:736 updates zero rows and gets no error. It has gone unnoticed
-- because `draws` is empty and the path has never run. Without this policy the
-- tightened draws_submit below would be unreachable code, which is a worse
-- outcome than the hole it replaces -- it would look fixed and do nothing.
drop policy if exists draws_payee_read on public.draws;
create policy draws_payee_read on public.draws
  for select
  to authenticated
  using (
    auth.uid() = payee_id
    or exists (select 1 from public.draw_schedules s
                where s.id = draws.job_id and s.payee_id = auth.uid())
  );

drop policy if exists draws_submit on public.draws;
create policy draws_submit on public.draws
  for update
  to authenticated
  using (
    status = 'pending'::draw_status
    and (
      auth.uid() = payee_id
      or exists (select 1 from public.draw_schedules s
                  where s.id = draws.job_id and s.payee_id = auth.uid())
    )
  )
  with check (status = 'submitted'::draw_status);

commit;

-- ---------------------------------------------------------------------------
-- Verifying this did what it says, after applying
-- ---------------------------------------------------------------------------
--   -- as a NON-admin logged-in user, every one of these must now fail:
--   update profiles set is_admin = true where id = auth.uid();
--   update profiles set tier = 'TradeDeck Pro' where id = auth.uid();
--   update profiles set checkr_status = 'clear' where id = auth.uid();
--
--   -- and this must still succeed, because the app does it:
--   update profiles set phone = '801-555-0100' where id = auth.uid();
--   update profiles set checkr_candidate_id = 'x', checkr_status = 'pending'
--     where id = auth.uid();
--
--   -- as an admin, this must still succeed, because the admin panel does it:
--   update profiles set is_admin = true where id = '<someone else>';
--
--   -- no client may write escrow at all:
--   update stripe_escrow set payee_id = auth.uid();   -- 0 rows / refused
