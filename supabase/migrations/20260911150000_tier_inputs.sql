-- Tier inputs (starter). Rating + repeat_hire_rate already recompute from
-- reviews via recalculate_profile_rating(). This adds the two missing pieces:
--   (1) jobs_completed increments for the payee when a job's draws are all
--       released (money actually paid out -- the canonical completion signal;
--       becomes active once escrow release is wired from the frontend).
--   (2) tier (the 5-tier ranking: 1 Verified .. 5 TradeDeck Pro) is derived
--       from jobs_completed + rating on every profile write.
-- Timeline adherence, cost variance, and cleanliness sign-offs are not
-- captured yet; when they are, refine compute_profile_tier accordingly.

create or replace function public.compute_profile_tier(p_jobs integer, p_rating numeric)
returns integer
language sql
immutable
set search_path = public, pg_temp
as $$
  select case
    when coalesce(p_jobs, 0) >= 25 and coalesce(p_rating, 0) >= 4.8 then 5  -- TradeDeck Pro
    when coalesce(p_jobs, 0) >= 10 and coalesce(p_rating, 0) >= 4.5 then 4  -- Trusted
    when coalesce(p_jobs, 0) >= 3  and coalesce(p_rating, 0) >= 4.0 then 3  -- Proven
    when coalesce(p_jobs, 0) >= 1 then 2                                     -- Active
    else 1                                                                  -- Verified (baseline)
  end;
$$;

-- BEFORE trigger: derive tier in-place (no extra UPDATE, no recursion). Fires
-- on any profile write, including the rating update the reviews trigger makes.
create or replace function public.set_profile_tier()
returns trigger
language plpgsql
set search_path = public, pg_temp
as $$
begin
  new.tier := public.compute_profile_tier(new.jobs_completed, new.rating);
  return new;
end;
$$;

drop trigger if exists trg_set_profile_tier on public.profiles;
create trigger trg_set_profile_tier
  before insert or update on public.profiles
  for each row execute function public.set_profile_tier();

-- Increment the payee's jobs_completed when a schedule's draws are all released.
-- draws.job_id references draw_schedules.id. Guarded so it fires once, on the
-- transition of the final draw (app releases draws one at a time).
create or replace function public.bump_jobs_completed_on_release()
returns trigger
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_payee    uuid;
  v_total    integer;
  v_released integer;
begin
  if new.status = 'released' and old.status is distinct from 'released' then
    select count(*), count(*) filter (where status = 'released')
      into v_total, v_released
      from public.draws where job_id = new.job_id;
    if v_total > 0 and v_released = v_total then
      select payee_id into v_payee from public.draw_schedules where id = new.job_id;
      if v_payee is not null then
        update public.profiles
          set jobs_completed = coalesce(jobs_completed, 0) + 1
          where id = v_payee;
      end if;
    end if;
  end if;
  return new;
end;
$$;

drop trigger if exists trg_bump_jobs_completed on public.draws;
create trigger trg_bump_jobs_completed
  after update of status on public.draws
  for each row execute function public.bump_jobs_completed_on_release();

-- Normalize tier on existing profiles to match the derived value.
update public.profiles set tier = public.compute_profile_tier(jobs_completed, rating);
