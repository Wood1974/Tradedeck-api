-- Job close-out: how a job ends, and how jobs_completed actually moves.
--
-- Until now the ONLY thing that incremented profiles.jobs_completed was
-- bump_jobs_completed_on_release, which fires when every draw on a
-- draw_schedule reaches 'released'. Escrow is switched off (ESCROW_ENABLED =
-- false in the frontend) and this service no longer has the escrow routes at
-- all, so that trigger can never fire. The consequence: jobs_completed is
-- stuck at 0 for everyone, and because compute_profile_tier() requires
-- jobs >= 1 for even Tier 2, nobody can ever leave Tier 1 -- no matter how
-- many 5-star reviews they collect. The Worker Directory, which filters on
-- jobs_completed > 0, shows nobody at all.
--
-- This decouples completion from escrow. The job owner closes the job out
-- directly, and the credit goes to the applicant on the accepted application
-- (applications.status is constrained to pending/accepted/rejected, so that
-- row is the source of truth for who was hired -- no draw_schedules needed).
--
-- The three binary questions are captured here but NOT yet used by
-- compute_profile_tier. That is deliberate: the tier formula currently reads
-- jobs_completed + rating only, and changing it is separate work. Capturing
-- the answers now means that work starts with history instead of from zero.

-- ── 1. when a job finished ───────────────────────────────────────────────────
alter table public.jobs
  add column if not exists completed_at timestamptz;

-- jobs.status has no CHECK constraint, so 'completed' needs no schema change.
-- Lifecycle is: open -> filled (hireApplicant) -> completed (this RPC).

-- ── 2. the close-out record ──────────────────────────────────────────────────
create table if not exists public.job_closeouts (
  id                uuid primary key default gen_random_uuid(),
  job_id            uuid not null unique references public.jobs(id) on delete cascade,
  closed_by         uuid not null references public.profiles(id),
  payee_id          uuid not null references public.profiles(id),
  on_time           boolean not null,
  site_clean        boolean not null,
  would_hire_again  boolean not null,
  created_at        timestamptz not null default now()
);

comment on table public.job_closeouts is
  'One row per completed job. UNIQUE(job_id) is what makes close_out_job() '
  'idempotent -- it is the guard against double-crediting jobs_completed.';

create index if not exists job_closeouts_payee_idx on public.job_closeouts(payee_id);

alter table public.job_closeouts enable row level security;

-- Both parties to the job can read their own close-out. Nobody writes
-- directly: close_out_job() is SECURITY DEFINER and is the only writer, so
-- there are deliberately no insert/update/delete policies.
drop policy if exists job_closeouts_select on public.job_closeouts;
create policy job_closeouts_select on public.job_closeouts
  for select to authenticated
  using (closed_by = auth.uid() or payee_id = auth.uid());

-- Migration 20261020000000 made new public tables grant nothing by default,
-- so the read has to be granted explicitly.
grant select on public.job_closeouts to authenticated;

-- ── 3. close_out_job() ───────────────────────────────────────────────────────
-- Mirrors accept_application(): SECURITY DEFINER, pinned search_path,
-- authorization checked against auth.uid(), granted to authenticated only.
create or replace function public.close_out_job(
  p_job_id           uuid,
  p_on_time          boolean,
  p_site_clean       boolean,
  p_would_hire_again boolean
)
returns jsonb
language plpgsql
security definer
set search_path to 'public', 'pg_temp'
as $$
declare
  v_owner    uuid;
  v_payee    uuid;
  v_inserted integer;
begin
  if p_on_time is null or p_site_clean is null or p_would_hire_again is null then
    raise exception 'All three close-out answers are required';
  end if;

  select owner_id into v_owner from public.jobs where id = p_job_id;
  if v_owner is null then
    raise exception 'Job not found' using errcode = 'no_data_found';
  end if;
  if v_owner <> auth.uid() then
    raise exception 'Only the job owner can close out a job'
      using errcode = 'insufficient_privilege';
  end if;

  -- Who was hired. Single-hire model, enforced by accept_application().
  select a.applicant_id into v_payee
    from public.applications a
   where a.job_id = p_job_id and a.status = 'accepted'
   limit 1;
  if v_payee is null then
    raise exception 'Cannot close out a job with no accepted applicant'
      using errcode = 'no_data_found';
  end if;

  -- UNIQUE(job_id) makes a second call a no-op rather than a second credit.
  insert into public.job_closeouts
    (job_id, closed_by, payee_id, on_time, site_clean, would_hire_again)
  values
    (p_job_id, v_owner, v_payee, p_on_time, p_site_clean, p_would_hire_again)
  on conflict (job_id) do nothing;
  get diagnostics v_inserted = row_count;

  if v_inserted = 0 then
    return jsonb_build_object(
      'job_id', p_job_id, 'payee_id', v_payee, 'already_closed', true, 'credited', false
    );
  end if;

  update public.jobs
     set status = 'completed', completed_at = now()
   where id = p_job_id;

  -- This write fires trg_set_profile_tier, which recomputes tier from
  -- compute_profile_tier(jobs_completed, rating).
  update public.profiles
     set jobs_completed = coalesce(jobs_completed, 0) + 1
   where id = v_payee;

  return jsonb_build_object(
    'job_id', p_job_id, 'payee_id', v_payee, 'already_closed', false, 'credited', true
  );
end;
$$;

revoke all on function public.close_out_job(uuid, boolean, boolean, boolean) from public, anon;
grant execute on function public.close_out_job(uuid, boolean, boolean, boolean) to authenticated;

-- ── 4. my_hire_contacts(): expose job status ────────────────────────────────
-- The Your Hires card needs to know whether a job is already closed out, or it
-- cannot decide whether to show the button. RETURNS TABLE signatures cannot be
-- widened with CREATE OR REPLACE, so this drops and recreates.
drop function if exists public.my_hire_contacts();

create function public.my_hire_contacts()
returns table (
  job_id        uuid,
  job_title     text,
  relation      text,   -- 'you_hired' (caller owns the job) | 'hired_you'
  other_id      uuid,
  other_name    text,
  other_company text,
  other_trade   text,
  other_phone   text,
  other_email   text,
  hired_at      timestamptz,
  job_status    text,
  completed_at  timestamptz
)
language sql
stable
security definer
set search_path to 'public'
as $$
  select j.id, j.title, 'you_hired', p.id, p.full_name, p.company, p.trade,
         p.phone, p.email, a.created_at, j.status, j.completed_at
    from applications a
    join jobs j     on j.id = a.job_id
    join profiles p on p.id = a.applicant_id
   where a.status = 'accepted' and j.owner_id = auth.uid()
  union all
  select j.id, j.title, 'hired_you', p.id, p.full_name, p.company, p.trade,
         p.phone, p.email, a.created_at, j.status, j.completed_at
    from applications a
    join jobs j     on j.id = a.job_id
    join profiles p on p.id = j.owner_id
   where a.status = 'accepted' and a.applicant_id = auth.uid()
  order by 10 desc;
$$;

revoke all on function public.my_hire_contacts() from public, anon;
grant execute on function public.my_hire_contacts() to authenticated;
