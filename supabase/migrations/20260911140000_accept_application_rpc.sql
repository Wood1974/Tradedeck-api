-- Atomically hire a contractor: the job owner accepts one application, which
-- attaches that applicant as the payee on the job's draw schedule(s) and every
-- draw under them. This is the step that unblocks require_draw_payee in the API
-- (auth.draw_payee_id reads draws.payee_id). SECURITY DEFINER so it can write
-- across tables in one transaction; authorization is enforced in-function
-- against auth.uid(), and EXECUTE is granted to authenticated only.
create or replace function public.accept_application(p_application_id uuid)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_job_id      uuid;
  v_applicant   uuid;
  v_owner       uuid;
  v_schedules   integer;
  v_draws       integer;
begin
  select a.job_id, a.applicant_id into v_job_id, v_applicant
  from public.applications a
  where a.id = p_application_id;

  if v_job_id is null then
    raise exception 'Application not found' using errcode = 'no_data_found';
  end if;
  if v_applicant is null then
    raise exception 'Application has no applicant';
  end if;

  select owner_id into v_owner from public.jobs where id = v_job_id;
  if v_owner is null or v_owner <> auth.uid() then
    raise exception 'Only the job owner can accept applications'
      using errcode = 'insufficient_privilege';
  end if;

  -- Accept this application; reject any other still-open applications on the
  -- same job (single-hire model: one payee per job).
  update public.applications set status = 'accepted' where id = p_application_id;
  update public.applications
    set status = 'rejected'
    where job_id = v_job_id
      and id <> p_application_id
      and coalesce(status, '') not in ('accepted', 'rejected');

  -- Attach the payee at the schedule level...
  update public.draw_schedules set payee_id = v_applicant where job_id = v_job_id;
  get diagnostics v_schedules = row_count;

  -- ...and on every draw under those schedules (draws.job_id -> draw_schedules.id).
  update public.draws
    set payee_id = v_applicant
    where job_id in (select id from public.draw_schedules where job_id = v_job_id);
  get diagnostics v_draws = row_count;

  return jsonb_build_object(
    'application_id',    p_application_id,
    'job_id',            v_job_id,
    'payee_id',          v_applicant,
    'schedules_updated', v_schedules,
    'draws_updated',     v_draws
  );
end;
$$;

revoke all on function public.accept_application(uuid) from public;
revoke all on function public.accept_application(uuid) from anon;
grant execute on function public.accept_application(uuid) to authenticated;
