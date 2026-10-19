-- Reviews: only the two parties of an accepted hire may review each other.
-- reviews_insert previously checked only reviewer_id = auth.uid(), so anyone
-- could rate anyone and move their rating/tier. Applied to production
-- 2026-10-19 (0 reviews existed). One review per person per job is already
-- enforced by reviews_job_id_reviewer_id_key.
create or replace function public.can_review(p_job_id uuid, p_reviewee uuid)
returns boolean language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from applications a join jobs j on j.id = a.job_id
     where a.job_id = p_job_id and a.status = 'accepted'
       and ((j.owner_id = auth.uid() and a.applicant_id = p_reviewee)
         or (a.applicant_id = auth.uid() and j.owner_id = p_reviewee))
  );
$$;
revoke all on function public.can_review(uuid, uuid) from public, anon;
grant execute on function public.can_review(uuid, uuid) to authenticated;

alter policy "reviews_insert" on public.reviews
  with check (reviewer_id = auth.uid() and public.can_review(job_id, reviewee_id));
