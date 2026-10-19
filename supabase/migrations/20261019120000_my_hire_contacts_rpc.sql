-- Contact details between hired parties.
--
-- profiles RLS only lets a user read their own row, and profiles_public has no
-- phone or email on purpose. Once a hire is made the two parties need to reach
-- each other, so this RPC returns the OTHER party's name, phone and email --
-- but only for jobs where the caller is the job owner of an accepted
-- application, or the accepted applicant. Nobody else's contact info is ever
-- returned.
create or replace function public.my_hire_contacts()
returns table (
  job_id       uuid,
  job_title    text,
  relation     text,   -- 'you_hired' (caller owns the job) | 'hired_you' (caller was hired)
  other_id     uuid,
  other_name   text,
  other_company text,
  other_trade  text,
  other_phone  text,
  other_email  text,
  hired_at     timestamptz
)
language sql
stable
security definer
set search_path = public
as $$
  select j.id, j.title, 'you_hired', p.id, p.full_name, p.company, p.trade, p.phone, p.email, a.created_at
    from applications a
    join jobs j     on j.id = a.job_id
    join profiles p on p.id = a.applicant_id
   where a.status = 'accepted' and j.owner_id = auth.uid()
  union all
  select j.id, j.title, 'hired_you', p.id, p.full_name, p.company, p.trade, p.phone, p.email, a.created_at
    from applications a
    join jobs j     on j.id = a.job_id
    join profiles p on p.id = j.owner_id
   where a.status = 'accepted' and a.applicant_id = auth.uid()
  order by 10 desc;
$$;

revoke all on function public.my_hire_contacts() from public, anon;
grant execute on function public.my_hire_contacts() to authenticated;
