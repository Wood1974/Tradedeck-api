-- What production had by hand on 2026-10-19 that no repo migration records:
-- the opt-in columns, left at a default of accepted after the revert.
alter table public.conversations add column status text default 'accepted';
alter table public.conversations add column requested_by uuid references public.profiles(id) on delete set null;
alter table public.conversations add constraint conversations_status_check check (status in ('pending', 'accepted', 'declined'));
