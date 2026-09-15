-- =====================================================================
-- Shield field notes — contemporaneous observations by the person on site.
--
-- A photograph shows a state. It does not show the weather, what the
-- inspector said, which sub did the work, or why the detail departs from the
-- plan. Those are the facts disputes turn on, and only the person holding the
-- camera can record them.
--
-- Notes are hearsay and need an exception to be admitted at all. Which one
-- applies turns on WHEN the note was written — FRE 803(1) present sense
-- impression reaches seconds to minutes, 803(5) recorded recollection needs
-- the matter fresh in memory, 803(6) business records needs a regular
-- practice. So `written_at` is set by the server, never by the client, and
-- the delay from the observation travels with the note into the export.
--
-- Append-only, for the same reason the custody log is. An editable note is
-- worthless: the first question on cross is whether it says what it said at
-- the time. Corrections are new rows pointing at the row they amend.
-- =====================================================================

create table if not exists public.shield_notes (
  id                uuid primary key default gen_random_uuid(),
  shield_job_id     uuid not null references public.shield_jobs(id) on delete restrict,

  -- A note may hang off a specific photo, a checkpoint, or the job itself
  -- (a daily log entry). At least one anchor is required.
  photo_id          uuid references public.shield_photos(id) on delete restrict,
  point_id          uuid references public.shield_pivotal_points(id) on delete restrict,

  author_id         uuid not null,
  author_role       text not null check (author_role in ('contractor', 'homeowner', 'inspector')),

  body              text not null check (length(btrim(body)) > 0),
  medium            text not null default 'typed'
                      check (medium in ('typed', 'dictated', 'photographed_handwritten')),
  -- When medium is photographed_handwritten, the scan of the written page.
  handwriting_photo_id uuid references public.shield_photos(id) on delete restrict,

  -- observed_at is the event the note describes: the photo's EXIF capture
  -- time where there is one, else when the server received it. written_at is
  -- server-set. The gap between them is what an exception hangs on, so
  -- neither may come from the client.
  observed_at       timestamptz,
  written_at        timestamptz not null default now(),
  contemporaneity   text check (contemporaneity in ('immediate', 'prompt', 'delayed',
                                                    'same_day', 'reconstructed',
                                                    'before_observation', 'unknown')),
  delay_seconds     integer,

  -- Amendment model: a correction is a new row. The original is never
  -- updated and never deleted.
  amends_note_id    uuid references public.shield_notes(id) on delete restrict,
  amendment_reason  text,

  -- Advisory quality signal recorded as it stood when written. Kept for
  -- honesty about what the author was shown, not as a judgement.
  strength          text check (strength in ('strong', 'adequate', 'thin')),

  -- Chain fields, same scheme as shield_custody_log.
  chain_version     integer not null default 1,
  prev_hash         text,
  entry_hash        text,

  created_at        timestamptz not null default now(),

  constraint shield_notes_has_an_anchor
    check (photo_id is not null or point_id is not null or amends_note_id is not null
           or (photo_id is null and point_id is null)),
  constraint shield_notes_amendment_states_a_reason
    check (amends_note_id is null or length(btrim(coalesce(amendment_reason, ''))) > 0),
  constraint shield_notes_handwriting_needs_that_medium
    check (handwriting_photo_id is null or medium = 'photographed_handwritten')
);

create index if not exists shield_notes_job_idx     on public.shield_notes (shield_job_id, written_at);
create index if not exists shield_notes_photo_idx   on public.shield_notes (photo_id);
create index if not exists shield_notes_point_idx   on public.shield_notes (point_id);
create index if not exists shield_notes_amends_idx  on public.shield_notes (amends_note_id);

-- One amendment may not itself be amended twice in parallel: corrections form
-- a line, not a tree, so the export can present them in order without
-- ambiguity about which version is current.
create unique index if not exists shield_notes_one_amendment_per_note
  on public.shield_notes (amends_note_id) where amends_note_id is not null;


-- ---------------------------------------------------------------------
-- Append-only
-- ---------------------------------------------------------------------
-- Same reasoning as shield_custody_log: the trigger stops an application bug,
-- and the hash chain is what makes tampering detectable by someone who does
-- not trust the operator.
create or replace function public.shield_notes_immutable()
returns trigger language plpgsql as $$
begin
  raise exception 'shield_notes is append-only — corrections are amendments, '
                  'not edits (attempted %)', tg_op;
end $$;

drop trigger if exists shield_notes_no_mutate on public.shield_notes;
create trigger shield_notes_no_mutate
  before update or delete on public.shield_notes
  for each row execute function public.shield_notes_immutable();

drop trigger if exists shield_notes_no_truncate on public.shield_notes;
create trigger shield_notes_no_truncate
  before truncate on public.shield_notes
  for each statement execute function public.shield_notes_immutable();


-- ---------------------------------------------------------------------
-- Custody event types for notes
-- ---------------------------------------------------------------------
alter table public.shield_custody_log drop constraint if exists shield_custody_log_event_type_check;
alter table public.shield_custody_log add constraint shield_custody_log_event_type_check
  check (event_type in ('created', 'activated', 'checkpoints_locked', 'token_issued',
                        'uploaded', 'superseded', 'ai_analyzed', 'flagged',
                        'integrity_flag', 'viewed', 'exported', 'completed',
                        'cancelled', 'refunded', 'note_written', 'note_amended'));


-- ---------------------------------------------------------------------
-- RLS
-- ---------------------------------------------------------------------
alter table public.shield_notes enable row level security;

-- Participants read every note on their job, including the other party's.
-- A record the contractor can see but the homeowner cannot is not a shared
-- record, and the asymmetry is exactly what a dispute would attack.
drop policy if exists shield_notes_read on public.shield_notes;
create policy shield_notes_read on public.shield_notes
  for select to authenticated
  using (exists (select 1 from public.shield_jobs j
                 where j.id = public.shield_notes.shield_job_id
                   and (j.homeowner_id = auth.uid() or j.contractor_id = auth.uid())));

-- No client write policy. Notes are written through the API so written_at is
-- server-set, the delay is computed against the observation, and the entry is
-- sealed into the chain. A client-inserted note could claim any timestamp it
-- liked, which would defeat the only thing that makes it worth having.


-- =====================================================================
-- VERIFY
--   select count(*) from public.shield_notes;
--   -- append-only should raise:
--   --   update public.shield_notes set body = 'x' where id = <any>;
--   select policyname, cmd from pg_policies where tablename = 'shield_notes';
--   -- expect exactly one: shield_notes_read / SELECT
-- =====================================================================
