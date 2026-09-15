-- =====================================================================
-- TradeDeck Shield — schema reconstruction + row-level security
-- =====================================================================
--
-- WHY THIS FILE EXISTS
--   The six shield_* tables existed only inside the live Supabase project.
--   There was no migration for any of them, so the schema could not be
--   rebuilt, staged, or tested — and Shield could not be extracted into a
--   standalone service. This file reconstructs them from column usage in
--   shield_api.py and turns RLS on, which was enabled on no table anywhere.
--
-- HOW IT WAS DERIVED
--   Every column below appears in an insert(), update(), select() or eq()
--   in shield_api.py. Types are inferred from what the Python writes.
--   Columns marked DERIVED-UNCERTAIN are inferred from usage but were not
--   observed in an explicit write — check them against the live table with
--   the verification query at the bottom before trusting this in prod.
--
-- IDEMPOTENT. Safe to re-run. Does not drop or alter existing data.
--
-- ORDER OF OPERATIONS FOR AN EXISTING PROJECT
--   1. Run the verification query at the bottom FIRST.
--   2. Reconcile any drift between live columns and this file.
--   3. Only then apply — the RLS section changes access for live clients.
--
-- READ BEFORE APPLYING THE RLS SECTION
--   Enabling RLS is a breaking change for any client that currently relies
--   on the anon key having unrestricted access. The frontend writes
--   directly to profiles/jobs/draws with the anon key today. Turning RLS on
--   without the companion policies WILL break those writes — that is the
--   point, but stage it.
-- =====================================================================

-- ---------------------------------------------------------------------
-- Extensions
-- ---------------------------------------------------------------------
create extension if not exists "pgcrypto";


-- ---------------------------------------------------------------------
-- shield_jobs — one purchased Shield engagement
-- ---------------------------------------------------------------------
create table if not exists public.shield_jobs (
  id                 uuid primary key default gen_random_uuid(),
  job_id             uuid,                -- external ref (TradeDeck jobs.id)
  homeowner_id       uuid references auth.users(id) on delete set null,
  contractor_id      uuid references auth.users(id) on delete set null,
  trade              text,
  amount_cents       integer check (amount_cents is null or amount_cents >= 0),
  status             text not null default 'pending'
                       check (status in ('pending','active','complete','cancelled','refunded')),
  stripe_payment_id  text,
  activated_at       timestamptz,
  completed_at       timestamptz,
  created_at         timestamptz not null default now()
);

create index if not exists shield_jobs_job_id_idx        on public.shield_jobs (job_id);
create index if not exists shield_jobs_contractor_idx    on public.shield_jobs (contractor_id);
create index if not exists shield_jobs_homeowner_idx     on public.shield_jobs (homeowner_id);
create index if not exists shield_jobs_status_idx        on public.shield_jobs (status);

-- Webhook activation does .eq('job_id', …).eq('status','pending'); without a
-- uniqueness guarantee a duplicated job_id would activate several rows at once.
create unique index if not exists shield_jobs_job_id_uniq
  on public.shield_jobs (job_id) where job_id is not null;


-- ---------------------------------------------------------------------
-- shield_pivotal_points — the 5 AI-generated checkpoints per job
-- ---------------------------------------------------------------------
create table if not exists public.shield_pivotal_points (
  id                 uuid primary key default gen_random_uuid(),
  shield_job_id      uuid not null references public.shield_jobs(id) on delete cascade,
  job_id             uuid,
  point_number       integer not null check (point_number between 1 and 20),
  label              text,
  description        text,
  irc_code           text,
  ibc_code           text,
  photo_instruction  text,
  must_show          text,
  status             text not null default 'pending'
                       check (status in ('pending','approved','flagged')),
  created_at         timestamptz not null default now()
);

-- generate_points() upserts on (shield_job_id, point_number); enforce it.
create unique index if not exists shield_points_job_number_uniq
  on public.shield_pivotal_points (shield_job_id, point_number);


-- ---------------------------------------------------------------------
-- shield_photos — the evidentiary record
-- ---------------------------------------------------------------------
-- NOTE ON THREE COLUMNS REMOVED FROM THE LIVE SHAPE:
--   upload_ip          was being written the HASH, not an IP. Duplicate of
--                      upload_ip_hash under a misleading name. Dropped.
--   device_user_agent  written the identical value as upload_user_agent.
--   file_size_bytes    duplicate of original_size_bytes.
-- If the live table has them, leave them; do not write them going forward.
create table if not exists public.shield_photos (
  id                       uuid primary key default gen_random_uuid(),
  point_id                 uuid references public.shield_pivotal_points(id) on delete set null,
  shield_job_id            uuid not null references public.shield_jobs(id) on delete cascade,
  contractor_id            uuid references auth.users(id) on delete set null,

  -- integrity anchor: SHA-256 over the raw bytes as received, before any
  -- processing. This is the whole product. It must be computed server-side.
  original_hash            text not null,
  original_hash_algo       text not null default 'SHA-256',
  original_size_bytes      bigint,
  original_storage_path    text not null,
  compressed_storage_path  text,

  -- GPS as reported by the client at upload time
  gps_lat                  double precision,
  gps_lng                  double precision,
  gps_accuracy_m           double precision,

  -- GPS and provenance as extracted server-side from EXIF
  exif_gps_lat             double precision,
  exif_gps_lng             double precision,
  exif_gps_altitude_m      double precision,
  exif_captured_at         timestamptz,
  exif_device_make         text,
  exif_device_model        text,
  exif_software            text,
  exif_orientation         integer,
  exif_raw                 jsonb,
  has_exif                 boolean not null default false,

  -- AI verdict
  ai_verdict               text check (ai_verdict is null or ai_verdict in ('pass','flag','fail','fake')),
  ai_confidence            numeric(4,3) check (ai_confidence is null or ai_confidence between 0 and 1),
  ai_notes                 text,
  ai_authentic             boolean,
  ai_model                 text,
  code_reference           text,

  -- hash of the compressed copy actually shown to the model
  photo_hash               text,
  hash_algorithm           text default 'SHA-256',

  -- custody timestamps and upload provenance
  server_received_at       timestamptz,
  integrity_sealed_at      timestamptz,
  uploaded_at              timestamptz not null default now(),
  upload_user_agent        text,
  upload_ip_hash           text,          -- salted SHA-256; salt MUST come from env

  created_at               timestamptz not null default now()
);

create index if not exists shield_photos_job_idx        on public.shield_photos (shield_job_id);
create index if not exists shield_photos_point_idx      on public.shield_photos (point_id);
create index if not exists shield_photos_contractor_idx on public.shield_photos (contractor_id);
create index if not exists shield_photos_verdict_idx    on public.shield_photos (ai_verdict);

-- The same original bytes must never be admitted twice under two photo ids.
create unique index if not exists shield_photos_hash_job_uniq
  on public.shield_photos (shield_job_id, original_hash);


-- ---------------------------------------------------------------------
-- shield_custody_log — append-only chain of custody
-- ---------------------------------------------------------------------
create table if not exists public.shield_custody_log (
  id                uuid primary key default gen_random_uuid(),
  photo_id          uuid references public.shield_photos(id) on delete set null,
  shield_job_id     uuid references public.shield_jobs(id) on delete set null,
  event_type        text not null
                      check (event_type in ('uploaded','ai_analyzed','flagged',
                                            'integrity_flag','viewed','exported','completed')),
  actor_id          uuid,
  actor_type        text not null default 'system'
                      check (actor_type in ('system','contractor','homeowner','ai','admin')),
  event_data        jsonb,
  gps_lat           double precision,
  gps_lng           double precision,
  file_hash         text,
  integrity_note    text,
  exif_captured_at  timestamptz,
  recorded_at       timestamptz not null default now()
);

create index if not exists shield_custody_photo_idx on public.shield_custody_log (photo_id);
create index if not exists shield_custody_job_idx   on public.shield_custody_log (shield_job_id);
create index if not exists shield_custody_time_idx  on public.shield_custody_log (recorded_at desc);

-- An audit trail that can be edited is not an audit trail. No policy below
-- grants update or delete to any role; service_role bypasses RLS, so keep
-- the API's own writes to insert-only.
create or replace function public.shield_custody_immutable()
returns trigger language plpgsql as $$
begin
  raise exception 'shield_custody_log is append-only (attempted %)', tg_op;
end $$;

drop trigger if exists shield_custody_no_mutate on public.shield_custody_log;
create trigger shield_custody_no_mutate
  before update or delete on public.shield_custody_log
  for each row execute function public.shield_custody_immutable();


-- ---------------------------------------------------------------------
-- shield_completion_reports — signed close-out packet
-- ---------------------------------------------------------------------
create table if not exists public.shield_completion_reports (
  id                uuid primary key default gen_random_uuid(),
  shield_job_id     uuid not null references public.shield_jobs(id) on delete cascade,
  job_id            uuid,
  contractor_id     uuid,
  homeowner_id      uuid,
  overall_verdict   text check (overall_verdict is null or overall_verdict in ('pass','flag','fail')),
  completion_score  numeric(5,1) check (completion_score is null or completion_score between 0 and 100),
  report_json       jsonb not null,
  report_sha256     text,
  created_at        timestamptz not null default now()
);

create index if not exists shield_reports_job_idx        on public.shield_completion_reports (shield_job_id);
create index if not exists shield_reports_contractor_idx on public.shield_completion_reports (contractor_id);


-- ---------------------------------------------------------------------
-- shield_subscriptions — contractor Shield Pro
-- ---------------------------------------------------------------------
create table if not exists public.shield_subscriptions (
  id                  uuid primary key default gen_random_uuid(),
  contractor_id       uuid not null references auth.users(id) on delete cascade,
  stripe_customer_id  text,
  stripe_sub_id       text unique,
  status              text not null default 'inactive'
                        check (status in ('active','inactive','cancelled','past_due','paused')),
  current_period_end  bigint,             -- Stripe epoch seconds, as written
  created_at          timestamptz not null default now()
);

create index if not exists shield_subs_contractor_idx on public.shield_subscriptions (contractor_id);


-- ---------------------------------------------------------------------
-- Webhook idempotency (already present in supabase_security.sql; repeated
-- here so this file alone is sufficient to stand a Shield database up)
-- ---------------------------------------------------------------------
create table if not exists public.stripe_webhook_events (
  event_id      text primary key,
  event_type    text not null,
  processed_at  timestamptz not null default now()
);


-- ---------------------------------------------------------------------
-- Private storage bucket
-- ---------------------------------------------------------------------
-- public = false. Shield photos are evidence; they are served only through
-- short-lived signed URLs minted server-side. The browser client currently
-- calls getPublicUrl() against the wrong bucket entirely — that path is to
-- be removed, not accommodated.
insert into storage.buckets (id, name, public)
values ('shield-photos', 'shield-photos', false)
on conflict (id) do update set public = false;


-- =====================================================================
-- ROW-LEVEL SECURITY
-- =====================================================================
-- Was enabled on NO table in this project. The anon key is shipped in the
-- browser, so until this runs, every table is world read/write — including
-- profiles.tradedeck_verified, which lets any visitor award themselves the
-- verified badge the whole trust system is built on.
--
-- Model: the API holds the service_role key and bypasses RLS entirely, so
-- these policies govern the BROWSER's anon/authenticated key only. Shield
-- rows are readable by their participants and writable by nobody from the
-- client — every Shield mutation must go through the Flask API so the
-- custody log is always written.
-- =====================================================================

alter table public.shield_jobs                enable row level security;
alter table public.shield_pivotal_points      enable row level security;
alter table public.shield_photos              enable row level security;
alter table public.shield_custody_log         enable row level security;
alter table public.shield_completion_reports  enable row level security;
alter table public.shield_subscriptions       enable row level security;
alter table public.stripe_webhook_events      enable row level security;

-- shield_jobs: participants read their own.
drop policy if exists shield_jobs_read on public.shield_jobs;
create policy shield_jobs_read on public.shield_jobs
  for select to authenticated
  using (homeowner_id = auth.uid() or contractor_id = auth.uid());

-- Checkpoints: visible to whoever can see the parent job.
drop policy if exists shield_points_read on public.shield_pivotal_points;
create policy shield_points_read on public.shield_pivotal_points
  for select to authenticated
  using (exists (
    select 1 from public.shield_jobs j
    where j.id = shield_job_id
      and (j.homeowner_id = auth.uid() or j.contractor_id = auth.uid())
  ));

-- Photos: read-only to participants. No client insert — uploads go through
-- POST /shield/upload-photo so the server computes the hash it will later
-- rely on as evidence.
drop policy if exists shield_photos_read on public.shield_photos;
create policy shield_photos_read on public.shield_photos
  for select to authenticated
  using (exists (
    select 1 from public.shield_jobs j
    where j.id = shield_job_id
      and (j.homeowner_id = auth.uid() or j.contractor_id = auth.uid())
  ));

-- Custody log: readable by participants, writable by no client role.
drop policy if exists shield_custody_read on public.shield_custody_log;
create policy shield_custody_read on public.shield_custody_log
  for select to authenticated
  using (exists (
    select 1 from public.shield_jobs j
    where j.id = shield_job_id
      and (j.homeowner_id = auth.uid() or j.contractor_id = auth.uid())
  ));

drop policy if exists shield_reports_read on public.shield_completion_reports;
create policy shield_reports_read on public.shield_completion_reports
  for select to authenticated
  using (contractor_id = auth.uid() or homeowner_id = auth.uid());

drop policy if exists shield_subs_read on public.shield_subscriptions;
create policy shield_subs_read on public.shield_subscriptions
  for select to authenticated
  using (contractor_id = auth.uid());

-- stripe_webhook_events: RLS on, zero policies — service_role only.

-- Storage objects: no client-side access to the evidence bucket at all.
drop policy if exists shield_photos_no_client_read on storage.objects;
create policy shield_photos_no_client_read on storage.objects
  for select to authenticated
  using (bucket_id <> 'shield-photos');


-- =====================================================================
-- VERIFICATION — run BEFORE applying against an existing project
-- =====================================================================
-- 1. Columns that exist live but are missing from this file:
--
--   select table_name, column_name, data_type
--   from information_schema.columns
--   where table_schema = 'public' and table_name like 'shield%'
--   order by table_name, ordinal_position;
--
-- 2. Tables still missing RLS (should return zero rows after this runs):
--
--   select tablename from pg_tables
--   where schemaname = 'public' and rowsecurity = false;
--
-- 3. THE IMPORTANT ONE — non-Shield tables the browser writes to directly
--    (profiles, jobs, draws, draw_schedules, applications, contact_requests)
--    are NOT covered by this migration. They are where the self-verification
--    hole lives. They need their own policies before RLS is enabled on them,
--    or the frontend's 31 direct calls will start failing.
-- =====================================================================
