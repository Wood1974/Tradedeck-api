-- =====================================================================
-- Shield hardening — corrections to 20260914000000 plus the anchors the
-- evidence model was missing.
--
-- Written as a second migration rather than an edit to the first so it is
-- safe whether or not the first has already been applied. Idempotent.
--
-- WHY EACH CHANGE EXISTS
--
--   1. shield_jobs had no site location. There was therefore nothing to
--      corroborate a photo's GPS *against* — the service compared the EXIF the
--      uploader wrote with the coordinates the uploader typed, and called
--      agreement "corroborated". Both sides were the same party. A site
--      location makes the check mean something.
--
--   2. external_ref did not exist. The API writes it on every job creation, so
--      POST /shield/jobs failed 100% of the time with a generic 500. It is
--      added as text, not uuid: an external system's id is not ours to
--      constrain, and the unique index on job_id let anyone squat a reference.
--
--   3. Checkpoints were re-generatable forever by either party. The contractor
--      could photograph whatever was actually built, read the verdicts, then
--      rewrite the requirements to match. A locked-at timestamp makes the
--      schedule a commitment made before the work, which is the property that
--      makes the record worth anything in a dispute.
--
--   4. The custody log had no links between rows. The append-only trigger
--      stops an application bug; it does not stop anyone who can DROP TRIGGER
--      or TRUNCATE, and it leaves no trace. Hash-chain columns make tampering
--      detectable rather than merely disallowed.
--
--   5. Capture tokens. A server-issued nonce with a short TTL bounds *when* an
--      upload happened, independent of any metadata the uploader controls.
-- =====================================================================


-- ---------------------------------------------------------------------
-- 1. Site location, external reference, payment binding, schedule lock
-- ---------------------------------------------------------------------
alter table public.shield_jobs
  add column if not exists external_ref              text,
  add column if not exists site_address              text,
  add column if not exists site_lat                  double precision,
  add column if not exists site_lng                  double precision,
  add column if not exists site_radius_m             integer not null default 250,
  add column if not exists job_budget_cents          bigint,
  add column if not exists stripe_payment_intent_id  text,
  add column if not exists checkpoints_locked_at     timestamptz,
  add column if not exists cancelled_at              timestamptz;

comment on column public.shield_jobs.site_lat is
  'Job site latitude, set at purchase by the homeowner. Photos are geofenced '
  'against THIS, not against coordinates supplied with the upload.';
comment on column public.shield_jobs.checkpoints_locked_at is
  'When the checkpoint schedule was frozen. After this, requirements cannot be '
  'rewritten — the audit criteria predate the work being audited.';

-- The old unique index on job_id let one caller squat another system's job id
-- and blocked legitimate re-use. Reference binding belongs to external_ref,
-- which is scoped per owner rather than globally.
drop index if exists public.shield_jobs_job_id_uniq;
create unique index if not exists shield_jobs_external_ref_uniq
  on public.shield_jobs (homeowner_id, external_ref)
  where external_ref is not null;

create unique index if not exists shield_jobs_payment_intent_uniq
  on public.shield_jobs (stripe_payment_intent_id)
  where stripe_payment_intent_id is not null;

-- A job is only geofenceable if it has both coordinates or neither.
alter table public.shield_jobs drop constraint if exists shield_jobs_site_coords_paired;
alter table public.shield_jobs add constraint shield_jobs_site_coords_paired
  check ((site_lat is null) = (site_lng is null));

alter table public.shield_jobs drop constraint if exists shield_jobs_site_lat_range;
alter table public.shield_jobs add constraint shield_jobs_site_lat_range
  check (site_lat is null or site_lat between -90 and 90);

alter table public.shield_jobs drop constraint if exists shield_jobs_site_lng_range;
alter table public.shield_jobs add constraint shield_jobs_site_lng_range
  check (site_lng is null or site_lng between -180 and 180);

-- A contractor auditing their own work is not an audit.
alter table public.shield_jobs drop constraint if exists shield_jobs_distinct_parties;
alter table public.shield_jobs add constraint shield_jobs_distinct_parties
  check (homeowner_id is null or contractor_id is null
         or homeowner_id <> contractor_id);


-- ---------------------------------------------------------------------
-- 2. Photos: bind every photo to its checkpoint's job, and to a capture
-- ---------------------------------------------------------------------
alter table public.shield_photos
  add column if not exists capture_token_id  uuid,
  add column if not exists site_distance_m   double precision,
  add column if not exists superseded_by     uuid references public.shield_photos(id),
  add column if not exists superseded_at     timestamptz,
  add column if not exists content_sha256_verified boolean not null default true;

comment on column public.shield_photos.site_distance_m is
  'Metres between the reported capture position and the job site. Null when '
  'the job carries no site location.';
comment on column public.shield_photos.superseded_by is
  'Set when a later photo replaces this one for the same checkpoint. Retakes '
  'are recorded, never deleted — the attempt history is part of the evidence.';

-- One live (non-superseded) photo per checkpoint. Retakes must explicitly
-- supersede, which keeps every attempt in the record instead of letting a
-- contractor re-roll the AI until a pass appears and silently hiding the rest.
create unique index if not exists shield_photos_one_live_per_point
  on public.shield_photos (point_id)
  where superseded_by is null;


-- ---------------------------------------------------------------------
-- 3. Capture tokens — a server-issued nonce bounding when a photo was taken
-- ---------------------------------------------------------------------
create table if not exists public.shield_capture_tokens (
  id             uuid primary key default gen_random_uuid(),
  shield_job_id  uuid not null references public.shield_jobs(id) on delete cascade,
  point_id       uuid not null references public.shield_pivotal_points(id) on delete cascade,
  contractor_id  uuid not null,
  token_hash     text not null unique,     -- only the hash is stored
  issued_at      timestamptz not null default now(),
  expires_at     timestamptz not null,
  redeemed_at    timestamptz,
  redeemed_photo uuid references public.shield_photos(id),
  check (expires_at > issued_at)
);

create index if not exists shield_tokens_job_idx on public.shield_capture_tokens (shield_job_id);
create index if not exists shield_tokens_open_idx
  on public.shield_capture_tokens (point_id) where redeemed_at is null;


-- ---------------------------------------------------------------------
-- 4. Custody chain
-- ---------------------------------------------------------------------
alter table public.shield_custody_log
  add column if not exists chain_version integer not null default 1,
  add column if not exists prev_hash     text,
  add column if not exists entry_hash    text;

create index if not exists shield_custody_chain_idx
  on public.shield_custody_log (shield_job_id, recorded_at);

-- TRUNCATE fires no row-level trigger, so the append-only guarantee from the
-- first migration could be erased with one statement. Statement-level trigger
-- closes that.
drop trigger if exists shield_custody_no_truncate on public.shield_custody_log;
create trigger shield_custody_no_truncate
  before truncate on public.shield_custody_log
  for each statement execute function public.shield_custody_immutable();

-- The custody log referenced event types the service actually emits for job
-- creation and payment activation, which had no home in the original CHECK and
-- were being logged as 'uploaded' — producing upload events with no photo.
alter table public.shield_custody_log drop constraint if exists shield_custody_log_event_type_check;
alter table public.shield_custody_log add constraint shield_custody_log_event_type_check
  check (event_type in ('created', 'activated', 'checkpoints_locked', 'token_issued',
                        'uploaded', 'superseded', 'ai_analyzed', 'flagged',
                        'integrity_flag', 'viewed', 'exported', 'completed',
                        'cancelled', 'refunded'));

-- Evidence must not be destroyable by deleting its parent row. The first
-- migration cascaded photos away and nulled custody rows into RLS invisibility
-- — one DELETE erased both the evidence and the trail of its erasure.
alter table public.shield_photos drop constraint if exists shield_photos_shield_job_id_fkey;
alter table public.shield_photos add constraint shield_photos_shield_job_id_fkey
  foreign key (shield_job_id) references public.shield_jobs(id) on delete restrict;

alter table public.shield_custody_log drop constraint if exists shield_custody_log_shield_job_id_fkey;
alter table public.shield_custody_log add constraint shield_custody_log_shield_job_id_fkey
  foreign key (shield_job_id) references public.shield_jobs(id) on delete restrict;


-- ---------------------------------------------------------------------
-- 5. Completion reports: one per job, and 'fake' must be sayable
-- ---------------------------------------------------------------------
-- Without this, calling complete three times wrote three 'pass' rows, and the
-- badge check counted rows rather than jobs — so one self-dealt job could mint
-- the verified badge.
create unique index if not exists shield_reports_one_per_job
  on public.shield_completion_reports (shield_job_id);

alter table public.shield_completion_reports
  drop constraint if exists shield_completion_reports_overall_verdict_check;
alter table public.shield_completion_reports
  add constraint shield_completion_reports_overall_verdict_check
  check (overall_verdict is null or overall_verdict in ('pass', 'flag', 'fail', 'fake'));

alter table public.shield_completion_reports
  add column if not exists custody_head_hash text,
  add column if not exists signature         text,
  add column if not exists signing_key_id    text;

comment on column public.shield_completion_reports.custody_head_hash is
  'Chain head at close-out. A holder of this value can later detect any '
  'rewrite of the job history, including by the operator.';


-- ---------------------------------------------------------------------
-- 6. RLS corrections
-- ---------------------------------------------------------------------
alter table public.shield_capture_tokens enable row level security;
-- No policy: tokens are server-only. RLS on with zero policies denies all
-- client access while the service role continues to bypass.

-- The previous storage policy was PERMISSIVE, and Postgres ORs permissive
-- policies together — so `using (bucket_id <> 'shield-photos')` could not deny
-- anything. Worse, it GRANTED authenticated read on every other bucket in the
-- project, including draw-photos. A RESTRICTIVE policy is the construct that
-- actually subtracts access.
drop policy if exists shield_photos_no_client_read on storage.objects;
drop policy if exists shield_evidence_bucket_denied on storage.objects;
create policy shield_evidence_bucket_denied on storage.objects
  as restrictive
  for select to authenticated
  using (bucket_id <> 'shield-photos');

-- The participant sub-queries referenced shield_job_id unqualified. It happens
-- to resolve to the outer table today only because shield_jobs has no column
-- of that name; adding one would silently turn every policy into j.id = j.id
-- and leak across tenants. Qualify them.
drop policy if exists shield_points_read on public.shield_pivotal_points;
create policy shield_points_read on public.shield_pivotal_points
  for select to authenticated
  using (exists (select 1 from public.shield_jobs j
                 where j.id = public.shield_pivotal_points.shield_job_id
                   and (j.homeowner_id = auth.uid() or j.contractor_id = auth.uid())));

-- Photos: narrowed to a view-safe column set. The previous whole-row grant
-- exposed exif_raw — camera serial numbers, owner name, MakerNote, and the GPS
-- of unrelated photos from the same roll — to the other party on the job.
drop policy if exists shield_photos_read on public.shield_photos;
create policy shield_photos_read on public.shield_photos
  for select to authenticated
  using (exists (select 1 from public.shield_jobs j
                 where j.id = public.shield_photos.shield_job_id
                   and (j.homeowner_id = auth.uid() or j.contractor_id = auth.uid())));

revoke select on public.shield_photos from authenticated;
grant select (id, point_id, shield_job_id, contractor_id, original_hash,
              original_hash_algo, original_size_bytes, gps_lat, gps_lng,
              gps_accuracy_m, site_distance_m, exif_captured_at, has_exif,
              ai_verdict, ai_confidence, ai_notes, ai_authentic, ai_model,
              code_reference, photo_hash, hash_algorithm, server_received_at,
              integrity_sealed_at, uploaded_at, superseded_by, superseded_at)
  on public.shield_photos to authenticated;

drop policy if exists shield_custody_read on public.shield_custody_log;
create policy shield_custody_read on public.shield_custody_log
  for select to authenticated
  using (exists (select 1 from public.shield_jobs j
                 where j.id = public.shield_custody_log.shield_job_id
                   and (j.homeowner_id = auth.uid() or j.contractor_id = auth.uid())));


-- =====================================================================
-- VERIFY
--   select column_name from information_schema.columns
--   where table_name = 'shield_jobs' order by ordinal_position;
--
--   -- restrictive policy present?
--   select policyname, permissive from pg_policies
--   where tablename = 'objects' and policyname = 'shield_evidence_bucket_denied';
--   -- permissive should read 'RESTRICTIVE'
-- =====================================================================
