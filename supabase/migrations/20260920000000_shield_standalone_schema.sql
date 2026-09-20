-- Shield, standalone: its own schema, its own identity, no TradeDeck.
--
-- WHY THIS IS A NEW SCHEMA RATHER THAN AN ALTERATION
--
-- The `public.shield_*` tables are TradeDeck's. Six foreign keys tie them to
-- `public.jobs` and `public.profiles`, which is what made Shield unsellable to
-- anybody else: a second business could not hold a record without first
-- existing as a row in someone else's marketplace.
--
-- Those tables are left exactly as they are. The old `shield_api.py` still
-- serves them, the one test job and its two photos stay where they are, and
-- nothing in this file touches them. Separation by addition, not by
-- transformation — there is no step here that can destroy anything.
--
-- Everything Shield owns now lives in the `shield` schema and references
-- nothing outside it. That constraint is not a style preference: it is what
-- makes this schema liftable into its own database later without rewriting a
-- single foreign key.
--
-- WHAT REPLACED THE TRADEDECK IDENTITIES
--
-- `homeowner_id` and `contractor_id` were foreign keys into `profiles`. They
-- are now `buyer_ref` and `subject_ref` — opaque strings the tenant supplies,
-- meaning whatever the tenant's own system means by them. Shield does not
-- resolve them, does not validate them, and cannot: they are somebody else's
-- identifiers. That is the point. A record belongs to a tenant; the parties
-- named in it belong to the tenant's world.

create schema if not exists shield;

comment on schema shield is
  'TradeDeck Shield. Self-contained: nothing here references any other schema.';

-- ---------------------------------------------------------------- identity --

create table if not exists shield.tenants (
    id          uuid primary key default gen_random_uuid(),
    name        text not null check (length(trim(name)) between 1 and 200),
    slug        text not null unique check (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
    status      text not null default 'active'
                check (status in ('active', 'suspended', 'closed')),
    created_at  timestamptz not null default now()
);

comment on table shield.tenants is
  'A business using Shield. The unit of isolation: every row in every other '
  'table below carries a tenant_id, and no query may run unscoped.';

-- API keys: machine-to-machine. One row per key, the plaintext never stored.
create table if not exists shield.api_keys (
    id            uuid primary key default gen_random_uuid(),
    tenant_id     uuid not null references shield.tenants(id) on delete cascade,
    public_id     text not null unique check (public_id ~ '^[a-f0-9]{8,64}$'),
    key_hash      text not null check (key_hash ~ '^[a-f0-9]{64}$'),
    label         text,
    created_at    timestamptz not null default now(),
    last_used_at  timestamptz,
    revoked_at    timestamptz
);

comment on column shield.api_keys.public_id is
  'The middle segment of shld_<public_id>_<secret>. Safe to log, and what '
  'turns verification into one indexed lookup instead of a scan of every hash.';
comment on column shield.api_keys.key_hash is
  'SHA-256 of the secret half. Fast on purpose — the secret is 32 random '
  'bytes, so there is no dictionary to slow down, and a KDF here would cost '
  '100ms on every request. See tenancy.py; this is not the password-hashing '
  'defect it resembles.';

create index if not exists shield_api_keys_tenant_idx
    on shield.api_keys (tenant_id) where revoked_at is null;

-- Members: humans signed in to Shield's own web client.
create table if not exists shield.members (
    id            uuid primary key default gen_random_uuid(),
    tenant_id     uuid not null references shield.tenants(id) on delete cascade,
    auth_user_id  uuid not null,
    email         text not null check (position('@' in email) > 1),
    role          text not null default 'member'
                  check (role in ('owner', 'member', 'viewer')),
    created_at    timestamptz not null default now(),
    disabled_at   timestamptz,
    unique (tenant_id, auth_user_id)
);

comment on column shield.members.auth_user_id is
  'Subject id from Shield''s OWN auth provider. Deliberately not a foreign '
  'key: the auth schema is the provider''s, and Shield must remain liftable '
  'into a different database without rewriting a reference.';

-- ------------------------------------------------------------------ records --

create table if not exists shield.records (
    id                     uuid primary key default gen_random_uuid(),
    tenant_id              uuid not null references shield.tenants(id) on delete restrict,
    external_ref           text not null,
    subject_ref            text,
    buyer_ref              text,
    trade                  text,
    site_address           text,
    site_lat               double precision check (site_lat between -90 and 90),
    site_lng               double precision check (site_lng between -180 and 180),
    status                 text not null default 'active'
                           check (status in ('active', 'complete', 'cancelled')),
    checkpoints_locked_at  timestamptz,
    created_at             timestamptz not null default now(),
    completed_at           timestamptz,
    constraint records_site_coords_paired
        check ((site_lat is null) = (site_lng is null)),
    constraint records_distinct_parties
        check (subject_ref is null or buyer_ref is null or subject_ref <> buyer_ref),
    unique (tenant_id, external_ref)
);

comment on table shield.records is
  'One sealed body of work. Was public.shield_jobs, which keyed into '
  'TradeDeck''s jobs table; this one is keyed by the tenant''s own external_ref.';
comment on column shield.records.subject_ref is
  'Whoever the tenant says did the work. An opaque string from the tenant''s '
  'own system — Shield does not resolve it and cannot.';
comment on column shield.records.checkpoints_locked_at is
  'Set once. After this the schedule cannot be regenerated, so requirements '
  'cannot be rewritten to fit the photographs that arrived.';

create table if not exists shield.checkpoints (
    id             uuid primary key default gen_random_uuid(),
    tenant_id      uuid not null references shield.tenants(id) on delete restrict,
    record_id      uuid not null references shield.records(id) on delete restrict,
    point_number   int not null check (point_number > 0),
    label          text not null,
    description    text,
    code_reference text,
    must_show      text,
    status         text not null default 'pending'
                   check (status in ('pending', 'approved', 'flagged', 'failed')),
    created_at     timestamptz not null default now(),
    unique (record_id, point_number)
);

create table if not exists shield.photos (
    id                 uuid primary key default gen_random_uuid(),
    tenant_id          uuid not null references shield.tenants(id) on delete restrict,
    record_id          uuid not null references shield.records(id) on delete restrict,
    checkpoint_id      uuid not null references shield.checkpoints(id) on delete restrict,
    uploaded_by_ref    text,
    storage_path       text not null,
    original_hash      text not null check (original_hash ~ '^[a-f0-9]{64}$'),
    original_size_bytes bigint,
    verdict            text check (verdict in ('pass', 'flag', 'fail', 'fake')),
    verdict_confidence double precision,
    verdict_notes      text,
    has_exif           boolean,
    exif_captured_at   timestamptz,
    gps_lat            double precision check (gps_lat between -90 and 90),
    gps_lng            double precision check (gps_lng between -180 and 180),
    site_distance_m    double precision,
    integrity_note     text,
    attestation_tier   text,
    upload_ip_hash     text,
    uploaded_at        timestamptz not null default now(),
    received_at        timestamptz not null default now(),
    superseded_by      uuid references shield.photos(id),
    superseded_at      timestamptz
);

comment on column shield.photos.superseded_by is
  'A retake supersedes; it never erases. Both rows stay, and the outcome '
  'report counts the superseded one so a corrected failure cannot vanish.';
comment on column shield.photos.received_at is
  'Server time. Proves not-after, never not-before — the honest limit. The '
  'capture time in exif_captured_at is the subject''s claim, not ours.';

-- One live photo per checkpoint. Retakes are allowed; two simultaneous
-- claims on the same requirement are not.
create unique index if not exists shield_photos_one_live_per_checkpoint
    on shield.photos (checkpoint_id)
    where superseded_by is null and superseded_at is null;

create index if not exists shield_photos_record_idx
    on shield.photos (tenant_id, record_id);

-- ------------------------------------------------------------ custody chain --

create table if not exists shield.custody_log (
    id                uuid primary key default gen_random_uuid(),
    tenant_id         uuid not null references shield.tenants(id) on delete restrict,
    record_id         uuid not null references shield.records(id) on delete restrict,
    photo_id          uuid references shield.photos(id),
    event_type        text not null check (event_type in (
                          'created', 'checkpoints_locked', 'uploaded',
                          'analyzed', 'superseded', 'integrity_flag',
                          'note_written', 'note_amended', 'viewed',
                          'exported', 'completed')),
    actor_ref         text,
    actor_kind        text check (actor_kind in ('api_key', 'member', 'system')),
    event_data        jsonb,
    gps_lat           double precision,
    gps_lng           double precision,
    file_hash         text,
    integrity_note    text,
    exif_captured_at  timestamptz,
    recorded_at       timestamptz not null default now(),
    prev_hash         text not null check (prev_hash ~ '^[a-f0-9]{64}$'),
    entry_hash        text not null unique check (entry_hash ~ '^[a-f0-9]{64}$'),
    chain_version     int not null default 1
);

comment on table shield.custody_log is
  'Append-only, hash-linked. prev_hash and entry_hash are the columns the '
  'public.shield_custody_log never had, which is why no chain has ever been '
  'written. Altering any signed field breaks every link after it.';

create index if not exists shield_custody_chain_idx
    on shield.custody_log (record_id, recorded_at);

create or replace function shield.custody_is_append_only()
returns trigger language plpgsql as $$
begin
    raise exception 'shield.custody_log is append-only: % is not permitted',
        tg_op;
end $$;

drop trigger if exists shield_custody_no_mutate on shield.custody_log;
create trigger shield_custody_no_mutate
    before update or delete on shield.custody_log
    for each row execute function shield.custody_is_append_only();

-- A row-level trigger cannot see TRUNCATE. Without this statement-level one,
-- the whole chain is removable in a single statement that fires nothing.
drop trigger if exists shield_custody_no_truncate on shield.custody_log;
create trigger shield_custody_no_truncate
    before truncate on shield.custody_log
    for each statement execute function shield.custody_is_append_only();

-- ------------------------------------------------------------- field notes --

create table if not exists shield.notes (
    id              uuid primary key default gen_random_uuid(),
    tenant_id       uuid not null references shield.tenants(id) on delete restrict,
    record_id       uuid not null references shield.records(id) on delete restrict,
    checkpoint_id   uuid references shield.checkpoints(id),
    photo_id        uuid references shield.photos(id),
    author_ref      text,
    body            text not null check (length(trim(body)) > 0),
    amends_note_id  uuid references shield.notes(id),
    amend_reason    text,
    written_at      timestamptz not null default now()
);

comment on column shield.notes.written_at is
  'Server-set. A note whose timestamp the author chose is not contemporaneous.';
comment on column shield.notes.amends_note_id is
  'Corrections are appended and disclosed. The original stays readable.';

create unique index if not exists shield_notes_one_amendment_per_note
    on shield.notes (amends_note_id) where amends_note_id is not null;

drop trigger if exists shield_notes_no_mutate on shield.notes;
create trigger shield_notes_no_mutate
    before update or delete on shield.notes
    for each row execute function shield.custody_is_append_only();

drop trigger if exists shield_notes_no_truncate on shield.notes;
create trigger shield_notes_no_truncate
    before truncate on shield.notes
    for each statement execute function shield.custody_is_append_only();

-- --------------------------------------------------------------- close-out --

create table if not exists shield.completion_reports (
    id                uuid primary key default gen_random_uuid(),
    tenant_id         uuid not null references shield.tenants(id) on delete restrict,
    record_id         uuid not null references shield.records(id) on delete restrict,
    overall_verdict   text not null
                      check (overall_verdict in ('pass', 'flag', 'fail', 'fake')),
    completion_score  double precision not null,
    coverage_pct      double precision not null,
    report_json       jsonb not null,
    report_sha256     text not null check (report_sha256 ~ '^[a-f0-9]{64}$'),
    custody_head_hash text not null check (custody_head_hash ~ '^[a-f0-9]{64}$'),
    closed_at         timestamptz not null default now()
);

-- One close-out per record. Repeat close-outs were how the badge was minted.
create unique index if not exists shield_reports_one_per_record
    on shield.completion_reports (record_id);

comment on column shield.completion_reports.custody_head_hash is
  'The head the recipient should keep. It is the only thing that later '
  'detects entries deleted from the end of the chain.';

-- ---------------------------------------------------------- capture tokens --

create table if not exists shield.capture_tokens (
    id          uuid primary key default gen_random_uuid(),
    tenant_id   uuid not null references shield.tenants(id) on delete cascade,
    record_id   uuid not null references shield.records(id) on delete cascade,
    nonce       text not null unique,
    issued_at   timestamptz not null default now(),
    expires_at  timestamptz not null,
    spent_at    timestamptz
);

create index if not exists shield_tokens_open_idx
    on shield.capture_tokens (record_id) where spent_at is null;

-- --------------------------------------------------------------------- RLS --
--
-- Deny by default, on every table. The service authenticates callers itself
-- and scopes every query by tenant_id in code (tenancy.scope); RLS is the
-- second line, so that a mistake in one layer is not the whole of the
-- defence. No permissive policy is created here on purpose: nothing reaches
-- these tables except the service role, which bypasses RLS.

alter table shield.tenants            enable row level security;
alter table shield.api_keys           enable row level security;
alter table shield.members            enable row level security;
alter table shield.records            enable row level security;
alter table shield.checkpoints        enable row level security;
alter table shield.photos             enable row level security;
alter table shield.custody_log        enable row level security;
alter table shield.notes              enable row level security;
alter table shield.completion_reports enable row level security;
alter table shield.capture_tokens     enable row level security;

alter table shield.tenants            force row level security;
alter table shield.api_keys           force row level security;
alter table shield.members            force row level security;
alter table shield.records            force row level security;
alter table shield.checkpoints        force row level security;
alter table shield.photos             force row level security;
alter table shield.custody_log        force row level security;
alter table shield.notes              force row level security;
alter table shield.completion_reports force row level security;
alter table shield.capture_tokens     force row level security;

-- The anon and authenticated roles have no business in this schema at all.
-- Access is through the API, which holds the service role.
revoke all on schema shield from anon, authenticated;
revoke all on all tables in schema shield from anon, authenticated;
