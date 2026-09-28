-- Shield standalone runtime columns.
--
-- The 20260920 schema gave Shield its own identity and tables. This migration
-- adds the few columns the hardened service needs to run against that schema
-- without borrowing anything from public.shield_* (TradeDeck's copy).
--
-- TradeDeck's public.shield_* tables are untouched. Separation by addition.

-- Pending exists so a record can wait on payment before photos are accepted.
alter table shield.records drop constraint if exists records_status_check;
alter table shield.records add constraint records_status_check
    check (status in ('pending', 'active', 'complete', 'cancelled'));

alter table shield.records
    add column if not exists site_radius_m integer
        check (site_radius_m is null or site_radius_m > 0),
    add column if not exists amount_cents integer
        check (amount_cents is null or amount_cents >= 0),
    add column if not exists job_budget_cents integer
        check (job_budget_cents is null or job_budget_cents >= 0),
    add column if not exists stripe_payment_intent_id text,
    add column if not exists stripe_payment_id text,
    add column if not exists activated_at timestamptz;

create index if not exists shield_records_payment_intent_idx
    on shield.records (stripe_payment_intent_id)
    where stripe_payment_intent_id is not null;

-- Compressed copy path — the only bytes the model ever sees. Original stays
-- on storage_path, unmodified.
alter table shield.photos
    add column if not exists compressed_path text,
    add column if not exists original_hash_algo text not null default 'SHA-256',
    add column if not exists gps_accuracy_m double precision,
    add column if not exists exif_gps_lat double precision,
    add column if not exists exif_gps_lng double precision,
    add column if not exists exif_device_make text,
    add column if not exists exif_device_model text,
    add column if not exists exif_software text,
    add column if not exists exif_raw jsonb,
    add column if not exists ai_model text,
    add column if not exists code_reference text,
    add column if not exists upload_user_agent text;

-- Tenant-scoped Stripe event claim table (webhook idempotency). Was
-- public.stripe_webhook_events in TradeDeck; Shield must not share it.
create table if not exists shield.stripe_events (
    event_id      text primary key,
    event_type    text not null,
    processed_at  timestamptz not null default now(),
    tenant_id     uuid references shield.tenants(id) on delete set null
);

alter table shield.stripe_events enable row level security;
alter table shield.stripe_events force row level security;
revoke all on table shield.stripe_events from anon, authenticated;

-- Optional contractor-style subscriptions, scoped to a tenant rather than a
-- TradeDeck profile.
create table if not exists shield.subscriptions (
    id                   uuid primary key default gen_random_uuid(),
    tenant_id            uuid not null references shield.tenants(id) on delete cascade,
    subject_ref          text not null,
    stripe_customer_id   text,
    stripe_sub_id        text unique,
    status               text not null default 'active'
                         check (status in ('active', 'cancelled', 'past_due', 'paused')),
    current_period_end   bigint,
    created_at           timestamptz not null default now(),
    unique (tenant_id, subject_ref)
);

alter table shield.subscriptions enable row level security;
alter table shield.subscriptions force row level security;
revoke all on table shield.subscriptions from anon, authenticated;
