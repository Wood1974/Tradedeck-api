-- ID check + signed photographer note for the Shield phone app (NOT APPLIED; for owner review).
--
-- Stores no ID or selfie images and no name or document data: Stripe Identity holds those. We keep
-- the Stripe session id and its status, the consent record, and the device-signed note.
-- Writes happen only from tradedeck-api with the service role; signed-in users may read their own rows.

create table if not exists public.shield_identity_sessions (
    id                uuid primary key default gen_random_uuid(),
    user_id           uuid not null references auth.users(id) on delete cascade,
    stripe_session_id text not null unique,
    status            text not null check (status in ('requires_input', 'processing', 'verified', 'canceled')),
    consent_at        timestamptz not null,
    consent_version   text not null,
    verified_at       timestamptz,
    created_at        timestamptz not null default now(),
    updated_at        timestamptz not null default now()
);
create index if not exists shield_identity_sessions_user_idx
    on public.shield_identity_sessions (user_id, created_at desc);

create table if not exists public.shield_note_attestations (
    id                uuid primary key default gen_random_uuid(),
    user_id           uuid not null references auth.users(id) on delete cascade,
    session_id        uuid not null references public.shield_identity_sessions(id),
    device_seal_id    text not null,
    device_public_key text not null,
    statement_version text not null,
    note_payload      jsonb not null,
    note_sha256       text not null unique check (note_sha256 ~ '^[a-f0-9]{64}$'),
    signature         text not null,
    signed_at         timestamptz not null,
    -- Service-signed receipt (ECDSA P-256) that Stripe reported the ID check verified for this note.
    receipt           jsonb not null,
    created_at        timestamptz not null default now(),
    revoked_at        timestamptz
);
create index if not exists shield_note_attestations_user_idx
    on public.shield_note_attestations (user_id);

alter table public.shield_identity_sessions enable row level security;
alter table public.shield_note_attestations enable row level security;

drop policy if exists shield_identity_sessions_select_own on public.shield_identity_sessions;
create policy shield_identity_sessions_select_own on public.shield_identity_sessions
    for select to authenticated using (user_id = auth.uid());

drop policy if exists shield_note_attestations_select_own on public.shield_note_attestations;
create policy shield_note_attestations_select_own on public.shield_note_attestations
    for select to authenticated using (user_id = auth.uid());

-- No insert/update/delete policies on purpose: only the service role (the API) writes these tables.
