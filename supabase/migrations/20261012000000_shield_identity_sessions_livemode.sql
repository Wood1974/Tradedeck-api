-- Owner-only Stripe test mode for the ID check (see identity_api.py).
-- A session started in test mode is stored with livemode = false so /status and /note ask Stripe with the matching
-- key, and its receipt is marked as a test. Every existing and every live row keeps the default (true).
alter table public.shield_identity_sessions
    add column if not exists livemode boolean not null default true;

comment on column public.shield_identity_sessions.livemode is
    'false only for an owner-allowlisted account that ran the check in Stripe test mode (no real ID).';
