-- Shield: single-use nonces for photo capture
--
-- Each attestation flow begins with a fresh, single-use challenge:
-- POST /shield/v2/records/<id>/capture-challenge → token
-- This table tracks that token, preventing replays on the same record
-- and providing audit trail for which challenges have been spent.
--
-- iOS: the token is bound to the attestation challenge and later assertion.
-- Android: the token is bound to the signature over clientData.
-- Both: a token may only be used once per record; reuse is rejected.

create table if not exists shield.capture_tokens (
    token         text primary key,             -- base64 challenge nonce
    tenant_id     uuid not null references shield.tenants(id) on delete cascade,
    record_id     text not null,
    used_at       timestamptz,                  -- when the token was used
    expires_at    timestamptz not null,         -- after which it is stale
    created_at    timestamptz not null default now()
);

create index if not exists shield_capture_tokens_record_idx
    on shield.capture_tokens (tenant_id, record_id) where used_at is null;

comment on table shield.capture_tokens is
  'Single-use nonces for Shield photo attestation. Prevents replay of '
  'the same challenge on the same record. Tokens expire after ~5 minutes '
  'and are marked used on first successful capture.';

-- Deny by default, like every other table in this schema. Only the service
-- role, which bypasses RLS, reaches it.
alter table shield.capture_tokens enable row level security;
alter table shield.capture_tokens force row level security;
revoke all on shield.capture_tokens from anon, authenticated;
