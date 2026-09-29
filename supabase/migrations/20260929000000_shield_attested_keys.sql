-- Shield: attested device keys, so a device attests once and signs after that.
--
-- Two platforms share this table. iOS: an App Attest key, attested to Apple's
-- root, each later capture an App Attest assertion with a counter. Android: a
-- Key Attestation key, attested to Google's root, each later capture a plain
-- ECDSA signature over the same client data (Android keys have no counter;
-- the single-use challenge the signature covers is what stops a replay).
--
-- WHY
--
-- `attestKey` may be called once per key and makes a round trip to Apple,
-- which rate-limits it. Until now the iOS client made a fresh key for every
-- photograph, which works and runs into that limit for a crew shooting fifty
-- frames in an afternoon. Apple's intended shape: attest a key once, keep its
-- public key, and verify each later capture's `generateAssertion` signature
-- against it with a counter that must go up.
--
-- This table is that "keep". A row exists only for a key whose attestation
-- verified to the configured Apple root (`app_attest.verify` is the only
-- thing that returns a public key), so nothing a client sends can create one.
--
-- WHAT A ROW IS BOUND TO
--
-- The tenant and the actor that attested it. An assertion from a key is
-- accepted only from the same actor -- otherwise one crew member's device
-- could sign captures uploaded under somebody else's credential. A new sign-in
-- on the same phone attests a new key rather than inheriting the old one.
--
-- THE COUNTER
--
-- `sign_count` is advanced with a compare-and-set (`update ... where
-- sign_count < new`), so two uploads racing on one assertion cannot both be
-- recorded. It starts at 0: Apple's first assertion from a key carries 1.

create table if not exists shield.attested_keys (
    key_id        text primary key,          -- base64 SHA256 of the public key
    tenant_id     uuid not null references shield.tenants(id) on delete cascade,
    actor_id      text not null,
    platform      text not null check (platform in ('ios', 'android')),
    -- Android only: 'TrustedEnvironment' or 'StrongBox', as attested.
    security_level text check (security_level in ('TrustedEnvironment', 'StrongBox')),
    public_key    text not null,             -- base64 uncompressed P-256 point
    environment   text not null check (environment in ('production', 'development')),
    sign_count    bigint not null default 0 check (sign_count >= 0),  -- iOS only
    receipt       text,                      -- base64; for Apple's fraud metric later
    attested_at   timestamptz not null default now(),
    last_used_at  timestamptz,
    revoked_at    timestamptz
);

create index if not exists shield_attested_keys_actor_idx
    on shield.attested_keys (tenant_id, actor_id) where revoked_at is null;

comment on table shield.attested_keys is
  'Device keys this service verified to the Apple (ios) or Google (android) '
  'attestation root. Written only after a verified attestation; each later '
  'capture from the key is checked against it. iOS advances sign_count by '
  'compare-and-set; Android has no counter and relies on the spent challenge.';

-- Deny by default, like every other table in this schema. Only the service
-- role, which bypasses RLS, reaches it.
alter table shield.attested_keys enable row level security;
alter table shield.attested_keys force row level security;
revoke all on shield.attested_keys from anon, authenticated;
