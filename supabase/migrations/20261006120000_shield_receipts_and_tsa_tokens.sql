-- Shield: a receipt for each accepted offline batch, and the timestamp
-- outcome that goes with it.
--
-- The receipt is signed by the same service key that signs job tickets.
-- head_hash is the custody-chain head after the batch entry was appended.
-- That entry's event_data carries the phone-chain head, so the custody
-- chain is still the chain. chain_version stays 2. This migration does
-- not re-chain anything.
--
-- tsa_tokens.status is 'present' or 'missing'. Missing means DigiCert and
-- Sectigo did not return a token this service could check. Missing is not
-- a forgery, and there is no status that says it is. The receipt row is
-- written either way.

begin;

-- One more custody event: the batch itself. The phone chain is nested in
-- event_data. It does not get its own table of links, and it does not
-- replace the rows already in this log.
do $$
declare
    r record;
begin
    for r in
        select con.conname
        from pg_constraint con
        join pg_class rel on rel.oid = con.conrelid
        join pg_namespace nsp on nsp.oid = rel.relnamespace
        where nsp.nspname = 'shield'
          and rel.relname = 'custody_log'
          and con.contype = 'c'
          and pg_get_constraintdef(con.oid) ilike '%event_type%'
    loop
        execute format(
            'alter table shield.custody_log drop constraint %I', r.conname);
    end loop;
end $$;

alter table shield.custody_log
    add constraint custody_log_event_type_check
    check (event_type in (
        'created', 'checkpoints_locked', 'uploaded',
        'analyzed', 'superseded', 'integrity_flag',
        'note_written', 'note_amended', 'viewed',
        'exported', 'completed', 'offline_batch'));

create table if not exists shield.receipts (
    id                 uuid primary key default gen_random_uuid(),
    tenant_id          uuid not null references shield.tenants(id) on delete restrict,
    record_id          uuid not null references shield.records(id) on delete restrict,
    ticket_hash        text not null check (ticket_hash ~ '^[a-f0-9]{64}$'),
    -- Custody head after this batch's entry. The receipt signature covers it.
    head_hash          text not null check (head_hash ~ '^[a-f0-9]{64}$'),
    -- Phone-chain head nested inside that custody entry. The next batch
    -- has to start here. Truncating back to an earlier head does not link.
    phone_chain_head   text not null check (phone_chain_head ~ '^[a-f0-9]{64}$'),
    accepted_at_ms     bigint not null check (accepted_at_ms >= 0),
    batch_index        integer not null check (batch_index >= 1),
    batch_size         integer not null check (batch_size >= 1),
    receipt_json       jsonb not null,
    server_signature   text not null,
    created_at         timestamptz not null default now(),
    unique (record_id, batch_index),
    unique (head_hash)
);

create index if not exists shield_receipts_tenant_idx
    on shield.receipts (tenant_id, record_id, batch_index);

comment on table shield.receipts is
  'One signed receipt per accepted offline batch. Written only by the '
  'service role, after every hardware signature in the batch verified. '
  'The signed fields are the record id, the custody head, and the time '
  'the batch was accepted.';

comment on column shield.receipts.head_hash is
  'Custody-chain head after the batch entry. chain_version is still 2. '
  'The phone chain is inside that entry, not a replacement for the chain.';

comment on column shield.receipts.phone_chain_head is
  'Head of the on-phone capture records this batch accepted. The next '
  'batch''s first record has to name it as prev_hash.';

create table if not exists shield.tsa_tokens (
    id            uuid primary key default gen_random_uuid(),
    tenant_id     uuid not null references shield.tenants(id) on delete restrict,
    receipt_id    uuid not null references shield.receipts(id) on delete restrict,
    record_id     uuid not null references shield.records(id) on delete restrict,
    head_hash     text not null check (head_hash ~ '^[a-f0-9]{64}$'),
    -- present: a token verified over head_hash. missing: no such token.
    -- There is no 'forged' status. A missing timestamp is not a forgery.
    status        text not null check (status in ('present', 'missing')),
    -- digicert or sectigo when the token came from those hosts. A
    -- deployment that points the URL at another host stores that host.
    -- Null when status is missing.
    authority     text check (authority is null or char_length(authority) between 1 and 64),
    token_b64     text,
    gen_time      text,
    created_at    timestamptz not null default now(),
    unique (receipt_id),
    check (
        (status = 'present' and token_b64 is not null)
        or (status = 'missing' and token_b64 is null)
    )
);

create index if not exists shield_tsa_tokens_tenant_idx
    on shield.tsa_tokens (tenant_id, receipt_id);

comment on table shield.tsa_tokens is
  'The RFC 3161 outcome for one receipt. missing means the timestamp '
  'authority did not produce a token this service could check. missing '
  'is not forged. The receipt row exists either way.';

comment on column shield.tsa_tokens.status is
  'present or missing. A missing timestamp is not a forgery finding.';

-- Append-only. A receipt that can be edited is not the receipt that was
-- signed, and a missing timestamp that can be flipped to present without
-- a token is the same problem.
create or replace function shield.receipts_are_append_only()
returns trigger language plpgsql as $$
begin
    raise exception 'shield.receipts is append-only: % is not permitted',
        tg_op;
end $$;

drop trigger if exists shield_receipts_no_mutate on shield.receipts;
create trigger shield_receipts_no_mutate
    before update or delete on shield.receipts
    for each row execute function shield.receipts_are_append_only();

drop trigger if exists shield_receipts_no_truncate on shield.receipts;
create trigger shield_receipts_no_truncate
    before truncate on shield.receipts
    for each statement execute function shield.receipts_are_append_only();

create or replace function shield.tsa_tokens_are_append_only()
returns trigger language plpgsql as $$
begin
    raise exception 'shield.tsa_tokens is append-only: % is not permitted',
        tg_op;
end $$;

drop trigger if exists shield_tsa_tokens_no_mutate on shield.tsa_tokens;
create trigger shield_tsa_tokens_no_mutate
    before update or delete on shield.tsa_tokens
    for each row execute function shield.tsa_tokens_are_append_only();

drop trigger if exists shield_tsa_tokens_no_truncate on shield.tsa_tokens;
create trigger shield_tsa_tokens_no_truncate
    before truncate on shield.tsa_tokens
    for each statement execute function shield.tsa_tokens_are_append_only();

alter table shield.receipts enable row level security;
alter table shield.receipts force row level security;
revoke all on shield.receipts from anon, authenticated;

alter table shield.tsa_tokens enable row level security;
alter table shield.tsa_tokens force row level security;
revoke all on shield.tsa_tokens from anon, authenticated;

commit;
