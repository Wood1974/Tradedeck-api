-- Shield: one job ticket per record, the genesis of the on-phone chain.
--
-- The phone countersigns this ticket while it still has a signal. The row
-- is written only after that hardware signature verifies. The bytes that
-- were signed live in ticket_json; ticket_hash is SHA-256 of their
-- canonical form and is what the first capture record names.
--
-- WHY A TABLE
--
-- Render runs more than one gunicorn worker. The capture-challenge jar in
-- the process is not shared between them, so a ticket kept there would
-- exist for whichever worker happened to issue it and be invisible to the
-- other. This table is the shared store. The service-role key is the only
-- writer (shield/db.py); the browser roles are revoked below.
--
-- PLAY INTEGRITY
--
-- One verdict per job, on this row, not per photograph. Android only.
-- iOS has no Play Integrity API. App Attest does not report jailbreak, and
-- the reason column says so rather than leaving a blank a reader could
-- fill in as a pass. 'absent' means nothing was presented. It is not
-- 'fail'.

begin;

create table if not exists shield.job_tickets (
    id                      uuid primary key default gen_random_uuid(),
    tenant_id               uuid not null references shield.tenants(id) on delete restrict,
    record_id               uuid not null references shield.records(id) on delete restrict,
    actor_id                text not null,
    platform                text not null check (platform in ('ios', 'android')),
    key_id                  text not null,
    ticket_hash             text not null unique check (ticket_hash ~ '^[a-f0-9]{64}$'),
    checkpoint_list_sha256  text not null check (checkpoint_list_sha256 ~ '^[a-f0-9]{64}$'),
    server_time_ms          bigint not null check (server_time_ms >= 0),
    expires_at_ms           bigint not null check (expires_at_ms > server_time_ms),
    -- Null when Roughtime is off or the outside clock did not answer.
    -- Genesis still completes; absence is the recorded fact.
    roughtime_ms            bigint check (roughtime_ms is null or roughtime_ms >= 0),
    ticket_json             jsonb not null,
    server_signature        text not null,
    hardware_signature      text not null,
    play_integrity_status   text not null
                            check (play_integrity_status in
                                   ('absent', 'pass', 'fail', 'unverifiable')),
    play_integrity_tier     text,
    play_integrity_reason   text,
    play_integrity_labels   jsonb,
    created_at              timestamptz not null default now(),
    unique (record_id)
);

create index if not exists shield_job_tickets_tenant_idx
    on shield.job_tickets (tenant_id, record_id);

comment on table shield.job_tickets is
  'One server-signed, phone-countersigned job ticket per record. Written '
  'only by the service role after the hardware signature verifies. Shared '
  'across gunicorn workers; not the in-process challenge jar.';

comment on column shield.job_tickets.ticket_hash is
  'SHA-256 of the canonical ticket JSON. The capture record stores this '
  'as ticket_id, and the first on-phone record uses it as prev_hash.';

comment on column shield.job_tickets.play_integrity_status is
  'One Play Integrity reading for the job. absent on every iOS row, and '
  'on an Android row that presented no token. absent is not a pass and '
  'not a fail. App Attest does not report jailbreak.';

-- Append-only. A signature that can be updated is not the signature that
-- was checked.
create or replace function shield.job_tickets_are_append_only()
returns trigger language plpgsql as $$
begin
    raise exception 'shield.job_tickets is append-only: % is not permitted',
        tg_op;
end $$;

drop trigger if exists shield_job_tickets_no_mutate on shield.job_tickets;
create trigger shield_job_tickets_no_mutate
    before update or delete on shield.job_tickets
    for each row execute function shield.job_tickets_are_append_only();

drop trigger if exists shield_job_tickets_no_truncate on shield.job_tickets;
create trigger shield_job_tickets_no_truncate
    before truncate on shield.job_tickets
    for each statement execute function shield.job_tickets_are_append_only();

-- Deny by default, like every other table in this schema. Only the service
-- role, which bypasses RLS, reaches it.
alter table shield.job_tickets enable row level security;
alter table shield.job_tickets force row level security;
revoke all on shield.job_tickets from anon, authenticated;

commit;
