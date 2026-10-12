-- Shield: three opt-in extras, all off until a tenant turns one on.
--
-- A GNSS fix hashed into the capture record, a one-second clip stored
-- beside the photograph under its own path, and a second phone's
-- signature over the same record hash. None of them is required for a
-- seal. A tenant that never sets these columns behaves as before.
--
-- The countersign table is append-only and tenant-scoped. A row is
-- written only after the second key verifies, and only when that key is
-- a different attested key of the same tenant. The service role is the
-- only writer.

begin;

alter table shield.tenants
    add column if not exists opt_in_gnss_fix boolean not null default false,
    add column if not exists opt_in_micro_clip boolean not null default false,
    add column if not exists opt_in_countersign boolean not null default false;

comment on column shield.tenants.opt_in_gnss_fix is
  'When true, phones may hash a short GNSS fix into the capture record. Default false. Not required for SEALED.';
comment on column shield.tenants.opt_in_micro_clip is
  'When true, phones may attach a one-second clip stored under a clip path. Default false. Not required for SEALED.';
comment on column shield.tenants.opt_in_countersign is
  'When true, a second attested key of this tenant may countersign a record hash. Default false. Not required for SEALED.';

create table if not exists shield.capture_countersigns (
    id                  uuid primary key default gen_random_uuid(),
    tenant_id           uuid not null references shield.tenants(id) on delete restrict,
    record_id           uuid not null references shield.records(id) on delete restrict,
    record_hash         text not null check (record_hash ~ '^[a-f0-9]{64}$'),
    capture_key_id      text not null,
    countersign_key_id  text not null,
    platform            text not null check (platform in ('ios', 'android')),
    hardware_signature  text not null,
    created_at          timestamptz not null default now(),
    unique (tenant_id, record_hash),
    check (capture_key_id <> countersign_key_id)
);

create index if not exists shield_capture_countersigns_tenant_idx
    on shield.capture_countersigns (tenant_id, record_id);

comment on table shield.capture_countersigns is
  'A second phone''s signature over a capture record hash. Written only '
  'when the tenant has opted in, and only for a different attested key '
  'of that same tenant. Not a seal requirement.';

create or replace function shield.capture_countersigns_are_append_only()
returns trigger language plpgsql as $$
begin
    raise exception 'shield.capture_countersigns is append-only: % is not permitted',
        tg_op;
end $$;

drop trigger if exists shield_capture_countersigns_no_mutate on shield.capture_countersigns;
create trigger shield_capture_countersigns_no_mutate
    before update or delete on shield.capture_countersigns
    for each row execute function shield.capture_countersigns_are_append_only();

drop trigger if exists shield_capture_countersigns_no_truncate on shield.capture_countersigns;
create trigger shield_capture_countersigns_no_truncate
    before truncate on shield.capture_countersigns
    for each statement execute function shield.capture_countersigns_are_append_only();

alter table shield.capture_countersigns enable row level security;
alter table shield.capture_countersigns force row level security;
revoke all on shield.capture_countersigns from anon, authenticated;

commit;
