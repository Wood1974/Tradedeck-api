-- Required for secure webhook idempotency.
create table if not exists public.stripe_webhook_events (
  event_id text primary key,
  event_type text not null,
  processed_at timestamptz not null default now()
);

create index if not exists stripe_webhook_events_processed_at_idx
  on public.stripe_webhook_events (processed_at desc);

-- Storage bucket for milestone photos (private; serve via signed URLs from frontend).
insert into storage.buckets (id, name, public)
values ('draw-photos', 'draw-photos', false)
on conflict (id) do nothing;
