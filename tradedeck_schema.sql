-- TradeDeck Supabase schema for tradedeck-api v2.1
-- Run in Supabase SQL Editor. Requires auth.users (created by Supabase Auth).

-- Profiles (extends auth.users)
create table if not exists public.profiles (
    id uuid primary key references auth.users(id) on delete cascade,
    email text,
    full_name text,
    role text default 'sub',
    trade text,
    stripe_account_id text,
    created_at timestamptz default now()
);

-- Jobs
create table if not exists public.jobs (
    id uuid primary key default gen_random_uuid(),
    owner_id uuid not null references public.profiles(id),
    title text not null,
    trade text not null,
    location text not null,
    description text default '',
    budget numeric,
    status text default 'open',
    created_at timestamptz default now()
);

create index if not exists jobs_status_idx on public.jobs(status);
create index if not exists jobs_trade_idx on public.jobs(trade);

-- Job applications
create table if not exists public.applications (
    id uuid primary key default gen_random_uuid(),
    job_id uuid not null references public.jobs(id) on delete cascade,
    user_id uuid references public.profiles(id),
    name text default '',
    email text default '',
    message text default '',
    created_at timestamptz default now()
);

create index if not exists applications_job_id_idx on public.applications(job_id);

-- Milestone draws
create table if not exists public.draws (
    id uuid primary key default gen_random_uuid(),
    job_id uuid not null references public.jobs(id) on delete cascade,
    title text,
    amount_cents integer not null,
    status text default 'pending',
    submitted_at timestamptz,
    approved_at timestamptz,
    released_at timestamptz,
    created_at timestamptz default now()
);

-- Stripe escrow records (one per draw)
create table if not exists public.stripe_escrow (
    id uuid primary key default gen_random_uuid(),
    job_id uuid not null references public.jobs(id),
    draw_id uuid not null unique references public.draws(id),
    payer_id uuid not null references public.profiles(id),
    payee_id uuid references public.profiles(id),
    stripe_payment_intent_id text not null,
    stripe_transfer_id text,
    amount_cents integer not null,
    status text default 'pending',
    held_at timestamptz,
    released_at timestamptz,
    created_at timestamptz default now()
);

-- Draw photos with AI analysis
create table if not exists public.draw_photos (
    id uuid primary key default gen_random_uuid(),
    draw_id uuid not null references public.draws(id) on delete cascade,
    uploaded_by uuid references public.profiles(id),
    storage_path text not null,
    ai_analysis jsonb,
    ai_passed boolean default false,
    ai_score integer,
    ai_summary text default '',
    ai_flags jsonb default '[]',
    created_at timestamptz default now()
);

-- Storage bucket for milestone photos (create in Supabase Dashboard > Storage)
-- Bucket name: draw-photos (public or signed URLs as needed)

-- Auto-create profile on signup
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
begin
    insert into public.profiles (id, email)
    values (new.id, new.email)
    on conflict (id) do nothing;
    return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
    after insert on auth.users
    for each row execute function public.handle_new_user();
