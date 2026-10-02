-- Phase 2: Checkpoint Scaffolding
-- Ties photos to IRC/IBC code sections so evidence proves code compliance

begin;

-- Create shield_checkpoints table with trade-specific inspection requirements
create table if not exists public.shield_checkpoints (
  id uuid primary key default gen_random_uuid(),
  trade text not null check (trade in ('Framing', 'Roofing', 'Electrical', 'Plumbing', 'HVAC', 'Concrete', 'General')),
  name text not null,
  irc_section text,
  ibc_section text,
  description text,
  photo_guidance text,
  required_before_concealment boolean default false,
  created_at timestamptz not null default now(),
  unique (trade, name)
);

create index if not exists shield_checkpoints_trade_idx on public.shield_checkpoints (trade);

comment on table public.shield_checkpoints is
  'Building code inspection checkpoints tied to IRC/IBC sections. Contractors photograph these specific points to prove compliance.';

comment on column public.shield_checkpoints.photo_guidance is
  'Instructions for how to photograph this checkpoint (e.g., "wide shot + detail + scale").';

comment on column public.shield_checkpoints.required_before_concealment is
  'True if this inspection must occur before work is covered (e.g., foundation before framing).';

-- Seed checkpoint data for each trade
insert into public.shield_checkpoints (trade, name, irc_section, description, photo_guidance, required_before_concealment) values
  ('Framing', 'Foundation Sill Plate & Anchor Bolts', 'R403.1.6', 'Sill plate installed with ≥½" anchor bolts at 6" on center maximum', 'Wide shot of sill plate with anchor bolts visible', true),
  ('Framing', 'Header Beam Installation', 'R603.7.1', 'Proper header sizing and bearing on supports', 'Close-up of header bearing point and fasteners', true),
  ('Framing', 'Joist Notching', 'R502.8', 'Notches limited to 1/6 of joist depth, no cutting in middle 1/3 of span', 'Detail showing maximum notch depth measurement', true),
  ('Framing', 'Interior Wall Framing', 'R602.3', 'Studs properly spaced and aligned', 'Wide shot of wall framing showing spacing', true),
  ('Roofing', 'Roof Decking', 'R902.1', 'Decking fastened per manufacturer specifications and code requirements', 'Wide angle showing decking fastening pattern', true),
  ('Roofing', 'Underlayment Installation', 'R905.2.8', 'Underlayment properly lapped and fastened, minimum 4" overlap', 'Detail of lap and fastening', true),
  ('Roofing', 'Flashing Installation', 'R903.2', 'Flashing at valleys, ridges, and penetrations properly sealed', 'Detail of flashing and sealing', true),
  ('Electrical', 'Rough-in Inspection', 'E3401.1', 'Wiring secured at regular intervals, no damage to insulation', 'Wide shot of rough-in run', true),
  ('Electrical', 'Box Installation', 'E3404.2', 'Electrical boxes properly secured and positioned', 'Detail of box mounting and accessibility', true),
  ('Plumbing', 'Rough-in Inspection', 'P2603.2', 'Pipe support and slope requirements met', 'Detail of pipe support and slope', true),
  ('Plumbing', 'Vent Stack Installation', 'P3101.1', 'Vent stacks properly installed with correct pitch and clearance', 'Wide shot of vent stack installation', true),
  ('HVAC', 'Duct Sealing', 'M1601.4', 'Duct seams sealed with mastic, connections tight', 'Close-up of duct sealing', true),
  ('HVAC', 'Equipment Installation', 'M1401.2', 'HVAC equipment properly secured and accessible for maintenance', 'Wide shot of equipment installation', true),
  ('Concrete', 'Foundation Pour', 'R403.1', 'Concrete strength and finishes per specifications', 'Wide shot of foundation with reference scale', true),
  ('Concrete', 'Reinforcement Installation', 'R403.1.1', 'Rebar spacing and placement per specifications', 'Detail of rebar grid and spacing', true),
  ('General', 'Site Condition Documentation', 'General', 'General site condition and progress documentation', 'Wide angle showing overall condition', false)
on conflict (trade, name) do nothing;

-- Add checkpoint_id and checkpoint_name_snapshot columns to shield_photos
alter table if exists public.shield_photos
  add column if not exists checkpoint_id uuid references public.shield_checkpoints(id) on delete set null,
  add column if not exists checkpoint_name_snapshot text;

create index if not exists shield_photos_checkpoint_idx on public.shield_photos (checkpoint_id);

comment on column public.shield_photos.checkpoint_id is
  'Link to the specific IRC/IBC checkpoint this photo documents.';

comment on column public.shield_photos.checkpoint_name_snapshot is
  'Denormalized checkpoint name captured at photo time for audit trail (in case checkpoint definition changes).';

commit;
