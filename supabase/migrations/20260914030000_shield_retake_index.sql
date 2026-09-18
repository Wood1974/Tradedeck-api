-- =====================================================================
-- Shield: make retakes possible without letting one vanish
--
-- The hardening migration created
--
--     create unique index shield_photos_one_live_per_point
--       on public.shield_photos (point_id) where superseded_by is null;
--
-- which is the right guarantee reached through the wrong column. A retake has
-- to mark the previous photo superseded BEFORE its replacement is inserted,
-- or the insert collides with this index. But superseded_by is a foreign key
-- to the replacement, which does not have an id until it is inserted. The two
-- requirements cannot both be met, so the second photo on any checkpoint
-- failed with a unique violation and the API returned 500 "please retry" —
-- advice that could never work. Retakes were impossible.
--
-- Keying the index on superseded_at breaks the cycle. The write order is:
--
--   1. update prior  set superseded_at = now()     -- leaves the live set
--   2. insert replacement                          -- index now free
--   3. update prior  set superseded_by = <new id>  -- pointer backfilled
--
-- If step 2 fails, step 1 is reverted. If step 3 fails, the row is still
-- correctly excluded from the live set and only the pointer is missing, so
-- selection stays right either way.
--
-- Neither column is ever cleared to hide an attempt: superseding is how a
-- retake is recorded, and every attempt stays in the export.
-- =====================================================================

drop index if exists public.shield_photos_one_live_per_point;

create unique index if not exists shield_photos_one_live_per_point
  on public.shield_photos (point_id)
  where superseded_at is null;

comment on column public.shield_photos.superseded_at is
  'Set the moment a replacement for this checkpoint is accepted. This column, '
  'not superseded_by, is what removes a photo from the live set — see '
  'shield_photos_one_live_per_point.';

-- A pointer without a timestamp would sit in the live set while claiming to
-- have been replaced.
alter table public.shield_photos
  drop constraint if exists shield_photos_supersede_consistent;
alter table public.shield_photos
  add constraint shield_photos_supersede_consistent
  check (superseded_by is null or superseded_at is not null);


-- ---------------------------------------------------------------------
-- Verify (run these after applying)
-- ---------------------------------------------------------------------
-- Expect one row, indexdef ending "WHERE (superseded_at IS NULL)":
--   select indexdef from pg_indexes
--    where indexname = 'shield_photos_one_live_per_point';
--
-- Expect zero rows — every checkpoint has at most one live photo:
--   select point_id, count(*) from public.shield_photos
--    where superseded_at is null group by point_id having count(*) > 1;
--
-- Expect zero rows — no pointer without a timestamp:
--   select id from public.shield_photos
--    where superseded_by is not null and superseded_at is null;
