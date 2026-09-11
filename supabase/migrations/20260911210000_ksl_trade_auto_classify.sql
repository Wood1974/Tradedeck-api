-- Classifies a KSL job listing into a TradeDeck trade category by keyword
-- match on title/description. Returns NULL when nothing matches (most KSL
-- rows are not construction jobs at all -- see CLAUDE.md).
create or replace function public.classify_ksl_trade(p_title text, p_description text)
returns text
language sql
immutable
set search_path = public, pg_temp
as $$
  select case
    when p_title ilike '%electric%' or p_description ilike '%electrician%' then 'Electrical'
    when p_title ilike '%plumb%' or p_description ilike '%plumbing%' then 'Plumbing'
    when p_title ilike '%hvac%' or p_title ilike '%refrigeration%' or p_description ilike '%hvac%' then 'HVAC'
    when p_title ilike '%concrete%' or p_title ilike '%mason%' or p_description ilike '%concrete%' then 'Concrete'
    when p_title ilike '%framer%' or p_title ilike '%framing%' or p_description ilike '%framing%' then 'Framing'
    when p_title ilike '%roof%' or p_description ilike '%roofing%' then 'Roofing'
    when p_title ilike '%drywall%' or p_title ilike '%sheetrock%' or p_description ilike '%drywall%' then 'Drywall'
    when p_title ilike '%excavat%' or p_description ilike '%excavat%' then 'Excavation'
    when p_title ilike '%landscap%' or p_description ilike '%landscap%' then 'Landscaping'
    when p_title ilike '%flooring%' or p_description ilike '%flooring install%' then 'Flooring'
    when p_title ilike '%construction laborer%' or p_title ilike '%construction helper%'
      or p_title ilike '%general labor%' or p_description ilike '%construction site%' then 'General Labor'
    else null
  end;
$$;

-- Backfill existing untagged KSL rows where a real match exists (verified:
-- 34 of 1,509 untagged rows -- the rest are not construction jobs at all).
update public.jobs
set trade = classify_ksl_trade(title, description)
where source = 'ksl' and trade is null
  and classify_ksl_trade(title, description) is not null;

-- Auto-classify future inserts/updates from the KSL scraper (or any process)
-- so this stays current without needing to re-run a backfill by hand.
create or replace function public.auto_classify_ksl_trade()
returns trigger
language plpgsql
set search_path = public, pg_temp
as $$
begin
  if new.source = 'ksl' and new.trade is null then
    new.trade := public.classify_ksl_trade(new.title, new.description);
  end if;
  return new;
end;
$$;

drop trigger if exists trg_auto_classify_ksl_trade on public.jobs;
create trigger trg_auto_classify_ksl_trade
  before insert or update on public.jobs
  for each row execute function public.auto_classify_ksl_trade();
