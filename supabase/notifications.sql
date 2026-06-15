-- EasyGameRoster — push notification backend (project yogymlpqgqjqragrxqgf).
-- Secret redacted as __FUNCTION_SECRET__; substitute the real FUNCTION_SECRET (also an
-- edge-function secret) before applying. The function lives in functions/notify/index.ts.

-- ---- Schema ----
create table if not exists public.push_subscriptions (
  id uuid primary key default gen_random_uuid(),
  endpoint text not null unique,
  p256dh text not null,
  auth text not null,
  user_agent text,
  device_id text,                 -- links a device to the names it signs up (for targeting)
  created_at timestamptz default now(),
  last_seen timestamptz default now()
);
alter table public.push_subscriptions enable row level security;
drop policy if exists "anyone can subscribe" on public.push_subscriptions;
create policy "anyone can subscribe" on public.push_subscriptions for insert to public with check (true);
drop policy if exists "anyone can unsubscribe" on public.push_subscriptions;
create policy "anyone can unsubscribe" on public.push_subscriptions for delete to public using (true);
drop policy if exists "anyone can update sub" on public.push_subscriptions;
create policy "anyone can update sub" on public.push_subscriptions for update to public using (true) with check (true);

alter table public.signups add column if not exists device_id text;

-- milestone de-dup (one notification per game per kind)
create table if not exists public.game_notifications (
  game_id uuid not null references public.games(id) on delete cascade,
  kind text not null,
  created_at timestamptz default now(),
  primary key (game_id, kind)
);
alter table public.game_notifications enable row level security;

create extension if not exists pg_net;

-- ---- Triggers: all send {type, game_id, ...} to the notify function ----
create or replace function public.notify_new_game() returns trigger
language plpgsql security definer as $fn$
begin
  if NEW.status = 'live' and (TG_OP = 'INSERT' or OLD.status is distinct from 'live') then
    perform net.http_post(
      url := 'https://yogymlpqgqjqragrxqgf.supabase.co/functions/v1/notify',
      headers := '{"Content-Type":"application/json"}'::jsonb,
      body := jsonb_build_object('type','new_game','game_id',NEW.id,'secret','__FUNCTION_SECRET__'));
  end if;
  return NEW;
end; $fn$;
drop trigger if exists trg_notify_new_game on public.games;
create trigger trg_notify_new_game after insert or update on public.games
for each row execute function public.notify_new_game();

create or replace function public.notify_signup() returns trigger
language plpgsql security definer as $fn$
begin
  perform net.http_post(
    url := 'https://yogymlpqgqjqragrxqgf.supabase.co/functions/v1/notify',
    headers := '{"Content-Type":"application/json"}'::jsonb,
    body := jsonb_build_object('type','signup','game_id',NEW.game_id,'secret','__FUNCTION_SECRET__'));
  return NEW;
end; $fn$;
drop trigger if exists trg_notify_signup on public.signups;
create trigger trg_notify_signup after insert on public.signups
for each row execute function public.notify_signup();

create or replace function public.notify_removal() returns trigger
language plpgsql security definer as $fn$
begin
  if exists (select 1 from public.games where id = OLD.game_id) then  -- skip cascade on game delete
    perform net.http_post(
      url := 'https://yogymlpqgqjqragrxqgf.supabase.co/functions/v1/notify',
      headers := '{"Content-Type":"application/json"}'::jsonb,
      body := jsonb_build_object('type','removal','game_id',OLD.game_id,'removed_at',OLD.created_at,'secret','__FUNCTION_SECRET__'));
  end if;
  return OLD;
end; $fn$;
drop trigger if exists trg_notify_removal on public.signups;
create trigger trg_notify_removal after delete on public.signups
for each row execute function public.notify_removal();
