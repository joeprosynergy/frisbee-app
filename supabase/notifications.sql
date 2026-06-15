-- EasyGameRoster — web-push backend (applied to project yogymlpqgqjqragrxqgf).
-- Secret is redacted here as __FUNCTION_SECRET__; substitute the real FUNCTION_SECRET
-- (also set as an edge-function secret) before applying. Not committed in plaintext.

-- Subscriptions table (isolated; cannot affect games/signups)
create table if not exists public.push_subscriptions (
  id uuid primary key default gen_random_uuid(),
  endpoint text not null unique,
  p256dh text not null,
  auth text not null,
  user_agent text,
  created_at timestamptz default now(),
  last_seen timestamptz default now()
);
alter table public.push_subscriptions enable row level security;
drop policy if exists "anyone can subscribe" on public.push_subscriptions;
create policy "anyone can subscribe" on public.push_subscriptions for insert to public with check (true);
drop policy if exists "anyone can unsubscribe" on public.push_subscriptions;
create policy "anyone can unsubscribe" on public.push_subscriptions for delete to public using (true);

create extension if not exists pg_net;

-- Event 1: a game goes live → notify everyone
create or replace function public.notify_new_game() returns trigger
language plpgsql security definer as $fn$
begin
  if NEW.status = 'live' and (TG_OP = 'INSERT' or OLD.status is distinct from 'live') then
    perform net.http_post(
      url := 'https://yogymlpqgqjqragrxqgf.supabase.co/functions/v1/notify',
      headers := '{"Content-Type":"application/json"}'::jsonb,
      body := jsonb_build_object(
        'title', 'New game posted',
        'body', NEW.label || ' — ' || to_char(NEW.game_date,'Dy, Mon FMDD') || ' at ' || to_char(NEW.game_time,'FMHH12:MI AM'),
        'tag', 'new-game-' || NEW.id::text,
        'url', 'https://www.easygameroster.com',
        'secret', '__FUNCTION_SECRET__'
      )
    );
  end if;
  return NEW;
end;
$fn$;
drop trigger if exists trg_notify_new_game on public.games;
create trigger trg_notify_new_game after insert or update on public.games
for each row execute function public.notify_new_game();

-- Event 2: a signup is removed from a (previously full) live game → a spot opened
create or replace function public.notify_spot_opened() returns trigger
language plpgsql security definer as $fn$
declare g record; remaining int;
begin
  select * into g from public.games where id = OLD.game_id;
  if not found then return OLD; end if;          -- game was deleted (cascade) → skip
  if g.status <> 'live' then return OLD; end if;  -- only live games
  select count(*) into remaining from public.signups where game_id = OLD.game_id;
  if remaining >= g.max_players - 1 then          -- game was full/full+waitlist before this removal
    perform net.http_post(
      url := 'https://yogymlpqgqjqragrxqgf.supabase.co/functions/v1/notify',
      headers := '{"Content-Type":"application/json"}'::jsonb,
      body := jsonb_build_object(
        'title', 'A spot opened up',
        'body', 'A roster spot just opened in ' || g.label || ' — grab it!',
        'tag', 'spot-' || g.id::text,
        'url', 'https://www.easygameroster.com',
        'secret', '__FUNCTION_SECRET__'
      )
    );
  end if;
  return OLD;
end;
$fn$;
drop trigger if exists trg_notify_spot_opened on public.signups;
create trigger trg_notify_spot_opened after delete on public.signups
for each row execute function public.notify_spot_opened();
