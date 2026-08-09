-- Easy Game Roster hardening 2026-08-09
-- 1) Stronger invite codes (generator only; rotate after client ships)
-- 2) Invite always required; admin pass only elevates
-- 3) In-DB rate limiting (per-IP fixed window)
-- 4) change_admin_passphrase
-- 5) Delete weak duplicate Joe admin on frisbee

-- ========== Rate limit helpers ==========
create table if not exists public.rl_attempts (
  bucket text not null,
  window_start timestamptz not null,
  fails int not null default 0,
  primary key (bucket, window_start)
);
create table if not exists public.rl_events (
  id bigserial primary key,
  at timestamptz not null default now(),
  bucket text not null,
  detail jsonb
);
revoke all on public.rl_attempts from anon, authenticated, public;
revoke all on public.rl_events from anon, authenticated, public;
grant all on public.rl_attempts to service_role;
grant all on public.rl_events to service_role;
grant usage, select on sequence public.rl_events_id_seq to service_role;

create or replace function public._rl_ip()
returns text
language plpgsql
stable
security definer
set search_path to 'public'
as $$
declare
  h jsonb;
  ip text;
  xff text;
begin
  begin
    h := current_setting('request.headers', true)::jsonb;
  exception when others then
    h := '{}'::jsonb;
  end;
  ip := nullif(btrim(coalesce(h->>'cf-connecting-ip','')), '');
  if ip is null then
    xff := nullif(btrim(coalesce(h->>'x-forwarded-for','')), '');
    if xff is not null then
      -- last hop (rightmost) is typically the trusted edge
      ip := nullif(btrim(split_part(reverse(xff), ',', 1)), '');
      -- split_part(reverse...) is wrong for multi - take first of xff instead (client-facing)
      ip := nullif(btrim(split_part(xff, ',', 1)), '');
    end if;
  end if;
  return coalesce(ip, 'unknown');
end;
$$;

create or replace function public._rl_window_start(p_window interval)
returns timestamptz
language sql
stable
as $$
  select to_timestamp(floor(extract(epoch from now()) / extract(epoch from p_window)) * extract(epoch from p_window));
$$;

create or replace function public._rl_ok(p_bucket text, p_limit int, p_window interval)
returns boolean
language plpgsql
volatile
security definer
set search_path to 'public'
as $$
declare v_fails int;
begin
  select fails into v_fails from rl_attempts
   where bucket = p_bucket and window_start = _rl_window_start(p_window);
  return coalesce(v_fails, 0) < p_limit;
end;
$$;

create or replace function public._rl_fail(p_bucket text, p_window interval, p_detail jsonb default null)
returns void
language plpgsql
volatile
security definer
set search_path to 'public'
as $$
declare v_ws timestamptz := _rl_window_start(p_window);
begin
  insert into rl_attempts (bucket, window_start, fails)
    values (p_bucket, v_ws, 1)
  on conflict (bucket, window_start)
    do update set fails = rl_attempts.fails + 1;
  insert into rl_events (bucket, detail)
    values (p_bucket, coalesce(p_detail, '{}'::jsonb));
end;
$$;

-- ========== Stronger invite code generator (9 random chars, unbiased) ==========
create or replace function public.gen_invite_code(p_name text)
returns text
language plpgsql
security definer
set search_path to 'public', 'extensions'
as $$
declare
  base text;
  code text;
  alphabet text := 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; -- 32 chars
  suffix text;
  i int;
  b bytea;
begin
  -- requires: create extension if not exists pgcrypto;
  base := left(coalesce(nullif(upper(regexp_replace(coalesce(p_name,'ROSTER'),'[^A-Za-z0-9]','','g')),''),'ROSTER'), 8);
  loop
    suffix := '';
    b := gen_random_bytes(9);
    for i in 0..8 loop
      suffix := suffix || substr(alphabet, 1 + (get_byte(b, i) % 32), 1);
    end loop;
    code := base || '-' || suffix;
    exit when not exists (select 1 from orgs where invite_code = code);
  end loop;
  return code;
end;
$$;

-- ========== _org_admin: invite required + pass elevates; wrong pass rate-limited ==========
drop function if exists public._org_admin(text, text);
drop function if exists public._org_admin(text, text, text);

create function public._org_admin(p_token text, p_pass text, p_access text default null)
returns table(org_id uuid, admin_name text)
language plpgsql
volatile
security definer
set search_path to 'public'
as $$
declare
  v_org uuid;
  v_name text;
  v_bucket text;
begin
  v_org := public._resolve_org_id(p_token);
  if v_org is null then return; end if;
  if not public._invite_matches(v_org, p_access) then return; end if;
  if btrim(coalesce(p_pass,'')) = '' then return; end if;

  select a.name into v_name from admins a
   where a.org_id = v_org and a.passphrase = p_pass
   limit 1;

  if v_name is null then
    v_bucket := 'pass:' || v_org::text || ':' || public._rl_ip();
    if not public._rl_ok(v_bucket, 5, interval '15 minutes') then
      raise exception 'rate_limited';
    end if;
    perform public._rl_fail(v_bucket, interval '15 minutes', jsonb_build_object('kind','pass','org',v_org));
    return;
  end if;

  org_id := v_org;
  admin_name := v_name;
  return next;
end;
$$;

-- ========== get_org_state: invite always; admin only with invite+pass; VOLATILE ==========
create or replace function public.get_org_state(
  p_token text default null,
  p_pass text default null,
  p_access text default null
)
returns jsonb
language plpgsql
volatile
security definer
set search_path to 'public'
as $$
declare
  v_org uuid;
  v_admin text := null;
  v_is_admin boolean := false;
  v_has_invite boolean := false;
  v_games jsonb;
  o orgs;
  v_org_json jsonb;
  v_bucket text;
begin
  v_org := _resolve_org_id(p_token);
  if v_org is null then
    return jsonb_build_object('error', 'invalid_token');
  end if;

  select * into o from orgs where id = v_org;

  v_has_invite := _invite_matches(v_org, p_access);

  if not v_has_invite then
    if btrim(coalesce(p_access,'')) <> '' then
      v_bucket := 'state:' || _rl_ip();
      if not _rl_ok(v_bucket, 20, interval '10 minutes') then
        raise exception 'rate_limited';
      end if;
      perform _rl_fail(v_bucket, interval '10 minutes', jsonb_build_object('kind','access','org',v_org));
    end if;
    v_org_json := jsonb_build_object(
      'slug', o.slug,
      'display_name', o.display_name,
      'subtitle', o.subtitle,
      'signup_notice', o.signup_notice,
      'is_default', o.is_default,
      'token', o.token,
      'custom_slug', o.custom_slug,
      'event_term', o.event_term,
      'event_term_plural', o.event_term_plural,
      'person_term', o.person_term,
      'person_term_plural', o.person_term_plural
    );
    return jsonb_build_object(
      'needs_access', true,
      'org', v_org_json,
      'is_admin', false,
      'admin_name', null,
      'games', '[]'::jsonb
    );
  end if;

  -- Invite OK. Optional admin elevation (wrong pass rate-limited via shared path).
  if p_pass is not null and btrim(p_pass) <> '' then
    select name into v_admin from admins
     where org_id = v_org and passphrase = p_pass limit 1;
    if v_admin is null then
      v_bucket := 'pass:' || v_org::text || ':' || _rl_ip();
      if not _rl_ok(v_bucket, 5, interval '15 minutes') then
        raise exception 'rate_limited';
      end if;
      perform _rl_fail(v_bucket, interval '15 minutes', jsonb_build_object('kind','pass','org',v_org,'via','get_org_state'));
    else
      v_is_admin := true;
    end if;
  end if;

  v_org_json := jsonb_build_object(
    'slug', o.slug,
    'display_name', o.display_name,
    'subtitle', o.subtitle,
    'signup_notice', o.signup_notice,
    'is_default', o.is_default,
    'token', o.token,
    'custom_slug', o.custom_slug,
    'event_term', o.event_term,
    'event_term_plural', o.event_term_plural,
    'person_term', o.person_term,
    'person_term_plural', o.person_term_plural
  );

  if v_is_admin then
    v_org_json := v_org_json || jsonb_build_object('invite_code', o.invite_code);
  end if;

  select coalesce(jsonb_agg(g order by g.game_date, g.game_time), '[]'::jsonb) into v_games
  from (
    select gm.id, gm.game_date, gm.game_time, gm.label, gm.max_players, gm.status,
           gm.maps_link, gm.created_at, gm.created_by,
           coalesce((select jsonb_agg(jsonb_build_object(
                       'id', s.id, 'player_name', s.player_name, 'created_at', s.created_at
                     ) order by s.created_at)
                     from signups s where s.game_id = gm.id), '[]'::jsonb) as signups
    from games gm
    where gm.org_id = v_org
      and (gm.status = 'live' or (v_is_admin and gm.status = 'draft'))
  ) g;

  return jsonb_build_object(
    'needs_access', false,
    'org', v_org_json,
    'is_admin', v_is_admin,
    'admin_name', v_admin,
    'games', v_games
  );
end;
$$;

-- ========== org_from_invite: rate limit + VOLATILE ==========
create or replace function public.org_from_invite(p_invite_code text)
returns jsonb
language plpgsql
volatile
security definer
set search_path to 'public'
as $$
declare
  o orgs;
  v_bucket text;
begin
  v_bucket := 'invite:' || _rl_ip();
  if not _rl_ok(v_bucket, 10, interval '10 minutes') then
    raise exception 'rate_limited';
  end if;

  if btrim(coalesce(p_invite_code,'')) = '' then
    perform _rl_fail(v_bucket, interval '10 minutes', jsonb_build_object('kind','invite_blank'));
    return jsonb_build_object('error', 'invalid_code');
  end if;

  select * into o from orgs
   where upper(btrim(invite_code)) = upper(btrim(p_invite_code))
   limit 1;

  if o.id is null then
    perform _rl_fail(v_bucket, interval '10 minutes', jsonb_build_object('kind','invite_miss'));
    return jsonb_build_object('error', 'invalid_code');
  end if;

  return jsonb_build_object(
    'token', o.token,
    'display_name', o.display_name,
    'slug', o.slug,
    'custom_slug', o.custom_slug
  );
end;
$$;

-- ========== Player RPCs: rate-limit wrong codes ==========
create or replace function public.signup_player(
  p_token text,
  p_game_id uuid,
  p_player_name text,
  p_device_id text default null,
  p_invite_code text default null
)
returns jsonb
language plpgsql
security definer
set search_path to 'public'
as $$
declare
  v_org uuid;
  v_g games;
  v_name text := btrim(p_player_name);
  v_bucket text;
begin
  v_org := _resolve_org_id(p_token);
  if v_org is null then raise exception 'invalid_token'; end if;
  if not _invite_matches(v_org, p_invite_code) then
    v_bucket := 'state:' || _rl_ip();
    if not _rl_ok(v_bucket, 20, interval '10 minutes') then raise exception 'rate_limited'; end if;
    perform _rl_fail(v_bucket, interval '10 minutes', jsonb_build_object('kind','signup_access'));
    raise exception 'access_required';
  end if;
  if v_name = '' then raise exception 'empty_name'; end if;
  select * into v_g from games where id = p_game_id;
  if v_g.id is null or v_g.org_id <> v_org then raise exception 'not_found'; end if;
  if v_g.status <> 'live' then raise exception 'not_open'; end if;
  begin
    insert into signups (game_id, org_id, player_name, device_id)
      values (p_game_id, v_org, v_name, p_device_id);
  exception when unique_violation then
    return jsonb_build_object('ok', false, 'reason', 'duplicate');
  end;
  insert into activity_log (game_id, org_id, action, player_name, actor_name, is_admin)
    values (p_game_id, v_org, 'signup', v_name, v_name, false);
  return jsonb_build_object('ok', true);
end;
$$;

create or replace function public.remove_signup(
  p_token text,
  p_game_id uuid,
  p_player_name text,
  p_actor_name text,
  p_invite_code text default null
)
returns jsonb
language plpgsql
security definer
set search_path to 'public'
as $$
declare v_org uuid; v_bucket text;
begin
  v_org := _resolve_org_id(p_token);
  if v_org is null then raise exception 'invalid_token'; end if;
  if not _invite_matches(v_org, p_invite_code) then
    v_bucket := 'state:' || _rl_ip();
    if not _rl_ok(v_bucket, 20, interval '10 minutes') then raise exception 'rate_limited'; end if;
    perform _rl_fail(v_bucket, interval '10 minutes', jsonb_build_object('kind','remove_access'));
    raise exception 'access_required';
  end if;
  if not exists (select 1 from games where id = p_game_id and org_id = v_org) then
    raise exception 'not_found';
  end if;
  delete from signups where game_id = p_game_id and lower(player_name) = lower(btrim(p_player_name));
  insert into activity_log (game_id, org_id, action, player_name, actor_name, is_admin)
    values (p_game_id, v_org, 'remove', btrim(p_player_name), nullif(btrim(p_actor_name),''), false);
  return jsonb_build_object('ok', true);
end;
$$;

create or replace function public.get_org_activity(
  p_token text,
  p_full boolean default false,
  p_access text default null
)
returns jsonb
language plpgsql
volatile
security definer
set search_path to 'public'
as $$
declare v_org uuid; v_bucket text;
begin
  v_org := _resolve_org_id(p_token);
  if v_org is null then return '[]'::jsonb; end if;
  if not _invite_matches(v_org, p_access) then
    if btrim(coalesce(p_access,'')) <> '' then
      v_bucket := 'state:' || _rl_ip();
      if not _rl_ok(v_bucket, 20, interval '10 minutes') then raise exception 'rate_limited'; end if;
      perform _rl_fail(v_bucket, interval '10 minutes', jsonb_build_object('kind','activity_access'));
    end if;
    return '[]'::jsonb;
  end if;
  return coalesce((
    select jsonb_agg(row_to_json(x)::jsonb)
    from (
      select l.game_id, l.action, l.player_name, l.actor_name, l.is_admin, l.created_at, g.label
        from activity_log l
        left join games g on g.id = l.game_id
       where l.org_id = v_org
         and (not p_full or l.created_at >= now() - interval '7 days')
       order by l.created_at desc
       limit case when p_full then 500 else 10 end
    ) x
  ), '[]'::jsonb);
end;
$$;

create or replace function public.save_subscription(
  p_token text,
  p_endpoint text,
  p_p256dh text,
  p_auth text,
  p_user_agent text,
  p_device_id text,
  p_invite_code text default null
)
returns void
language plpgsql
security definer
set search_path to 'public'
as $$
declare v_org uuid; v_bucket text;
begin
  v_org := _resolve_org_id(p_token);
  if v_org is null then raise exception 'invalid_token'; end if;
  if not _invite_matches(v_org, p_invite_code) then
    v_bucket := 'state:' || _rl_ip();
    if not _rl_ok(v_bucket, 20, interval '10 minutes') then raise exception 'rate_limited'; end if;
    perform _rl_fail(v_bucket, interval '10 minutes', jsonb_build_object('kind','push_access'));
    raise exception 'access_required';
  end if;
  insert into push_subscriptions (endpoint,p256dh,auth,user_agent,device_id)
    values (p_endpoint,p_p256dh,p_auth,p_user_agent,p_device_id)
  on conflict (endpoint) do update set device_id=excluded.device_id, user_agent=excluded.user_agent;
  insert into push_org (endpoint, org_id) values (p_endpoint, v_org) on conflict do nothing;
end;
$$;

-- ========== Admin RPCs: add p_access (default null) and pass to _org_admin ==========
drop function if exists public.verify_admin(text, text);
drop function if exists public.verify_admin(text, text, text);
create function public.verify_admin(p_token text, p_pass text, p_access text default null)
returns jsonb
language plpgsql
volatile
security definer
set search_path to 'public'
as $$
declare v_name text;
begin
  select a.admin_name into v_name from _org_admin(p_token, p_pass, p_access) a;
  if v_name is null then
    return jsonb_build_object('ok', false);
  end if;
  return jsonb_build_object('ok', true, 'name', v_name);
end;
$$;
grant execute on function public.verify_admin(text, text, text) to anon, authenticated, service_role, public;

drop function if exists public.get_org_archived(text, text);
drop function if exists public.get_org_archived(text, text, text);
create function public.get_org_archived(p_token text, p_pass text, p_access text default null)
returns jsonb
language plpgsql
volatile
security definer
set search_path to 'public'
as $$
declare v_org uuid; v_games jsonb;
begin
  select a.org_id into v_org from _org_admin(p_token, p_pass, p_access) a;
  if v_org is null then return jsonb_build_object('error','forbidden'); end if;
  select coalesce(jsonb_agg(g order by g.game_date desc, g.game_time desc),'[]'::jsonb) into v_games
  from (select gm.id,gm.game_date,gm.game_time,gm.label,gm.max_players,gm.status,gm.maps_link,gm.created_at,
               coalesce((select jsonb_agg(jsonb_build_object('id',s.id,'player_name',s.player_name,'created_at',s.created_at) order by s.created_at)
                         from signups s where s.game_id=gm.id),'[]'::jsonb) as signups
        from games gm where gm.org_id = v_org and gm.status = 'archived') g;
  return jsonb_build_object('games', v_games);
end;
$$;
grant execute on function public.get_org_archived(text, text, text) to anon, authenticated, service_role, public;

drop function if exists public.create_game(text, text, date, time, text, integer, text);
drop function if exists public.create_game(text, text, date, time, text, integer, text, text);
create function public.create_game(
  p_token text, p_pass text, p_date date, p_time time, p_label text, p_max_players integer,
  p_maps_link text default null, p_access text default null
)
returns uuid
language plpgsql security definer set search_path to 'public'
as $$
declare v_org uuid; v_admin text; v_id uuid;
begin
  select org_id, admin_name into v_org, v_admin from _org_admin(p_token, p_pass, p_access);
  if v_org is null then raise exception 'forbidden'; end if;
  insert into games (org_id, game_date, game_time, label, max_players, status, maps_link)
    values (v_org, p_date, p_time, p_label, p_max_players, 'draft', nullif(btrim(p_maps_link),''))
    returning id into v_id;
  insert into activity_log (game_id, org_id, action, player_name, actor_name, is_admin)
    values (v_id, v_org, 'game_created', p_label, v_admin, true);
  return v_id;
end;
$$;
grant execute on function public.create_game(text, text, date, time, text, integer, text, text) to anon, authenticated, service_role, public;

drop function if exists public.update_game(text, text, uuid, date, time, text, integer, text);
drop function if exists public.update_game(text, text, uuid, date, time, text, integer, text, text);
create function public.update_game(
  p_token text, p_pass text, p_game_id uuid, p_date date, p_time time, p_label text, p_max_players integer,
  p_maps_link text, p_access text default null
)
returns void language plpgsql security definer set search_path to 'public' as $$
declare v_org uuid;
begin
  select org_id into v_org from _org_admin(p_token, p_pass, p_access);
  if v_org is null then raise exception 'forbidden'; end if;
  update games set game_date=p_date, game_time=p_time, label=p_label,
                   max_players=p_max_players, maps_link=nullif(btrim(p_maps_link),'')
   where id = p_game_id and org_id = v_org;
  if not found then raise exception 'not_found'; end if;
end;
$$;
grant execute on function public.update_game(text, text, uuid, date, time, text, integer, text, text) to anon, authenticated, service_role, public;

drop function if exists public.publish_game(text, text, uuid);
drop function if exists public.publish_game(text, text, uuid, text);
create function public.publish_game(p_token text, p_pass text, p_game_id uuid, p_access text default null)
returns void language plpgsql security definer set search_path to 'public' as $$
declare v_org uuid; v_admin text; v_label text;
begin
  select org_id, admin_name into v_org, v_admin from _org_admin(p_token, p_pass, p_access);
  if v_org is null then raise exception 'forbidden'; end if;
  update games set status='live' where id=p_game_id and org_id=v_org and status='draft'
    returning label into v_label;
  if not found then raise exception 'not_found'; end if;
  insert into activity_log (game_id, org_id, action, player_name, actor_name, is_admin)
    values (p_game_id, v_org, 'game_published', v_label, v_admin, true);
end;
$$;
grant execute on function public.publish_game(text, text, uuid, text) to anon, authenticated, service_role, public;

drop function if exists public.delete_game(text, text, uuid);
drop function if exists public.delete_game(text, text, uuid, text);
create function public.delete_game(p_token text, p_pass text, p_game_id uuid, p_access text default null)
returns void language plpgsql security definer set search_path to 'public' as $$
declare v_org uuid; v_admin text; v_label text;
begin
  select org_id, admin_name into v_org, v_admin from _org_admin(p_token, p_pass, p_access);
  if v_org is null then raise exception 'forbidden'; end if;
  select label into v_label from games where id=p_game_id and org_id=v_org;
  if v_label is null then raise exception 'not_found'; end if;
  insert into activity_log (game_id, org_id, action, player_name, actor_name, is_admin)
    values (p_game_id, v_org, 'game_deleted', v_label, v_admin, true);
  delete from games where id=p_game_id and org_id=v_org;
end;
$$;
grant execute on function public.delete_game(text, text, uuid, text) to anon, authenticated, service_role, public;

drop function if exists public.unarchive_game(text, text, uuid);
drop function if exists public.unarchive_game(text, text, uuid, text);
create function public.unarchive_game(p_token text, p_pass text, p_game_id uuid, p_access text default null)
returns void language plpgsql security definer set search_path to 'public' as $$
declare v_org uuid;
begin
  select org_id into v_org from _org_admin(p_token, p_pass, p_access);
  if v_org is null then raise exception 'forbidden'; end if;
  update games set status='live' where id=p_game_id and org_id=v_org and status='archived';
  if not found then raise exception 'not_found'; end if;
end;
$$;
grant execute on function public.unarchive_game(text, text, uuid, text) to anon, authenticated, service_role, public;

drop function if exists public.add_admin(text, text, text, text);
drop function if exists public.add_admin(text, text, text, text, text);
create function public.add_admin(p_token text, p_pass text, p_name text, p_passphrase text, p_access text default null)
returns void language plpgsql security definer set search_path to 'public' as $$
declare v_org uuid;
begin
  select org_id into v_org from _org_admin(p_token, p_pass, p_access);
  if v_org is null then raise exception 'forbidden'; end if;
  insert into admins (name, passphrase, org_id) values (p_name, p_passphrase, v_org);
end;
$$;
grant execute on function public.add_admin(text, text, text, text, text) to anon, authenticated, service_role, public;

drop function if exists public.admin_remove_signup(text, text, uuid, text);
drop function if exists public.admin_remove_signup(text, text, uuid, text, text);
create function public.admin_remove_signup(p_token text, p_pass text, p_game_id uuid, p_player_name text, p_access text default null)
returns void language plpgsql security definer set search_path to 'public' as $$
declare v_org uuid; v_admin text;
begin
  select org_id, admin_name into v_org, v_admin from _org_admin(p_token, p_pass, p_access);
  if v_org is null then raise exception 'forbidden'; end if;
  if not exists (select 1 from games where id=p_game_id and org_id=v_org) then raise exception 'not_found'; end if;
  delete from signups where game_id=p_game_id and lower(player_name)=lower(btrim(p_player_name));
  insert into activity_log (game_id, org_id, action, player_name, actor_name, is_admin)
    values (p_game_id, v_org, 'admin_remove', btrim(p_player_name), v_admin, true);
end;
$$;
grant execute on function public.admin_remove_signup(text, text, uuid, text, text) to anon, authenticated, service_role, public;

drop function if exists public.rotate_invite_code(text, text);
drop function if exists public.rotate_invite_code(text, text, text);
create function public.rotate_invite_code(p_token text, p_pass text, p_access text default null)
returns jsonb language plpgsql security definer set search_path to 'public' as $$
declare v_org uuid; v_name text; v_code text;
begin
  select org_id into v_org from _org_admin(p_token, p_pass, p_access);
  if v_org is null then raise exception 'forbidden'; end if;
  select display_name into v_name from orgs where id = v_org;
  v_code := gen_invite_code(v_name);
  update orgs set invite_code = v_code where id = v_org;
  return jsonb_build_object('invite_code', v_code);
end;
$$;
grant execute on function public.rotate_invite_code(text, text, text) to anon, authenticated, service_role, public;

drop function if exists public.delete_roster(text, text);
drop function if exists public.delete_roster(text, text, text);
create function public.delete_roster(p_token text, p_pass text, p_access text default null)
returns jsonb language plpgsql security definer set search_path to 'public' as $$
declare v_org uuid; v_is_default boolean;
begin
  select org_id into v_org from _org_admin(p_token, p_pass, p_access);
  if v_org is null then raise exception 'forbidden'; end if;
  select is_default into v_is_default from orgs where id = v_org;
  if v_is_default then raise exception 'cannot_delete_default'; end if;
  delete from signups      where org_id = v_org;
  delete from activity_log where org_id = v_org;
  delete from games        where org_id = v_org;
  delete from admins       where org_id = v_org;
  delete from push_org     where org_id = v_org;
  delete from orgs         where id = v_org;
  return jsonb_build_object('ok', true);
end;
$$;
grant execute on function public.delete_roster(text, text, text) to anon, authenticated, service_role, public;

-- set_org_branding: drop by signature then recreate with p_access
drop function if exists public.set_org_branding(text, text, text, text, text, text, text, text, text, text);
drop function if exists public.set_org_branding(text, text, text, text, text, text, text, text, text, text, text);
create function public.set_org_branding(
  p_token text, p_pass text,
  p_display_name text, p_subtitle text, p_signup_notice text,
  p_event_term text default null, p_event_term_plural text default null,
  p_person_term text default null, p_person_term_plural text default null,
  p_custom_slug text default null,
  p_access text default null
)
returns void language plpgsql security definer set search_path to 'public' as $$
declare v_org uuid; v_slug text;
begin
  select org_id into v_org from _org_admin(p_token, p_pass, p_access);
  if v_org is null then raise exception 'forbidden'; end if;
  update orgs set
     display_name  = coalesce(nullif(btrim(p_display_name),''), display_name),
     subtitle      = nullif(btrim(p_subtitle),''),
     signup_notice = nullif(btrim(p_signup_notice),''),
     event_term         = case when p_event_term is null then event_term
                               when btrim(p_event_term)='' then null else btrim(p_event_term) end,
     event_term_plural  = case when p_event_term_plural is null then event_term_plural
                               when btrim(p_event_term_plural)='' then null else btrim(p_event_term_plural) end,
     person_term        = case when p_person_term is null then person_term
                               when btrim(p_person_term)='' then null else btrim(p_person_term) end,
     person_term_plural = case when p_person_term_plural is null then person_term_plural
                               when btrim(p_person_term_plural)='' then null else btrim(p_person_term_plural) end
   where id = v_org;
  if p_custom_slug is not null then
    if btrim(p_custom_slug) = '' then
      update orgs set custom_slug = null where id = v_org;
    else
      v_slug := lower(btrim(p_custom_slug));
      if v_slug !~ '^[a-z0-9][a-z0-9-]{1,28}[a-z0-9]$' then raise exception 'slug_invalid'; end if;
      if exists(select 1 from orgs where id <> v_org
                and (lower(custom_slug) = v_slug or slug = v_slug or token = v_slug)) then
        raise exception 'slug_taken';
      end if;
      update orgs set custom_slug = v_slug where id = v_org;
    end if;
  end if;
end;
$$;
grant execute on function public.set_org_branding(text, text, text, text, text, text, text, text, text, text, text) to anon, authenticated, service_role, public;

-- create_roster: proof still uses _org_admin — add optional p_proof_access
drop function if exists public.create_roster(text, text, text, text, text, text, text, text, text);
drop function if exists public.create_roster(text, text, text, text, text, text, text, text, text, text);
create function public.create_roster(
  p_proof_token text, p_proof_pass text, p_name text, p_subtitle text, p_admin_pass text,
  p_event_term text default null, p_event_term_plural text default null,
  p_person_term text default null, p_person_term_plural text default null,
  p_proof_access text default null
)
returns jsonb language plpgsql security definer set search_path to 'public' as $$
declare
  v_proof_org uuid; v_creator text; v_id uuid; v_tok text; v_code text; v_slug text;
begin
  select org_id, admin_name into v_proof_org, v_creator from _org_admin(p_proof_token, p_proof_pass, p_proof_access);
  if v_proof_org is null then raise exception 'forbidden'; end if;
  if btrim(coalesce(p_name,'')) = '' then raise exception 'name_required'; end if;
  if btrim(coalesce(p_admin_pass,'')) = '' then raise exception 'pass_required'; end if;
  v_tok  := gen_org_token();
  v_code := gen_invite_code(p_name);
  v_slug := left(lower(regexp_replace(p_name,'[^A-Za-z0-9]+','-','g')),20) || '-' || substr(md5(gen_random_uuid()::text),1,4);
  insert into orgs (slug, token, invite_code, display_name, subtitle,
                    event_term, event_term_plural, person_term, person_term_plural)
    values (v_slug, v_tok, v_code, btrim(p_name), nullif(btrim(p_subtitle),''),
            nullif(btrim(p_event_term),''), nullif(btrim(p_event_term_plural),''),
            nullif(btrim(p_person_term),''), nullif(btrim(p_person_term_plural),''))
    returning id into v_id;
  insert into admins (name, passphrase, org_id) values (coalesce(v_creator,'Admin'), p_admin_pass, v_id);
  return jsonb_build_object('token', v_tok, 'display_name', btrim(p_name), 'slug', v_slug, 'invite_code', v_code);
end;
$$;
grant execute on function public.create_roster(text, text, text, text, text, text, text, text, text, text) to anon, authenticated, service_role, public;

-- Change own admin passphrase (requires invite + current pass)
create or replace function public.change_admin_passphrase(
  p_token text, p_pass text, p_new_pass text, p_access text default null
)
returns jsonb
language plpgsql security definer set search_path to 'public' as $$
declare v_org uuid; v_admin text; n int;
begin
  select org_id, admin_name into v_org, v_admin from _org_admin(p_token, p_pass, p_access);
  if v_org is null then raise exception 'forbidden'; end if;
  if btrim(coalesce(p_new_pass,'')) = '' then raise exception 'pass_required'; end if;
  if length(btrim(p_new_pass)) < 8 then raise exception 'pass_too_short'; end if;
  update admins set passphrase = btrim(p_new_pass)
   where org_id = v_org and passphrase = p_pass;
  get diagnostics n = row_count;
  if n = 0 then raise exception 'forbidden'; end if;
  return jsonb_build_object('ok', true, 'name', v_admin);
end;
$$;
grant execute on function public.change_admin_passphrase(text, text, text, text) to anon, authenticated, service_role, public;

-- Grants for core functions already recreated with replace
grant execute on function public.get_org_state(text, text, text) to anon, authenticated, service_role, public;
grant execute on function public.org_from_invite(text) to anon, authenticated, service_role, public;
grant execute on function public.signup_player(text, uuid, text, text, text) to anon, authenticated, service_role, public;
grant execute on function public.remove_signup(text, uuid, text, text, text) to anon, authenticated, service_role, public;
grant execute on function public.get_org_activity(text, boolean, text) to anon, authenticated, service_role, public;
grant execute on function public.save_subscription(text, text, text, text, text, text, text) to anon, authenticated, service_role, public;

-- Delete weak duplicate Joe (7-char Frisbee) on Ultimate Frisbee
delete from admins where id = 'f3e27792-7fdd-489f-9e34-c1821981bd7d';

-- Cleanup job if pg_cron available
do $$
begin
  if exists (select 1 from pg_extension where extname = 'pg_cron') then
    perform cron.unschedule('egr_rl_cleanup') from cron.job where jobname = 'egr_rl_cleanup';
    perform cron.schedule('egr_rl_cleanup', '15 * * * *',
      $$delete from rl_attempts where window_start < now() - interval '1 day';
        delete from rl_events where at < now() - interval '30 days';$$);
  end if;
exception when others then
  raise notice 'pg_cron schedule skipped: %', sqlerrm;
end $$;
