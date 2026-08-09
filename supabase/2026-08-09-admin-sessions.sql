-- Admin session tracking + boot-all
-- Active = last_seen within 24 hours

create table if not exists public.admin_sessions (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs(id) on delete cascade,
  admin_name text not null,
  session_token text not null unique,
  device_id text,
  user_agent text,
  created_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now()
);
create index if not exists admin_sessions_org_seen_idx on public.admin_sessions (org_id, last_seen_at desc);
revoke all on public.admin_sessions from anon, authenticated, public;
grant all on public.admin_sessions to service_role;

create or replace function public._new_session_token()
returns text
language sql
volatile
as $$
  select replace(replace(encode(extensions.gen_random_bytes(24), 'base64'), '+', 'A'), '/', 'B');
$$;

-- Login: invite + pass only; creates a session row
drop function if exists public.verify_admin(text, text, text);
drop function if exists public.verify_admin(text, text, text, text, text);
create function public.verify_admin(
  p_token text,
  p_pass text,
  p_access text default null,
  p_device_id text default null,
  p_user_agent text default null
)
returns jsonb
language plpgsql
volatile
security definer
set search_path to 'public', 'extensions'
as $$
declare
  v_org uuid;
  v_name text;
  v_bucket text;
  v_sid uuid;
  v_tok text;
begin
  v_org := _resolve_org_id(p_token);
  if v_org is null then return jsonb_build_object('ok', false); end if;
  if not _invite_matches(v_org, p_access) then return jsonb_build_object('ok', false); end if;
  if btrim(coalesce(p_pass,'')) = '' then return jsonb_build_object('ok', false); end if;

  select a.name into v_name from admins a
   where a.org_id = v_org and a.passphrase = p_pass limit 1;

  if v_name is null then
    v_bucket := 'pass:' || v_org::text || ':' || _rl_ip();
    if not _rl_ok(v_bucket, 5, interval '15 minutes') then
      raise exception 'rate_limited';
    end if;
    perform _rl_fail(v_bucket, interval '15 minutes', jsonb_build_object('kind','pass','org',v_org,'via','verify_admin'));
    return jsonb_build_object('ok', false);
  end if;

  v_tok := _new_session_token();
  insert into admin_sessions (org_id, admin_name, session_token, device_id, user_agent)
    values (v_org, v_name, v_tok, nullif(btrim(coalesce(p_device_id,'')),''), nullif(left(coalesce(p_user_agent,''), 240), ''))
    returning id into v_sid;

  return jsonb_build_object(
    'ok', true,
    'name', v_name,
    'session_token', v_tok,
    'session_id', v_sid
  );
end;
$$;
grant execute on function public.verify_admin(text, text, text, text, text) to anon, authenticated, service_role, public;

-- Admin ops: invite + pass + live session
drop function if exists public._org_admin(text, text, text);
drop function if exists public._org_admin(text, text, text, text);
create function public._org_admin(
  p_token text,
  p_pass text,
  p_access text default null,
  p_session text default null
)
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
  v_sess admin_sessions%rowtype;
begin
  v_org := public._resolve_org_id(p_token);
  if v_org is null then return; end if;
  if not public._invite_matches(v_org, p_access) then return; end if;
  if btrim(coalesce(p_pass,'')) = '' then return; end if;
  if btrim(coalesce(p_session,'')) = '' then return; end if;

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

  select * into v_sess from admin_sessions s
   where s.org_id = v_org
     and s.session_token = p_session
     and s.admin_name = v_name
     and s.last_seen_at > now() - interval '7 days'
   limit 1;

  if v_sess.id is null then
    return; -- session missing/expired/booted
  end if;

  update admin_sessions set last_seen_at = now() where id = v_sess.id;

  org_id := v_org;
  admin_name := v_name;
  return next;
end;
$$;

-- get_org_state: admin elevation needs valid session too
create or replace function public.get_org_state(
  p_token text default null,
  p_pass text default null,
  p_access text default null,
  p_session text default null
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
      if not _rl_ok(v_bucket, 20, interval '10 minutes') then raise exception 'rate_limited'; end if;
      perform _rl_fail(v_bucket, interval '10 minutes', jsonb_build_object('kind','access','org',v_org));
    end if;
    v_org_json := jsonb_build_object(
      'slug', o.slug, 'display_name', o.display_name, 'subtitle', o.subtitle,
      'signup_notice', o.signup_notice, 'is_default', o.is_default, 'token', o.token,
      'custom_slug', o.custom_slug, 'event_term', o.event_term, 'event_term_plural', o.event_term_plural,
      'person_term', o.person_term, 'person_term_plural', o.person_term_plural
    );
    return jsonb_build_object('needs_access', true, 'org', v_org_json, 'is_admin', false, 'admin_name', null, 'games', '[]'::jsonb);
  end if;

  -- Invite OK. Admin only with pass + live session.
  if p_pass is not null and btrim(p_pass) <> '' and p_session is not null and btrim(p_session) <> '' then
    select a.admin_name into v_admin from _org_admin(p_token, p_pass, p_access, p_session) a;
    v_is_admin := v_admin is not null;
    if not v_is_admin and btrim(p_pass) <> '' then
      -- pass may be right but session booted; do not rate-limit as wrong pass if pass matches
      if exists (select 1 from admins where org_id = v_org and passphrase = p_pass) then
        v_admin := null;
        v_is_admin := false;
      else
        v_bucket := 'pass:' || v_org::text || ':' || _rl_ip();
        if not _rl_ok(v_bucket, 5, interval '15 minutes') then raise exception 'rate_limited'; end if;
        perform _rl_fail(v_bucket, interval '15 minutes', jsonb_build_object('kind','pass','org',v_org,'via','get_org_state'));
      end if;
    end if;
  end if;

  v_org_json := jsonb_build_object(
    'slug', o.slug, 'display_name', o.display_name, 'subtitle', o.subtitle,
    'signup_notice', o.signup_notice, 'is_default', o.is_default, 'token', o.token,
    'custom_slug', o.custom_slug, 'event_term', o.event_term, 'event_term_plural', o.event_term_plural,
    'person_term', o.person_term, 'person_term_plural', o.person_term_plural
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
grant execute on function public.get_org_state(text, text, text, text) to anon, authenticated, service_role, public;

-- List active sessions (last 24h)
create or replace function public.list_admin_sessions(
  p_token text, p_pass text, p_access text default null, p_session text default null
)
returns jsonb
language plpgsql
volatile
security definer
set search_path to 'public'
as $$
declare v_org uuid; v_name text;
begin
  select a.org_id, a.admin_name into v_org, v_name from _org_admin(p_token, p_pass, p_access, p_session) a;
  if v_org is null then raise exception 'forbidden'; end if;
  return coalesce((
    select jsonb_agg(jsonb_build_object(
      'id', s.id,
      'admin_name', s.admin_name,
      'device_id', s.device_id,
      'created_at', s.created_at,
      'last_seen_at', s.last_seen_at,
      'is_me', (s.session_token = p_session),
      'active', (s.last_seen_at > now() - interval '24 hours')
    ) order by s.last_seen_at desc)
    from admin_sessions s
    where s.org_id = v_org
      and s.last_seen_at > now() - interval '7 days'
  ), '[]'::jsonb);
end;
$$;
grant execute on function public.list_admin_sessions(text, text, text, text) to anon, authenticated, service_role, public;

-- Boot sessions: 'others' keeps caller, 'all' boots everyone
create or replace function public.revoke_admin_sessions(
  p_token text, p_pass text, p_access text default null, p_session text default null,
  p_mode text default 'others'
)
returns jsonb
language plpgsql
volatile
security definer
set search_path to 'public'
as $$
declare v_org uuid; v_name text; n int;
begin
  select a.org_id, a.admin_name into v_org, v_name from _org_admin(p_token, p_pass, p_access, p_session) a;
  if v_org is null then raise exception 'forbidden'; end if;
  if lower(coalesce(p_mode,'others')) = 'all' then
    delete from admin_sessions where org_id = v_org;
  else
    delete from admin_sessions where org_id = v_org and session_token is distinct from p_session;
  end if;
  get diagnostics n = row_count;
  return jsonb_build_object('ok', true, 'revoked', n, 'mode', lower(coalesce(p_mode,'others')));
end;
$$;
grant execute on function public.revoke_admin_sessions(text, text, text, text, text) to anon, authenticated, service_role, public;

-- Logout self
create or replace function public.revoke_my_admin_session(
  p_token text, p_session text
)
returns jsonb
language plpgsql
volatile
security definer
set search_path to 'public'
as $$
declare v_org uuid; n int;
begin
  v_org := _resolve_org_id(p_token);
  if v_org is null or btrim(coalesce(p_session,'')) = '' then
    return jsonb_build_object('ok', true, 'revoked', 0);
  end if;
  delete from admin_sessions where org_id = v_org and session_token = p_session;
  get diagnostics n = row_count;
  return jsonb_build_object('ok', true, 'revoked', n);
end;
$$;
grant execute on function public.revoke_my_admin_session(text, text) to anon, authenticated, service_role, public;

-- Patch admin RPCs that call _org_admin to pass p_session (recreate with 4th arg default null)
-- Helper pattern: add p_session text default null and call _org_admin(..., p_session)

create or replace function public.change_admin_passphrase(
  p_token text, p_pass text, p_new_pass text, p_access text default null, p_session text default null
)
returns jsonb
language plpgsql security definer set search_path to 'public' as $$
declare v_org uuid; v_admin text; n int;
begin
  select org_id, admin_name into v_org, v_admin from _org_admin(p_token, p_pass, p_access, p_session);
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
grant execute on function public.change_admin_passphrase(text, text, text, text, text) to anon, authenticated, service_role, public;

-- Forward p_session through all admin mutation RPCs
drop function if exists public.get_org_archived(text, text, text);
drop function if exists public.get_org_archived(text, text, text, text);
create function public.get_org_archived(p_token text, p_pass text, p_access text default null, p_session text default null)
returns jsonb language plpgsql volatile security definer set search_path to 'public' as $$
declare v_org uuid; v_games jsonb;
begin
  select a.org_id into v_org from _org_admin(p_token, p_pass, p_access, p_session) a;
  if v_org is null then return jsonb_build_object('error','forbidden'); end if;
  select coalesce(jsonb_agg(g order by g.game_date desc, g.game_time desc),'[]'::jsonb) into v_games
  from (select gm.id,gm.game_date,gm.game_time,gm.label,gm.max_players,gm.status,gm.maps_link,gm.created_at,
               coalesce((select jsonb_agg(jsonb_build_object('id',s.id,'player_name',s.player_name,'created_at',s.created_at) order by s.created_at)
                         from signups s where s.game_id=gm.id),'[]'::jsonb) as signups
        from games gm where gm.org_id = v_org and gm.status = 'archived') g;
  return jsonb_build_object('games', v_games);
end;
$$;
grant execute on function public.get_org_archived(text, text, text, text) to anon, authenticated, service_role, public;

drop function if exists public.create_game(text, text, date, time, text, integer, text, text);
drop function if exists public.create_game(text, text, date, time, text, integer, text, text, text);
create function public.create_game(
  p_token text, p_pass text, p_date date, p_time time, p_label text, p_max_players integer,
  p_maps_link text default null, p_access text default null, p_session text default null
)
returns uuid language plpgsql security definer set search_path to 'public' as $$
declare v_org uuid; v_admin text; v_id uuid;
begin
  select org_id, admin_name into v_org, v_admin from _org_admin(p_token, p_pass, p_access, p_session);
  if v_org is null then raise exception 'forbidden'; end if;
  insert into games (org_id, game_date, game_time, label, max_players, status, maps_link)
    values (v_org, p_date, p_time, p_label, p_max_players, 'draft', nullif(btrim(p_maps_link),''))
    returning id into v_id;
  insert into activity_log (game_id, org_id, action, player_name, actor_name, is_admin)
    values (v_id, v_org, 'game_created', p_label, v_admin, true);
  return v_id;
end;
$$;
grant execute on function public.create_game(text, text, date, time, text, integer, text, text, text) to anon, authenticated, service_role, public;

drop function if exists public.update_game(text, text, uuid, date, time, text, integer, text, text);
drop function if exists public.update_game(text, text, uuid, date, time, text, integer, text, text, text);
create function public.update_game(
  p_token text, p_pass text, p_game_id uuid, p_date date, p_time time, p_label text, p_max_players integer,
  p_maps_link text, p_access text default null, p_session text default null
)
returns void language plpgsql security definer set search_path to 'public' as $$
declare v_org uuid;
begin
  select org_id into v_org from _org_admin(p_token, p_pass, p_access, p_session);
  if v_org is null then raise exception 'forbidden'; end if;
  update games set game_date=p_date, game_time=p_time, label=p_label,
                   max_players=p_max_players, maps_link=nullif(btrim(p_maps_link),'')
   where id = p_game_id and org_id = v_org;
  if not found then raise exception 'not_found'; end if;
end;
$$;
grant execute on function public.update_game(text, text, uuid, date, time, text, integer, text, text, text) to anon, authenticated, service_role, public;

drop function if exists public.publish_game(text, text, uuid, text);
drop function if exists public.publish_game(text, text, uuid, text, text);
create function public.publish_game(p_token text, p_pass text, p_game_id uuid, p_access text default null, p_session text default null)
returns void language plpgsql security definer set search_path to 'public' as $$
declare v_org uuid; v_admin text; v_label text;
begin
  select org_id, admin_name into v_org, v_admin from _org_admin(p_token, p_pass, p_access, p_session);
  if v_org is null then raise exception 'forbidden'; end if;
  update games set status='live' where id=p_game_id and org_id=v_org and status='draft' returning label into v_label;
  if not found then raise exception 'not_found'; end if;
  insert into activity_log (game_id, org_id, action, player_name, actor_name, is_admin)
    values (p_game_id, v_org, 'game_published', v_label, v_admin, true);
end;
$$;
grant execute on function public.publish_game(text, text, uuid, text, text) to anon, authenticated, service_role, public;

drop function if exists public.delete_game(text, text, uuid, text);
drop function if exists public.delete_game(text, text, uuid, text, text);
create function public.delete_game(p_token text, p_pass text, p_game_id uuid, p_access text default null, p_session text default null)
returns void language plpgsql security definer set search_path to 'public' as $$
declare v_org uuid; v_admin text; v_label text;
begin
  select org_id, admin_name into v_org, v_admin from _org_admin(p_token, p_pass, p_access, p_session);
  if v_org is null then raise exception 'forbidden'; end if;
  select label into v_label from games where id=p_game_id and org_id=v_org;
  if v_label is null then raise exception 'not_found'; end if;
  insert into activity_log (game_id, org_id, action, player_name, actor_name, is_admin)
    values (p_game_id, v_org, 'game_deleted', v_label, v_admin, true);
  delete from games where id=p_game_id and org_id=v_org;
end;
$$;
grant execute on function public.delete_game(text, text, uuid, text, text) to anon, authenticated, service_role, public;

drop function if exists public.unarchive_game(text, text, uuid, text);
drop function if exists public.unarchive_game(text, text, uuid, text, text);
create function public.unarchive_game(p_token text, p_pass text, p_game_id uuid, p_access text default null, p_session text default null)
returns void language plpgsql security definer set search_path to 'public' as $$
declare v_org uuid;
begin
  select org_id into v_org from _org_admin(p_token, p_pass, p_access, p_session);
  if v_org is null then raise exception 'forbidden'; end if;
  update games set status='live' where id=p_game_id and org_id=v_org and status='archived';
  if not found then raise exception 'not_found'; end if;
end;
$$;
grant execute on function public.unarchive_game(text, text, uuid, text, text) to anon, authenticated, service_role, public;

drop function if exists public.add_admin(text, text, text, text, text);
drop function if exists public.add_admin(text, text, text, text, text, text);
create function public.add_admin(p_token text, p_pass text, p_name text, p_passphrase text, p_access text default null, p_session text default null)
returns void language plpgsql security definer set search_path to 'public' as $$
declare v_org uuid;
begin
  select org_id into v_org from _org_admin(p_token, p_pass, p_access, p_session);
  if v_org is null then raise exception 'forbidden'; end if;
  insert into admins (name, passphrase, org_id) values (p_name, p_passphrase, v_org);
end;
$$;
grant execute on function public.add_admin(text, text, text, text, text, text) to anon, authenticated, service_role, public;

drop function if exists public.admin_remove_signup(text, text, uuid, text, text);
drop function if exists public.admin_remove_signup(text, text, uuid, text, text, text);
create function public.admin_remove_signup(p_token text, p_pass text, p_game_id uuid, p_player_name text, p_access text default null, p_session text default null)
returns void language plpgsql security definer set search_path to 'public' as $$
declare v_org uuid; v_admin text;
begin
  select org_id, admin_name into v_org, v_admin from _org_admin(p_token, p_pass, p_access, p_session);
  if v_org is null then raise exception 'forbidden'; end if;
  if not exists (select 1 from games where id=p_game_id and org_id=v_org) then raise exception 'not_found'; end if;
  delete from signups where game_id=p_game_id and lower(player_name)=lower(btrim(p_player_name));
  insert into activity_log (game_id, org_id, action, player_name, actor_name, is_admin)
    values (p_game_id, v_org, 'admin_remove', btrim(p_player_name), v_admin, true);
end;
$$;
grant execute on function public.admin_remove_signup(text, text, uuid, text, text, text) to anon, authenticated, service_role, public;

drop function if exists public.rotate_invite_code(text, text, text);
drop function if exists public.rotate_invite_code(text, text, text, text);
create function public.rotate_invite_code(p_token text, p_pass text, p_access text default null, p_session text default null)
returns jsonb language plpgsql security definer set search_path to 'public' as $$
declare v_org uuid; v_name text; v_code text;
begin
  select org_id into v_org from _org_admin(p_token, p_pass, p_access, p_session);
  if v_org is null then raise exception 'forbidden'; end if;
  select display_name into v_name from orgs where id = v_org;
  v_code := gen_invite_code(v_name);
  update orgs set invite_code = v_code where id = v_org;
  return jsonb_build_object('invite_code', v_code);
end;
$$;
grant execute on function public.rotate_invite_code(text, text, text, text) to anon, authenticated, service_role, public;

drop function if exists public.delete_roster(text, text, text);
drop function if exists public.delete_roster(text, text, text, text);
create function public.delete_roster(p_token text, p_pass text, p_access text default null, p_session text default null)
returns jsonb language plpgsql security definer set search_path to 'public' as $$
declare v_org uuid; v_is_default boolean;
begin
  select org_id into v_org from _org_admin(p_token, p_pass, p_access, p_session);
  if v_org is null then raise exception 'forbidden'; end if;
  select is_default into v_is_default from orgs where id = v_org;
  if v_is_default then raise exception 'cannot_delete_default'; end if;
  delete from signups where org_id = v_org;
  delete from activity_log where org_id = v_org;
  delete from games where org_id = v_org;
  delete from admin_sessions where org_id = v_org;
  delete from admins where org_id = v_org;
  delete from push_org where org_id = v_org;
  delete from orgs where id = v_org;
  return jsonb_build_object('ok', true);
end;
$$;
grant execute on function public.delete_roster(text, text, text, text) to anon, authenticated, service_role, public;

drop function if exists public.set_org_branding(text, text, text, text, text, text, text, text, text, text, text);
drop function if exists public.set_org_branding(text, text, text, text, text, text, text, text, text, text, text, text);
create function public.set_org_branding(
  p_token text, p_pass text,
  p_display_name text, p_subtitle text, p_signup_notice text,
  p_event_term text default null, p_event_term_plural text default null,
  p_person_term text default null, p_person_term_plural text default null,
  p_custom_slug text default null,
  p_access text default null, p_session text default null
)
returns void language plpgsql security definer set search_path to 'public' as $$
declare v_org uuid; v_slug text;
begin
  select org_id into v_org from _org_admin(p_token, p_pass, p_access, p_session);
  if v_org is null then raise exception 'forbidden'; end if;
  update orgs set
     display_name  = coalesce(nullif(btrim(p_display_name),''), display_name),
     subtitle      = nullif(btrim(p_subtitle),''),
     signup_notice = nullif(btrim(p_signup_notice),''),
     event_term         = case when p_event_term is null then event_term when btrim(p_event_term)='' then null else btrim(p_event_term) end,
     event_term_plural  = case when p_event_term_plural is null then event_term_plural when btrim(p_event_term_plural)='' then null else btrim(p_event_term_plural) end,
     person_term        = case when p_person_term is null then person_term when btrim(p_person_term)='' then null else btrim(p_person_term) end,
     person_term_plural = case when p_person_term_plural is null then person_term_plural when btrim(p_person_term_plural)='' then null else btrim(p_person_term_plural) end
   where id = v_org;
  if p_custom_slug is not null then
    if btrim(p_custom_slug) = '' then
      update orgs set custom_slug = null where id = v_org;
    else
      v_slug := lower(btrim(p_custom_slug));
      if v_slug !~ '^[a-z0-9][a-z0-9-]{1,28}[a-z0-9]$' then raise exception 'slug_invalid'; end if;
      if exists(select 1 from orgs where id <> v_org and (lower(custom_slug)=v_slug or slug=v_slug or token=v_slug)) then
        raise exception 'slug_taken';
      end if;
      update orgs set custom_slug = v_slug where id = v_org;
    end if;
  end if;
end;
$$;
grant execute on function public.set_org_branding(text, text, text, text, text, text, text, text, text, text, text, text) to anon, authenticated, service_role, public;

drop function if exists public.create_roster(text, text, text, text, text, text, text, text, text, text);
drop function if exists public.create_roster(text, text, text, text, text, text, text, text, text, text, text);
create function public.create_roster(
  p_proof_token text, p_proof_pass text, p_name text, p_subtitle text, p_admin_pass text,
  p_event_term text default null, p_event_term_plural text default null,
  p_person_term text default null, p_person_term_plural text default null,
  p_proof_access text default null, p_proof_session text default null
)
returns jsonb language plpgsql security definer set search_path to 'public' as $$
declare
  v_proof_org uuid; v_creator text; v_id uuid; v_tok text; v_code text; v_slug text;
begin
  select org_id, admin_name into v_proof_org, v_creator from _org_admin(p_proof_token, p_proof_pass, p_proof_access, p_proof_session);
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
grant execute on function public.create_roster(text, text, text, text, text, text, text, text, text, text, text) to anon, authenticated, service_role, public;
