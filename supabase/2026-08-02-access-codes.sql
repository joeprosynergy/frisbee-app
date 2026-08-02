-- Per-roster access codes (Easy Game Roster)
-- Applied 2026-08-02 via Supabase Management API.
-- Each org already has invite_code; this makes it required for reads/writes.

-- ---------- helpers ----------
create or replace function public._invite_matches(p_org uuid, p_code text)
returns boolean
language sql
stable
security definer
set search_path to 'public'
as $$
  select exists (
    select 1 from orgs
     where id = p_org
       and btrim(coalesce(p_code,'')) <> ''
       and upper(btrim(invite_code)) = upper(btrim(p_code))
  );
$$;

create or replace function public._resolve_org_id(p_token text)
returns uuid
language plpgsql
stable
security definer
set search_path to 'public'
as $$
declare v uuid;
begin
  v := _org_for_token(p_token);
  if v is null and coalesce(p_token,'') <> '' then
    select id into v from orgs
     where lower(custom_slug) = lower(p_token) or slug = lower(p_token)
     limit 1;
  end if;
  return v;
end;
$$;

-- ---------- get_org_state ----------
drop function if exists public.get_org_state(text, text);
drop function if exists public.get_org_state(text, text, text);

create function public.get_org_state(
  p_token text default null,
  p_pass text default null,
  p_access text default null
)
returns jsonb
language plpgsql
stable
security definer
set search_path to 'public'
as $$
declare
  v_org uuid;
  v_admin text := null;
  v_is_admin boolean := false;
  v_has_access boolean := false;
  v_games jsonb;
  o orgs;
  v_org_json jsonb;
begin
  v_org := _resolve_org_id(p_token);
  if v_org is null then
    return jsonb_build_object('error', 'invalid_token');
  end if;

  select * into o from orgs where id = v_org;

  if p_pass is not null and btrim(p_pass) <> '' then
    select name into v_admin from admins
     where org_id = v_org and passphrase = p_pass limit 1;
    v_is_admin := v_admin is not null;
  end if;

  v_has_access := v_is_admin or _invite_matches(v_org, p_access);

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

  if not v_has_access then
    return jsonb_build_object(
      'needs_access', true,
      'org', v_org_json,
      'is_admin', false,
      'admin_name', null,
      'games', '[]'::jsonb
    );
  end if;

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

grant execute on function public.get_org_state(text, text, text) to anon, authenticated, service_role, public;

-- ---------- signup_player ----------
drop function if exists public.signup_player(text, uuid, text, text);
drop function if exists public.signup_player(text, uuid, text, text, text);

create function public.signup_player(
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
begin
  v_org := _resolve_org_id(p_token);
  if v_org is null then raise exception 'invalid_token'; end if;
  if not _invite_matches(v_org, p_invite_code) then raise exception 'access_required'; end if;
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

grant execute on function public.signup_player(text, uuid, text, text, text) to anon, authenticated, service_role, public;

-- ---------- remove_signup ----------
drop function if exists public.remove_signup(text, uuid, text, text);
drop function if exists public.remove_signup(text, uuid, text, text, text);

create function public.remove_signup(
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
declare v_org uuid;
begin
  v_org := _resolve_org_id(p_token);
  if v_org is null then raise exception 'invalid_token'; end if;
  if not _invite_matches(v_org, p_invite_code) then raise exception 'access_required'; end if;
  if not exists (select 1 from games where id = p_game_id and org_id = v_org) then
    raise exception 'not_found';
  end if;
  delete from signups where game_id = p_game_id and lower(player_name) = lower(btrim(p_player_name));
  insert into activity_log (game_id, org_id, action, player_name, actor_name, is_admin)
    values (p_game_id, v_org, 'remove', btrim(p_player_name), nullif(btrim(p_actor_name),''), false);
  return jsonb_build_object('ok', true);
end;
$$;

grant execute on function public.remove_signup(text, uuid, text, text, text) to anon, authenticated, service_role, public;

-- ---------- get_org_activity ----------
drop function if exists public.get_org_activity(text, boolean);
drop function if exists public.get_org_activity(text, boolean, text);

create function public.get_org_activity(
  p_token text,
  p_full boolean default false,
  p_access text default null
)
returns jsonb
language plpgsql
stable
security definer
set search_path to 'public'
as $$
declare v_org uuid;
begin
  v_org := _resolve_org_id(p_token);
  if v_org is null then return '[]'::jsonb; end if;
  if not _invite_matches(v_org, p_access) then return '[]'::jsonb; end if;
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

grant execute on function public.get_org_activity(text, boolean, text) to anon, authenticated, service_role, public;

-- ---------- org_from_invite ----------
create or replace function public.org_from_invite(p_invite_code text)
returns jsonb
language plpgsql
stable
security definer
set search_path to 'public'
as $$
declare o orgs;
begin
  if btrim(coalesce(p_invite_code,'')) = '' then
    return jsonb_build_object('error', 'invalid_code');
  end if;
  select * into o from orgs
   where upper(btrim(invite_code)) = upper(btrim(p_invite_code))
   limit 1;
  if o.id is null then
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

grant execute on function public.org_from_invite(text) to anon, authenticated, service_role, public;

-- ---------- create_roster: return invite_code ----------
create or replace function public.create_roster(
  p_proof_token text,
  p_proof_pass text,
  p_name text,
  p_subtitle text,
  p_admin_pass text,
  p_event_term text default null,
  p_event_term_plural text default null,
  p_person_term text default null,
  p_person_term_plural text default null
)
returns jsonb
language plpgsql
security definer
set search_path to 'public'
as $$
declare
  v_proof_org uuid;
  v_creator text;
  v_id uuid;
  v_tok text;
  v_code text;
  v_slug text;
begin
  select org_id, admin_name into v_proof_org, v_creator from _org_admin(p_proof_token, p_proof_pass);
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
  return jsonb_build_object(
    'token', v_tok,
    'display_name', btrim(p_name),
    'slug', v_slug,
    'invite_code', v_code
  );
end;
$$;

-- ---------- rotate_invite_code (admin, console/later UI) ----------
create or replace function public.rotate_invite_code(p_token text, p_pass text)
returns jsonb
language plpgsql
security definer
set search_path to 'public'
as $$
declare v_org uuid; v_name text; v_code text;
begin
  select org_id into v_org from _org_admin(p_token, p_pass);
  if v_org is null then raise exception 'forbidden'; end if;
  select display_name into v_name from orgs where id = v_org;
  v_code := gen_invite_code(v_name);
  update orgs set invite_code = v_code where id = v_org;
  return jsonb_build_object('invite_code', v_code);
end;
$$;

grant execute on function public.rotate_invite_code(text, text) to anon, authenticated, service_role, public;

-- ---------- Drop open direct write policies on signups ----------
drop policy if exists "signups_ins_default" on public.signups;
drop policy if exists "signups_del_default" on public.signups;
-- Residual SELECT/INSERT policies on default org (table GRANTs already revoked for anon).
drop policy if exists "signups_sel_default" on public.signups;
drop policy if exists "games_sel_default" on public.games;
drop policy if exists "activity_sel_default" on public.activity_log;
drop policy if exists "activity_ins_default" on public.activity_log;

-- Ensure every org has a non-null invite code
update orgs set invite_code = gen_invite_code(display_name) where invite_code is null or btrim(invite_code) = '';
alter table public.orgs alter column invite_code set not null;

-- ---------- save_subscription requires invite code (applied in follow-up) ----------
-- See also live: save_subscription(..., p_invite_code text default null)

-- ---------- Follow-up 2026-08-02b: save_subscription + residual policies ----------
drop function if exists public.save_subscription(text, text, text, text, text, text);
drop function if exists public.save_subscription(text, text, text, text, text, text, text);

create function public.save_subscription(
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
declare v_org uuid;
begin
  v_org := _resolve_org_id(p_token);
  if v_org is null then raise exception 'invalid_token'; end if;
  if not _invite_matches(v_org, p_invite_code) then raise exception 'access_required'; end if;
  insert into push_subscriptions (endpoint,p256dh,auth,user_agent,device_id)
    values (p_endpoint,p_p256dh,p_auth,p_user_agent,p_device_id)
  on conflict (endpoint) do update set device_id=excluded.device_id, user_agent=excluded.user_agent;
  insert into push_org (endpoint, org_id) values (p_endpoint, v_org) on conflict do nothing;
end;
$$;

grant execute on function public.save_subscription(text, text, text, text, text, text, text) to anon, authenticated, service_role, public;
