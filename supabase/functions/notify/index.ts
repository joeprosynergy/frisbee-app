// EasyGameRoster — push fan-out. Triggers send {type, game_id, ...}; this function
// reads the current roster and decides who gets what, targeting devices by device_id.
//   new_game : broadcast
//   signup   : milestone broadcasts (half full / 2 left / full), de-duped per game
//   removal  : bumped-in device → "you're in"; each waitlist device → "you're now #N"
//              (no double-notify); everyone else → general "a spot opened / someone left"
import * as webpush from "jsr:@negrel/webpush@0.5.0";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const FUNCTION_SECRET = Deno.env.get("FUNCTION_SECRET")!;
const VAPID_JWK = Deno.env.get("VAPID_JWK")!;
const VAPID_SUBJECT = Deno.env.get("VAPID_SUBJECT") ?? "mailto:joe@plyntr.com";
const SITE = "https://www.easygameroster.com";

const vapidKeys = await webpush.importVapidKeys(JSON.parse(VAPID_JWK), { extractable: false });
const appServer = await webpush.ApplicationServer.new({ contactInformation: VAPID_SUBJECT, vapidKeys });

const REST = `${SUPABASE_URL}/rest/v1`;
const H: Record<string, string> = { apikey: SERVICE_KEY, Authorization: `Bearer ${SERVICE_KEY}`, "Content-Type": "application/json" };
const rest = (path: string, init: RequestInit = {}) => fetch(`${REST}/${path}`, { ...init, headers: { ...H, ...(init.headers || {}) } });
const getJson = async (path: string) => (await rest(path)).json();

function fmtDate(d: string) {
  const dt = new Date(d + "T00:00:00Z");
  const days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
  const mons = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  return `${days[dt.getUTCDay()]}, ${mons[dt.getUTCMonth()]} ${dt.getUTCDate()}`;
}
function fmtTime(t: string) {
  const [h, m] = t.split(":").map(Number);
  const ap = h >= 12 ? "PM" : "AM";
  return `${h % 12 || 12}:${String(m).padStart(2, "0")} ${ap}`;
}

async function sendTo(subs: any[], payload: any, results: any) {
  const notif = JSON.stringify({ url: SITE, ...payload });
  for (const s of subs) {
    try {
      await appServer.subscribe({ endpoint: s.endpoint, keys: { p256dh: s.p256dh, auth: s.auth } }).pushTextMessage(notif, {});
      results.sent++;
    } catch (err: any) {
      if (err instanceof webpush.PushMessageError && (err.response.status === 404 || err.response.status === 410)) {
        results.removed++;
        await rest(`push_subscriptions?endpoint=eq.${encodeURIComponent(s.endpoint)}`, { method: "DELETE" });
      } else {
        results.errors.push(String(err?.statusCode || err).slice(0, 120));
      }
    }
  }
}

// returns true the FIRST time a milestone is recorded for a game (idempotent broadcast)
async function markMilestone(game_id: string, kind: string): Promise<boolean> {
  const r = await rest("game_notifications", { method: "POST", headers: { Prefer: "return=minimal" }, body: JSON.stringify({ game_id, kind }) });
  return r.status === 201; // 409 = already sent
}

Deno.serve(async (req) => {
  if (req.method !== "POST") return new Response("method", { status: 405 });
  let p: any;
  try { p = await req.json(); } catch { return new Response("bad json", { status: 400 }); }
  const { type, game_id, removed_at, secret, dry_run } = p || {};
  if (!secret || secret !== FUNCTION_SECRET) return new Response("unauthorized", { status: 401 });
  if (!type || !game_id) return new Response("missing", { status: 400 });

  const game = (await getJson(`games?id=eq.${game_id}&select=*`))?.[0];
  if (!game) return Response.json({ skip: "no game" });

  // Scope to THIS roster's subscribers only. push_org maps each subscription endpoint to its org,
  // so a game in one roster never notifies another roster's people.
  const orgRows = await getJson(`push_org?org_id=eq.${game.org_id}&select=endpoint`);
  const orgEndpoints = new Set((Array.isArray(orgRows) ? orgRows : []).map((r: any) => r.endpoint));
  const allSubs = await getJson(`push_subscriptions?select=endpoint,p256dh,auth,device_id`);
  const subs = (Array.isArray(allSubs) ? allSubs : []).filter((s: any) => orgEndpoints.has(s.endpoint));
  const results: any = { type, dry_run: !!dry_run, sent: 0, removed: 0, errors: [], breakdown: [] };
  if (!Array.isArray(subs) || subs.length === 0) return Response.json({ ...results, skip: "no subs" });
  const deliver = (s: any[], payload: any) => (dry_run ? Promise.resolve() : sendTo(s, payload, results));

  if (type === "new_game") {
    if (game.status !== "live") return Response.json({ skip: "not live" });
    await deliver(subs, { title: "New game posted", body: `${game.label} — ${fmtDate(game.game_date)} at ${fmtTime(game.game_time)}`, tag: `new-${game_id}` });
    results.breakdown.push({ new_game: subs.length });
    return Response.json(results);
  }

  const signups = await getJson(`signups?game_id=eq.${game_id}&select=player_name,created_at,device_id&order=created_at.asc`);
  const max = game.max_players;
  const count = signups.length;
  const roster = signups.slice(0, max);
  const waitlist = signups.slice(max);

  if (type === "signup") {
    const half = Math.ceil(max / 2);
    let kind = "", title = "", body = "";
    if (count === max) { kind = "full"; title = `${game.label} is full`; body = `All ${max} spots are taken — the waitlist is now open.`; }
    else if (count === max - 2 && max > 4) { kind = "two_left"; title = "Only 2 spots left!"; body = `${game.label} has just 2 spots left — grab one.`; }
    else if (count === half && max >= 4) { kind = "half"; title = `${game.label} is half full`; body = `${count}/${max} signed up — get your spot.`; }
    if (kind) {
      const fresh = dry_run ? true : await markMilestone(game_id, kind);
      if (fresh) {
        await deliver(subs, { title, body, tag: `${kind}-${game_id}` });
        results.breakdown.push({ milestone: kind, count, recipients: subs.length });
      } else {
        results.breakdown.push({ milestone: "already-sent", kind, count });
      }
    } else {
      results.breakdown.push({ milestone: "none", count });
    }
    return Response.json(results);
  }

  if (type === "removal") {
    const removedPos = signups.filter((s: any) => s.created_at < removed_at).length + 1; // 1-based in the pre-removal list
    const wasRosterRemoval = removedPos <= max;
    const bumped = (wasRosterRemoval && count >= max) ? roster[max - 1] : null; // former W1, now in the roster

    const targeted = new Set<string>();

    // 1) the bumped-in player's device(s)
    if (bumped && bumped.device_id) {
      const ds = subs.filter((s: any) => s.device_id === bumped.device_id);
      if (ds.length) {
        targeted.add(bumped.device_id);
        await deliver(ds, { title: "You're in! 🎉", body: `A spot opened in ${game.label} — ${bumped.player_name}, you're now playing.`, tag: `in-${game_id}` });
        results.breakdown.push({ bumped: bumped.player_name, device_id: bumped.device_id, devices: ds.length });
      }
    }

    // 2) each remaining waitlist player's device(s) → position-specific, one per device
    for (let i = 0; i < waitlist.length; i++) {
      const w = waitlist[i];
      if (!w.device_id || targeted.has(w.device_id)) continue;
      const ds = subs.filter((s: any) => s.device_id === w.device_id && !targeted.has(s.device_id));
      if (!ds.length) continue;
      targeted.add(w.device_id);
      const pos = i + 1;
      await deliver(ds, { title: `Waitlist update — you're #${pos}`, body: `Someone left ${game.label}. ${w.player_name}, you're now #${pos} on the waitlist.`, tag: `wl-${game_id}` });
      results.breakdown.push({ waitlist: w.player_name, pos, device_id: w.device_id });
    }

    // 3) everyone else → general
    const general = subs.filter((s: any) => !s.device_id || !targeted.has(s.device_id));
    if (general.length) {
      const spotsLeft = Math.max(0, max - count);
      const title = spotsLeft > 0 ? `A spot opened in ${game.label}` : `Someone left ${game.label}`;
      const body = spotsLeft > 0 ? `${spotsLeft} spot${spotsLeft > 1 ? "s" : ""} now open in ${game.label}.` : `Someone just left ${game.label}.`;
      await deliver(general, { title, body, tag: `open-${game_id}` });
      results.breakdown.push({ general: general.length });
    }
    return Response.json(results);
  }

  return Response.json({ skip: "unknown type" });
});
