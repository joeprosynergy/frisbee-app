// EasyGameRoster — web-push sender.
// Uses @negrel/webpush (Deno-native; works in the edge runtime, unlike npm:web-push).
// Called server-side only (by DB triggers) with a shared secret. The triggers decide
// WHEN and build the title/body; this just fans one notification out to every device.
import * as webpush from "jsr:@negrel/webpush@0.5.0";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const FUNCTION_SECRET = Deno.env.get("FUNCTION_SECRET")!;
const VAPID_JWK = Deno.env.get("VAPID_JWK")!;
const VAPID_SUBJECT = Deno.env.get("VAPID_SUBJECT") ?? "mailto:joe@plyntr.com";

const vapidKeys = await webpush.importVapidKeys(JSON.parse(VAPID_JWK), { extractable: false });
const appServer = await webpush.ApplicationServer.new({
  contactInformation: VAPID_SUBJECT,
  vapidKeys,
});

const sbHeaders = {
  apikey: SERVICE_KEY,
  Authorization: `Bearer ${SERVICE_KEY}`,
  "Content-Type": "application/json",
};

Deno.serve(async (req) => {
  if (req.method !== "POST") return new Response("method not allowed", { status: 405 });

  let payload: any;
  try { payload = await req.json(); } catch { return new Response("bad json", { status: 400 }); }
  const { title, body, url, tag, secret } = payload || {};

  if (!secret || secret !== FUNCTION_SECRET) return new Response("unauthorized", { status: 401 });
  if (!title) return new Response("missing title", { status: 400 });

  const res = await fetch(
    `${SUPABASE_URL}/rest/v1/push_subscriptions?select=endpoint,p256dh,auth`,
    { headers: sbHeaders }
  );
  const subs = await res.json();
  if (!Array.isArray(subs) || subs.length === 0) return Response.json({ sent: 0, removed: 0, errors: [] });

  const notif = JSON.stringify({
    title,
    body: body || "",
    url: url || "https://www.easygameroster.com",
    tag: tag || "egr",
  });

  let sent = 0, removed = 0;
  const errors: string[] = [];
  for (const s of subs) {
    try {
      const subscriber = appServer.subscribe({
        endpoint: s.endpoint,
        keys: { p256dh: s.p256dh, auth: s.auth },
      });
      await subscriber.pushTextMessage(notif, {});
      sent++;
    } catch (err) {
      let status = 0;
      if (err instanceof webpush.PushMessageError) {
        status = err.response.status;
        if (status === 404 || status === 410) {
          // dead subscription — clean it up
          removed++;
          await fetch(
            `${SUPABASE_URL}/rest/v1/push_subscriptions?endpoint=eq.${encodeURIComponent(s.endpoint)}`,
            { method: "DELETE", headers: sbHeaders }
          );
        }
      }
      errors.push(String(status || err).slice(0, 140));
    }
  }

  return Response.json({ sent, removed, errors });
});
