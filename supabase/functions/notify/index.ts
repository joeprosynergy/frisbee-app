// EasyGameRoster — web-push sender.
// Called server-side only (by DB triggers) with a shared secret. Fans a single
// notification out to every push subscription. Stateless re: business logic:
// the DB triggers decide WHEN and build the title/body; this just delivers.
import webpush from 'npm:web-push@3.6.7'

const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!
const SERVICE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
const FUNCTION_SECRET = Deno.env.get('FUNCTION_SECRET')!
const VAPID_PUBLIC = Deno.env.get('VAPID_PUBLIC_KEY')!
const VAPID_PRIVATE = Deno.env.get('VAPID_PRIVATE_KEY')!
const VAPID_SUBJECT = Deno.env.get('VAPID_SUBJECT') || 'mailto:joe@plyntr.com'

webpush.setVapidDetails(VAPID_SUBJECT, VAPID_PUBLIC, VAPID_PRIVATE)

const sbHeaders = {
  apikey: SERVICE_KEY,
  Authorization: `Bearer ${SERVICE_KEY}`,
  'Content-Type': 'application/json',
}

Deno.serve(async (req) => {
  if (req.method !== 'POST') return new Response('method not allowed', { status: 405 })

  let payload: any
  try { payload = await req.json() } catch { return new Response('bad json', { status: 400 }) }
  const { title, body, url, tag, secret } = payload || {}

  if (!secret || secret !== FUNCTION_SECRET) return new Response('unauthorized', { status: 401 })
  if (!title) return new Response('missing title', { status: 400 })

  const res = await fetch(
    `${SUPABASE_URL}/rest/v1/push_subscriptions?select=endpoint,p256dh,auth`,
    { headers: sbHeaders }
  )
  const subs = await res.json()
  if (!Array.isArray(subs) || subs.length === 0) return Response.json({ sent: 0, removed: 0 })

  const notif = JSON.stringify({
    title,
    body: body || '',
    url: url || 'https://www.easygameroster.com',
    tag: tag || 'egr',
  })

  let sent = 0, removed = 0
  await Promise.all(subs.map(async (s: any) => {
    try {
      await webpush.sendNotification(
        { endpoint: s.endpoint, keys: { p256dh: s.p256dh, auth: s.auth } },
        notif
      )
      sent++
    } catch (e: any) {
      const code = e?.statusCode
      if (code === 404 || code === 410) {
        // Subscription is dead — clean it up so the list stays healthy.
        removed++
        await fetch(
          `${SUPABASE_URL}/rest/v1/push_subscriptions?endpoint=eq.${encodeURIComponent(s.endpoint)}`,
          { method: 'DELETE', headers: sbHeaders }
        )
      }
    }
  }))

  return Response.json({ sent, removed })
})
