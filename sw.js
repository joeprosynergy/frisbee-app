// EasyGameRoster service worker.
// Push + a NETWORK-FIRST app shell. The fetch handler ONLY touches navigations
// (the HTML document): it fetches fresh from the network so installed users pick up
// new HTML promptly, and falls back to the cached copy only when offline. It never
// intercepts the Supabase API calls or other resources — that interception was what
// made mobile loads slow/hang, so it stays scoped to navigations only.
const CACHE = 'egr-v2';

self.addEventListener('install', (event) => {
  self.skipWaiting();
  event.waitUntil(caches.open(CACHE).then((c) => c.add('/index.html')).catch(() => {}));
});

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)));
    await self.clients.claim();
  })());
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;
  const isNav = req.mode === 'navigate' || (req.headers.get('accept') || '').includes('text/html');
  if (!isNav) return; // API calls / other assets: pass straight through, never intercepted
  event.respondWith((async () => {
    try {
      const fresh = await fetch(req);
      try { const c = await caches.open(CACHE); c.put('/index.html', fresh.clone()); } catch (e) {}
      return fresh;
    } catch (e) {
      const cached = await caches.match('/index.html');
      return cached || Response.error();
    }
  })());
});

self.addEventListener('push', (event) => {
  let data = {};
  try { data = event.data ? event.data.json() : {}; } catch (e) {}
  const title = data.title || 'Game Roster';
  event.waitUntil(self.registration.showNotification(title, {
    body: data.body || '',
    icon: '/icon-192.png',
    badge: '/icon-192.png',
    tag: data.tag || 'egr',
    data: { url: data.url || 'https://www.easygameroster.com' },
  }));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const url = (event.notification.data && event.notification.data.url) || 'https://www.easygameroster.com';
  event.waitUntil((async () => {
    const wins = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const c of wins) { if ('focus' in c) return c.focus(); }
    if (self.clients.openWindow) return self.clients.openWindow(url);
  })());
});
