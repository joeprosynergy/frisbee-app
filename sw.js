// EasyGameRoster service worker — web push + installability.
// Intentionally does NO caching: a no-op fetch handler satisfies the installability
// criterion while every request still goes to the network, so deploys are never stale
// and rosters are never served from a cache.
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));
self.addEventListener('fetch', () => {});

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
