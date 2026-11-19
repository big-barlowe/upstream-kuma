// The service worker: only for Web push (src/webpush.js). It shows each push
// as a notification and, when one is tapped, opens the monitor in the app.
// No fetch handler: nothing is cached, the app loads as it always does.

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));

self.addEventListener('push', (e) => {
  let d;
  try {
    d = e.data.json();
  } catch {
    d = { title: 'Upstream Kuma', body: e.data ? e.data.text() : '' };
  }
  // every push must show something (iOS stops delivering otherwise)
  e.waitUntil(self.registration.showNotification(d.title || 'Upstream Kuma', {
    body: d.body || '',
    // a monitor's "back up" replaces its "down", and still alerts
    tag: d.tag,
    renotify: Boolean(d.tag),
    timestamp: d.time,
    icon: 'icon-192.png',
    badge: 'icon-192.png',
    requireInteraction: d.level === 'urgent',
    data: { url: d.url || '#/' },
  }));
});

self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  const hash = e.notification.data?.url || '#/';
  e.waitUntil((async () => {
    const wins = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    const app = wins.find((w) => new URL(w.url).pathname.startsWith(new URL(self.registration.scope).pathname));
    if (app) {
      await app.focus();
      app.postMessage({ open: hash }); // app.js moves to it
      return;
    }
    await self.clients.openWindow(new URL(hash, self.registration.scope).href);
  })());
});
