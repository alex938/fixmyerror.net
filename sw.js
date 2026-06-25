// Service worker for fixmyerror.net
// Bump CACHE_NAME on every release so clients pick up new HTML/JS.
const CACHE_NAME = 'fixmyerror-net-v2.1.0';
const CORE_ASSETS = [
  '/',
  '/index.html',
  '/embedded-data.js',
  '/manifest.json',
  '/feed.xml',
  'https://cdn.jsdelivr.net/npm/fuse.js@6.6.2/dist/fuse.min.js'
];

// Install: pre-cache core assets. Use individual put() calls so a single
// failed fetch can't reject the whole install (addAll is all-or-nothing).
self.addEventListener('install', event => {
  event.waitUntil(
    (async () => {
      const cache = await caches.open(CACHE_NAME);
      await Promise.all(
        CORE_ASSETS.map(async (url) => {
          try {
            const response = await fetch(url, { cache: 'no-cache' });
            if (response && response.ok) {
              await cache.put(url, response);
            }
          } catch (err) {
            console.warn('SW: failed to pre-cache', url, err);
          }
        })
      );
      await self.skipWaiting();
    })()
  );
});

// Activate: purge old caches.
self.addEventListener('activate', event => {
  event.waitUntil(
    (async () => {
      const names = await caches.keys();
      await Promise.all(
        names.filter(n => n !== CACHE_NAME).map(n => caches.delete(n))
      );
      await self.clients.claim();
    })()
  );
});

// Fetch strategy:
// - HTML navigations: network-first (so deployments are picked up quickly)
// - Same-origin static assets + the pinned CDN script: stale-while-revalidate
// - Everything else: passthrough
self.addEventListener('fetch', event => {
  const request = event.request;
  if (request.method !== 'GET') return;

  const url = new URL(request.url);
  const isSameOrigin = url.origin === self.location.origin;
  const isPinnedCdn =
    url.host === 'cdn.jsdelivr.net' && url.pathname.includes('/fuse.js@6.6.2/');
  if (!isSameOrigin && !isPinnedCdn) return;

  const acceptHeader = request.headers.get('accept') || '';
  const isHtml =
    request.mode === 'navigate' || acceptHeader.includes('text/html');

  if (isHtml) {
    event.respondWith(networkFirst(request));
  } else {
    event.respondWith(staleWhileRevalidate(request));
  }
});

async function networkFirst(request) {
  const cache = await caches.open(CACHE_NAME);
  try {
    const fresh = await fetch(request);
    if (fresh && fresh.ok) {
      cache.put(request, fresh.clone()).catch(() => {});
    }
    return fresh;
  } catch (err) {
    const cached = await cache.match(request);
    if (cached) return cached;
    const fallback = await cache.match('/index.html');
    if (fallback) return fallback;
    throw err;
  }
}

async function staleWhileRevalidate(request) {
  const cache = await caches.open(CACHE_NAME);
  const cached = await cache.match(request);
  const networkFetch = fetch(request)
    .then(response => {
      // Only cache successful, non-opaque responses.
      if (response && response.ok && response.type !== 'opaque') {
        cache.put(request, response.clone()).catch(() => {});
      }
      return response;
    })
    .catch(err => {
      console.warn('SW: network failed for', request.url, err);
      return cached;
    });
  return cached || networkFetch;
}

// Push notifications (defensive against non-JSON payloads).
self.addEventListener('push', event => {
  if (!event.data) return;

  let data;
  try {
    data = event.data.json();
  } catch (err) {
    data = { title: 'FixMyError.net', body: event.data.text() };
  }

  const title = data.title || 'FixMyError.net';
  const options = {
    body: data.body || '',
    icon: '/icon-192.png',
    badge: '/icon-192.png',
    vibrate: [100, 50, 100],
    data: { url: data.url || '/' }
  };

  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  const targetUrl = (event.notification.data && event.notification.data.url) || '/';
  event.waitUntil(self.clients.openWindow(targetUrl));
});

self.addEventListener('message', event => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});
