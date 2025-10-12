const CACHE_NAME = 'fixmyerror-net-v1.0.0';
const CACHE_URLS = [
  '/',
  '/index.html',
  '/errors.json',
  '/manifest.json',
  'https:
];


self.addEventListener('install', event => {
  console.log('Service Worker: Installing...');
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        console.log('Service Worker: Caching files');
        return cache.addAll(CACHE_URLS);
      })
      .then(() => {
        console.log('Service Worker: Installation complete');
        return self.skipWaiting();
      })
      .catch(err => {
        console.error('Service Worker: Cache failed:', err);
      })
  );
});


self.addEventListener('activate', event => {
  console.log('Service Worker: Activating...');
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.map(cacheName => {
          if (cacheName !== CACHE_NAME) {
            console.log('Service Worker: Deleting old cache:', cacheName);
            return caches.delete(cacheName);
          }
        })
      );
    }).then(() => {
      console.log('Service Worker: Activation complete');
      return self.clients.claim();
    })
  );
});


self.addEventListener('fetch', event => {
  
  if (event.request.method !== 'GET') {
    return;
  }

  
  if (!event.request.url.startsWith(self.location.origin)) {
    
    if (!event.request.url.includes('cdn.jsdelivr.net')) {
      return;
    }
  }

  event.respondWith(
    caches.match(event.request)
      .then(response => {
        
        if (response) {
          console.log('Service Worker: Serving from cache:', event.request.url);
          return response;
        }

        
        console.log('Service Worker: Fetching from network:', event.request.url);
        return fetch(event.request).then(response => {
          
          if (!response || response.status !== 200 || response.type !== 'basic') {
            return response;
          }

          
          const responseToCache = response.clone();

          
          caches.open(CACHE_NAME)
            .then(cache => {
              cache.put(event.request, responseToCache);
            });

          return response;
        });
      })
      .catch(err => {
        console.error('Service Worker: Fetch failed:', err);
        
        
        if (event.request.headers.get('accept').includes('text/html')) {
          return caches.match('/index.html');
        }
        
        
        throw err;
      })
  );
});


self.addEventListener('sync', event => {
  if (event.tag === 'background-sync') {
    console.log('Service Worker: Background sync triggered');
    
  }
});


self.addEventListener('push', event => {
  if (event.data) {
    const data = event.data.json();
    const options = {
      body: data.body,
      icon: '/manifest.json',
      badge: '/manifest.json',
      vibrate: [100, 50, 100],
      data: {
        url: data.url || '/'
      }
    };

    event.waitUntil(
      self.registration.showNotification(data.title, options)
    );
  }
});


self.addEventListener('notificationclick', event => {
  event.notification.close();
  
  event.waitUntil(
    clients.openWindow(event.notification.data.url || '/')
  );
});


self.addEventListener('message', event => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});

console.log('Service Worker: Script loaded');