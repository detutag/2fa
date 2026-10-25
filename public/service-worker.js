/* 2FA 驗證器 Service Worker v2.0.0
 * 快取策略：
 * - 導覽請求 / 同源靜態資源：network-first，失敗時回退快取（確保更新即時生效、離線可用）
 * - /api/*：僅網路，離線時回傳明確的 503 JSON
 * - 安裝時預快取應用殼；版本變更時自動清理舊快取
 */
'use strict';

const CACHE_VERSION = 'v2.0.0';
const STATIC_CACHE = `2fa-static-${CACHE_VERSION}`;
const RUNTIME_CACHE = `2fa-runtime-${CACHE_VERSION}`;

const PRECACHE_URLS = [
  '/',
  '/index.html',
  '/app.js',
  '/vendor/jsQR.js',
  '/manifest.json',
  '/icons/icon.svg'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(STATIC_CACHE)
      .then((cache) => cache.addAll(PRECACHE_URLS))
      .catch((error) => {
        console.error('[SW] Precache failed:', error);
      })
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((cacheNames) => Promise.all(
        cacheNames.map((cacheName) => {
          if (cacheName !== STATIC_CACHE && cacheName !== RUNTIME_CACHE) {
            return caches.delete(cacheName);
          }
          return Promise.resolve();
        })
      ))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const { request } = event;
  if (request.method !== 'GET') return;

  const url = new URL(request.url);

  // 非同源請求：直接走網路（本應用無外部依賴）
  if (url.origin !== location.origin) return;

  // API 請求：僅網路，離線時回傳 503 JSON
  if (url.pathname.startsWith('/api/')) {
    event.respondWith(
      fetch(request).catch(() => new Response(
        JSON.stringify({ error: 'Network unavailable', offline: true }),
        {
          status: 503,
          statusText: 'Service Unavailable',
          headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }
        }
      ))
    );
    return;
  }

  // 靜態資源與導覽：network-first + 快取回退
  event.respondWith(
    fetch(request)
      .then((response) => {
        if (response && response.status === 200 && response.type === 'basic') {
          const responseToCache = response.clone();
          caches.open(RUNTIME_CACHE).then((cache) => {
            cache.put(request, responseToCache);
          }).catch(() => { /* 配額不足時忽略 */ });
        }
        return response;
      })
      .catch(async () => {
        // 離線：先查快取
        const cached = await caches.match(request);
        if (cached) return cached;
        // 導覽請求 → 回退到應用殼
        if (request.mode === 'navigate') {
          const shell = await caches.match('/index.html') || await caches.match('/');
          if (shell) return shell;
          return new Response('離線且無快取可用', {
            status: 503,
            statusText: 'Service Unavailable',
            headers: { 'Content-Type': 'text/plain; charset=utf-8' }
          });
        }
        return new Response('', { status: 503, statusText: 'Service Unavailable' });
      })
  );
});

self.addEventListener('message', (event) => {
  if (!event.data) return;
  if (event.data.type === 'CLEAR_CACHE') {
    event.waitUntil(
      caches.keys().then((cacheNames) => Promise.all(
        cacheNames.map((cacheName) => caches.delete(cacheName))
      ))
    );
  }
  if (event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});
