/* Addison Garden service worker — network-first, self-updating.
   Replaces the old cache-first worker that caused devices to stick on an old version. */
const CACHE = "addison-garden-v18";
const SHELL = ["./","./index.html","./manifest.webmanifest","./icon-192.png","./icon-512.png","./apple-touch-icon-180.png"];

self.addEventListener("install", e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", e => {
  // Purge every old cache (this is what clears a device stuck on an old version).
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.map(k => k !== CACHE ? caches.delete(k) : null)))
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", e => {
  const req = e.request;
  if (req.method !== "GET") return;
  // Never cache the sync API — it must always hit the live server.
  let path = "";
  try { path = new URL(req.url).pathname; } catch (_) {}
  if (path.indexOf("/api/") === 0) return;
  // Network-first: always try the live version, fall back to cache when offline.
  e.respondWith(
    fetch(req).then(resp => {
      const copy = resp.clone();
      caches.open(CACHE).then(c => c.put(req, copy)).catch(() => {});
      return resp;
    }).catch(() => caches.match(req).then(hit => hit || caches.match("./index.html")))
  );
});
