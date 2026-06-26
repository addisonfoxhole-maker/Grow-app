const CACHE = "addison-garden-v1";
const ASSETS = ["./","./index.html","./manifest.webmanifest","./icon-192.png","./icon-512.png","./apple-touch-icon-180.png"];
self.addEventListener("install", e => { e.waitUntil(caches.open(CACHE).then(c => c.addAll(ASSETS)).then(() => self.skipWaiting())); });
self.addEventListener("activate", e => { e.waitUntil(caches.keys().then(ks => Promise.all(ks.map(k => k !== CACHE && caches.delete(k)))).then(() => self.clients.claim())); });
self.addEventListener("fetch", e => {
  const r = e.request; if (r.method !== "GET") return;
  e.respondWith(caches.match(r).then(c => c || fetch(r).then(resp => { const cp = resp.clone(); caches.open(CACHE).then(c2 => c2.put(r, cp)); return resp; }).catch(() => caches.match("./index.html"))));
});
