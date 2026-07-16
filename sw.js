/*
  QRShield service worker
  - Caches the app shell so the scanner UI still works offline / installs as a PWA.
  - NETWORK-FIRST for same-origin files: every request tries the real network
    first, so a new deploy shows up immediately instead of being masked by an
    old cached copy. The cache is only used as a fallback when there's no
    network at all.
  - Only successful (res.ok) responses are cached — error pages (404/500)
    are never saved, so a bad deploy can't get stuck in the offline cache.
  - Falls back to a dedicated offline.html for full-page navigations when
    both the network and the cache come up empty.
  - Deliberately does NOT register push, notification, or background-sync
    handlers — this app never needs to notify the user.
  - Never caches or intercepts requests to the destinations found inside
    scanned QR codes; it only manages this app's own static files.

  NOTE: bump CACHE_NAME (e.g. v3 -> v4) whenever you want to force every
  previously-installed copy of this app to drop its old offline cache.
*/

const CACHE_NAME = "qrshield-shell-v4";
const SHELL_FILES = [
  "./",
  "./index.html",
  "./style.css",
  "./app.js",
  "./manifest.json",
  "./offline.html",
  "./icons/icon-192.png",
  "./icons/icon-512.png",
  "./icons/favicon-32.png",
  "./icons/favicon-16.png",
  "./icons/apple-touch-icon.png"
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => cache.addAll(SHELL_FILES))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((names) =>
      Promise.all(
        names.filter((n) => n !== CACHE_NAME).map((n) => caches.delete(n))
      )
    ).then(() => self.clients.claim())
  );
});

// Network-first for same-origin app-shell files: always try to fetch the
// live version, cache it only if the response is actually OK, and fall
// back to the cached copy (or a dedicated offline page for navigations)
// only if the network request fails outright.
self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET") return;

  const url = new URL(req.url);
  const isSameOrigin = url.origin === self.location.origin;
  if (!isSameOrigin) return; // cross-origin (e.g. jsQR CDN) passes through untouched

  event.respondWith(
    fetch(req)
      .then((res) => {
        if (res && res.ok) {
          const copy = res.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(req, copy));
        }
        return res;
      })
      .catch(() =>
        caches.match(req).then((cached) => {
          if (cached) return cached;
          if (req.mode === "navigate") return caches.match("./offline.html");
          return undefined;
        })
      )
  );
});
