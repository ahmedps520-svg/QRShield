/*
  QRShield service worker
  - Caches the app shell so the scanner UI still works offline / installs as a PWA.
  - NETWORK-FIRST for same-origin files: every request tries the real network
    first, so a new deploy shows up immediately instead of being masked by an
    old cached copy. The cache is only used as a fallback when there's no
    network at all.
  - Deliberately does NOT register push, notification, or background-sync
    handlers — this app never needs to notify the user.
  - Never caches or intercepts requests to the destinations found inside
    scanned QR codes; it only manages this app's own static files.

  NOTE: bump CACHE_NAME (e.g. v2 -> v3) whenever you want to force every
  previously-installed copy of this app to drop its old offline cache.
*/

const CACHE_NAME = "qrshield-shell-v2";
const SHELL_FILES = [
  "./",
  "./index.html",
  "./style.css",
  "./app.js",
  "./manifest.json",
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
// live version, update the cache with whatever comes back, and only serve
// the cached copy if the network request fails outright (offline).
// Cross-origin requests (e.g. the jsQR CDN library) are left alone entirely.
self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET") return;

  const url = new URL(req.url);
  const isSameOrigin = url.origin === self.location.origin;
  if (!isSameOrigin) return;

  event.respondWith(
    fetch(req)
      .then((res) => {
        const copy = res.clone();
        caches.open(CACHE_NAME).then((cache) => cache.put(req, copy));
        return res;
      })
      .catch(() => caches.match(req))
  );
});
