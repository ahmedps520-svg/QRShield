/*
  QRShield service worker
  - Caches the app shell so the scanner UI works offline / installs as a PWA.
  - Deliberately does NOT register push, notification, or background-sync
    handlers — this app never needs to notify the user.
  - Never caches or intercepts requests to the destinations found inside
    scanned QR codes; it only manages this app's own static files.
*/

const CACHE_NAME = "qrshield-shell-v1";
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

// Cache-first for same-origin app-shell files, network-first fallback for
// anything else (e.g. the jsQR CDN script), never for cross-origin
// destinations a user might choose to open from a scan result.
self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET") return;

  const url = new URL(req.url);
  const isSameOrigin = url.origin === self.location.origin;

  if (isSameOrigin) {
    event.respondWith(
      caches.match(req).then((cached) => {
        if (cached) return cached;
        return fetch(req).then((res) => {
          const copy = res.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(req, copy));
          return res;
        }).catch(() => cached);
      })
    );
  }
  // Cross-origin requests (e.g. the jsQR CDN library) fall through to the
  // network normally; nothing scanned is ever proxied through here.
});
