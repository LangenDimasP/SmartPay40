const CACHE_NAME = "kantin40-cache-v1";
const urlsToCache = [
  "/",
  "/penjual/dashboard",
  "/static/styles/register.css",
  // Tambahkan file statis lain yang penting
];

// Install service worker dan cache file
self.addEventListener("install", event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(urlsToCache))
  );
});

// Fetch dari cache jika offline
self.addEventListener("fetch", event => {
  event.respondWith(
    caches.match(event.request)
      .then(response => response || fetch(event.request))
  );
});