// filepath: c:\Users\pramu\kantin40_digital\static\js\sw.js
const CACHE_NAME = 'dimascash-v1';
const urlsToCache = [
    '/',
    '/dashboard',
    '/static/css/style.css',
    '/static/js/main.js',
    '/static/images/hanya_logo.png',
    '/static/icons/icon-192x192.png',
    '/static/icons/icon-512x512.png'
];

self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then((cache) => cache.addAll(urlsToCache))
    );
});

self.addEventListener('fetch', (event) => {
    event.respondWith(
        caches.match(event.request)
            .then((response) => response || fetch(event.request))
    );
});