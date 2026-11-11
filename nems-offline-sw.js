'use strict';
const CACHE='nems-offline-shell-v2';
const SHELL=['/offline','/nems-offline.js','/nems-offline-core.js'];
self.addEventListener('install',event=>{event.waitUntil(caches.open(CACHE).then(c=>c.addAll(SHELL)));});
self.addEventListener('activate',event=>{event.waitUntil(self.clients.claim());});
// Cache the public encoding shell ONLY, never authentication, API responses, user data or tokens.
self.addEventListener('fetch',event=>{
 const u=new URL(event.request.url);
 if(event.request.mode==='navigate'&&u.origin===self.location.origin&&u.pathname==='/'){
   event.respondWith(fetch(event.request).catch(async()=>{const cached=await (await caches.open(CACHE)).match('/offline');return cached||Response.error();}));return;
 }
 if(event.request.method!=='GET'||u.origin!==self.location.origin||!SHELL.includes(u.pathname))return;
 event.respondWith((async()=>{
   const cached=await (await caches.open(CACHE)).match(event.request);if(cached)return cached;
   const response=await fetch(event.request);if(response.ok){const c=await caches.open(CACHE);await c.put(event.request,response.clone());}return response;
 })());
});
