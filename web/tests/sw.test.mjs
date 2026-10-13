import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const source = readFileSync(new URL('../dist/sw.js', import.meta.url), 'utf8');
const html = readFileSync(new URL('../dist/index.html', import.meta.url), 'utf8');
function runtime() {
  const handlers = {}, stores = new Map();
  let offline = false, claimed = false;
  const fetch = async request => {
    if (offline) throw new TypeError('offline');
    const path = typeof request === 'string' ? request : new URL(request.url).pathname;
    return new Response(path === '/' || path === '/index.html' ? html : 'asset:' + path);
  };
  const caches = {
    async open(name) {
      if (!stores.has(name)) stores.set(name, new Map());
      const store = stores.get(name);
      return { async addAll(paths) { for (const path of paths) store.set(path, await fetch(path)); }, async match(request) { const path = typeof request === 'string' ? request : new URL(request.url).pathname; return store.get(path)?.clone(); } };
    },
    async keys() { return [...stores.keys()]; },
    async delete(name) { return stores.delete(name); },
    async match(request) { for (const name of stores.keys()) { const match = await (await this.open(name)).match(request); if (match) return match; } }
  };
  vm.runInNewContext(source, { self: { location: { origin: 'http://localhost:8787' }, clients: { async claim() { claimed = true; } }, addEventListener(name, callback) { handlers[name] = callback; } }, URL, caches, fetch });
  return { handlers, stores, setOffline() { offline = true; }, claimed: () => claimed };
}
async function install(r) { let pending; r.handlers.install({ waitUntil(p) { pending = p; } }); await pending; }
function request(r, path, method = 'GET', mode = 'cors') { let pending; r.handlers.fetch({ request: { url: 'http://localhost:8787' + path, method, mode }, respondWith(p) { pending = p; } }); return pending; }

test('offline navigation and bundle assets load from the public shell cache', async () => {
  const r = runtime(); await install(r); r.setOffline();
  assert.equal(await (await request(r, '/', 'GET', 'navigate')).text(), html);
  const assets = [...html.matchAll(/(?:src|href)="(\/assets\/[^"?#]+)"/g)].map(m => m[1]);
  assert.ok(assets.length >= 2);
  for (const asset of assets) assert.equal(await (await request(r, asset)).text(), 'asset:' + asset);
});
test('API reads and commands are never intercepted or cached', async () => {
  const r = runtime(); await install(r); r.setOffline();
  assert.equal(request(r, '/api/v1/services'), undefined);
  assert.equal(request(r, '/api/v1/services/minecraft/control', 'POST'), undefined);
  assert.equal(request(r, '/other', 'POST'), undefined);
  for (const cache of r.stores.values()) assert.ok([...cache.keys()].every(key => !key.startsWith('/api/')));
});
test('activation removes old Hearth versions and preserves unrelated caches', async () => {
  const r = runtime(); r.stores.set('hearth-shell-old', new Map()); r.stores.set('unrelated-app', new Map()); await install(r);
  let pending; r.handlers.activate({ waitUntil(p) { pending = p; } }); await pending;
  assert.ok(!r.stores.has('hearth-shell-old')); assert.ok(r.stores.has('unrelated-app')); assert.ok(r.claimed());
});
