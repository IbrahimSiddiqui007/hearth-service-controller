import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';

export default defineConfig({
  plugins: [react(), { name: 'version-shell-cache', apply: 'build', closeBundle() {
    const output = resolve('dist');
    const version = createHash('sha256').update(readFileSync(resolve(output, 'index.html'))).digest('hex').slice(0, 12);
    const worker = resolve(output, 'sw.js');
    writeFileSync(worker, readFileSync(worker, 'utf8').replace('__BUILD_VERSION__', version));
  } }],
  server: { proxy: { '/api': 'http://127.0.0.1:8787' } },
});
