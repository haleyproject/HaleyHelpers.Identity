import { svelte } from '@sveltejs/vite-plugin-svelte';
import { defineConfig } from 'vite';

export default defineConfig({
  base: './',
  plugins: [svelte()],
  server: {
    host: '127.0.0.1',
    port: 7432,
    proxy: {
      '/admin/api': { target: 'http://127.0.0.1:7430' },
      '/api': { target: 'http://127.0.0.1:7430', rewrite: path => '/admin' + path }
    }
  },
  build: { outDir: '../HaleyIdentityHost/wwwroot/admin', emptyOutDir: true, sourcemap: false }
});
