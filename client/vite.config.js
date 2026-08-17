import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

// During `npm run dev` the Vite server proxies everything the Express server
// owns, so the SPA and the API share an origin exactly like they do in prod.
const API_TARGET = process.env.API_TARGET || 'http://localhost:3000';

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    proxy: {
      '/api': API_TARGET,
      '/login': API_TARGET,
      '/logout': API_TARGET,
      '/auth': API_TARGET,
      '/oauth2callback': API_TARGET,
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    chunkSizeWarningLimit: 900,
  },
});
