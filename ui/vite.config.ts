import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { '@': path.resolve(__dirname, './src') },
  },
  server: {
    port: 3100,
    proxy: {
      '/api': 'http://localhost:8000',
      '/auth': 'http://localhost:8000',
    },
  },
  build: {
    outDir: 'dist',
    // Disable source maps in production to avoid exposing TypeScript source,
    // variable names, API surface, and code comments (issue #21 / LOW).
    sourcemap: process.env.NODE_ENV !== 'production',
  },
})
