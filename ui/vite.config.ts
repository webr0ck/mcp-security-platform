import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3100,
    proxy: {
      '/api': { target: 'https://localhost', secure: false },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
  },
})
