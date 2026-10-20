import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    host: true,            // doosre devices se access ke liye
    port: 5173,            // admin-panel mein 5174 rakho
    proxy: {
      '/login':  'http://localhost:8000',
      '/reset-password': 'http://localhost:8000',
      '/logout': 'http://localhost:8000',
      '/me':     'http://localhost:8000',
      '/admin':  'http://localhost:8000',
      '/audit':  'http://localhost:8000',
      '/health': 'http://localhost:8000',
    },
  },
})