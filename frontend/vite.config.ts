import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: parseInt(process.env.VITE_PORT || '6001', 10),
    proxy: {
      '/api': {
        target: process.env.VITE_BACKEND_URL || 'http://localhost:6000',
        changeOrigin: true,
      },
    },
  },
})
