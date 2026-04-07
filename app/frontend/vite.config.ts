import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    host: true, // Docker経由のアクセスを許可 (重要)
    port: 3000,
    watch: {
      usePolling: true, // WSL2でのホットリロードを確実にする
    },
  },
})