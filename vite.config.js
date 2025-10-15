import { fileURLToPath, URL } from 'node:url'

import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { version } from 'node:os'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [vue()],
  base: '/cwe-visualization/',
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url))
    }
  }
})
