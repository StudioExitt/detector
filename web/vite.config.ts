import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

const withTrailingSlash = (p: string) => (p.endsWith('/') ? p : `${p}/`)

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), 'VITE_')
  const base = withTrailingSlash(env.VITE_APP_BASE_URL || '/')
  const apiBase = env.VITE_API_BASE_URL || '/api/v1'
  const proxyTarget = env.VITE_PROXY_TARGET || 'http://localhost:8088'

  return {
    base,
    plugins: [react(), tailwindcss()],
    server: {
      // VITE_API_BASE_URL 이 상대경로일 때만 개발용 proxy 사용
      proxy: apiBase.startsWith('/') ? { [apiBase]: { target: proxyTarget, changeOrigin: true } } : undefined,
    },
    build: {
      outDir: 'dist',
      emptyOutDir: true,
      rollupOptions: {
        output: {
          // 해시 없이 고정된 파일명 사용
          entryFileNames: 'assets/[name].js',
          chunkFileNames: 'assets/[name].js',
          assetFileNames: 'assets/[name][extname]',
        },
      },
    },
  }
})
