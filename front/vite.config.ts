import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, '..', '')
  const agentPort = env.AGENT_PORT || '8000'

  // Listen port of the dev server. A privileged port (e.g. 443) needs sudo / setcap.
  const frontendPort = Number(env.FRONTEND_PORT || '5173')

  // Vite validates the Host header by default, so hostnames other than localhost must be
  // explicitly allowed. Comma-separated.
  // e.g. FRONTEND_ALLOWED_HOSTS=redagent.lab.example,10.0.0.10
  const allowedHostsRaw = (env.FRONTEND_ALLOWED_HOSTS || '').trim()
  const allowedHosts = allowedHostsRaw
    ? allowedHostsRaw.split(',').map((s) => s.trim()).filter(Boolean)
    : undefined

  // Client-side port for the HMR WebSocket when the dev server sits behind a reverse proxy
  // that terminates on a different port than server.port.
  const hmrClientPort = env.FRONTEND_HMR_CLIENT_PORT
    ? Number(env.FRONTEND_HMR_CLIENT_PORT)
    : undefined

  return {
    plugins: [react(), tailwindcss()],
    envDir: '..',
    server: {
      port: frontendPort,
      strictPort: true,      // Fail rather than silently falling back to another port
      host: true,            // Listen on 0.0.0.0 (reachable from other hosts on the network)
      ...(allowedHosts ? { allowedHosts } : {}),
      ...(hmrClientPort
        ? { hmr: { clientPort: hmrClientPort } }
        : {}),
      proxy: {
        '/api': {
          target: `http://localhost:${agentPort}`,
          changeOrigin: true,
        },
        '/threads': {
          target: `http://localhost:${agentPort}`,
          changeOrigin: true,
        },
        '/health': {
          target: `http://localhost:${agentPort}`,
          changeOrigin: true,
        },
      },
    },
  }
})
