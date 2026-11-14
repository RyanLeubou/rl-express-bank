import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// Dans Docker, la SPA est servie derrière Caddy (https://bank.localhost) :
// le rechargement à chaud passe par le port 443 en WebSocket sécurisé.
const inDocker = process.env.VITE_IN_DOCKER === "1";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  // node_modules appartient à root dans l'image (npm ci) : le cache de pré-bundling
  // doit vivre ailleurs pour l'utilisateur node
  cacheDir: inDocker ? "/tmp/vite" : undefined,
  server: {
    host: "0.0.0.0",
    port: 5173,
    strictPort: true,
    allowedHosts: ["bank.localhost", "localhost", "frontend"],
    hmr: inDocker ? { clientPort: 443, protocol: "wss" } : undefined,
    // Hors Docker (npm run dev sur l'hôte), l'API locale est jointe par proxy
    proxy: inDocker ? undefined : { "/api": process.env.VITE_API_PROXY_TARGET ?? "http://localhost:8000" },
  },
  build: { sourcemap: false, target: "es2022" },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    css: false,
  },
});
