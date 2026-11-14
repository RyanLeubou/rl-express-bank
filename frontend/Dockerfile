# =====================================================================
# RL EXPRESS BANK — image frontend
#   target dev  : serveur Vite, rechargement à chaud (code monté en volume)
#   target prod : build statique servi par Caddy avec une CSP stricte
# =====================================================================
FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

FROM deps AS dev
COPY . .
USER node
EXPOSE 5173
CMD ["npm", "run", "dev"]

FROM deps AS build
COPY . .
RUN npm run build

FROM caddy:2-alpine AS prod
COPY Caddyfile.prod /etc/caddy/Caddyfile
COPY --from=build /app/dist /srv
EXPOSE 5173
