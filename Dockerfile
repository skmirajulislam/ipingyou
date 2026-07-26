# ============================================================
#  iPingYou Zero-Knowledge Broker Server Dockerfile
# ============================================================
FROM node:22-alpine AS builder

WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev

COPY . .

FROM node:22-alpine
WORKDIR /app

COPY --chown=node:node --from=builder /app ./

ENV NODE_ENV=production
ENV PORT=3000

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://localhost:3000/health').then(r => r.ok ? process.exit(0) : process.exit(1)).catch(() => process.exit(1))"

USER node

CMD ["node", "src/server.js"]
