# Proof Gatekeeper agent — deployable image (Node 20)
FROM node:20-slim

WORKDIR /app

# Dependencies first (better layer caching).
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

# Application code. The verification key is in the repo; the two binary
# circuit artifacts (wasm, zkey) are downloaded at build time from the
# official public endpoint, so the image never needs them committed.
COPY src ./src
COPY circuits/gatekeeper_vkey.json ./circuits/

RUN apt-get update \
  && apt-get install -y --no-install-recommends curl ca-certificates \
  && rm -rf /var/lib/apt/lists/* \
  && curl -fsSL -o circuits/gatekeeper.wasm https://agentgames.zkverify.io/circuits/gatekeeper.wasm \
  && curl -fsSL -o circuits/gatekeeper_final.zkey https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey \
  && ls -la circuits/

ENV NODE_ENV=production
# The server listens on $PORT (default 3000) and 0.0.0.0; hosts like
# Railway and Cloady inject PORT themselves.
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD curl -fsS http://localhost:${PORT:-3000}/health || exit 1

CMD ["node", "src/index.js"]
