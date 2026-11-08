# The reference broker, for self-hosting (SELF-HOST.md). Build from the repository root, because the broker reads
# the specification's schemas at run time:
#
#   docker build -f reference/Dockerfile -t reference-broker .
#
# Node runs the TypeScript sources directly (type stripping), so there is no build step and no dev dependency.

FROM node:22.22.2-alpine3.22 AS deps
WORKDIR /app/reference
COPY reference/package.json reference/package-lock.json reference/.npmrc ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force

FROM node:22.22.2-alpine3.22
# The broker (reference/) is licensed under FSL-1.1-ALv2 (reference/LICENSE.md); the specification's schemas it reads,
# under Apache-2.0 (the repository's LICENSE, which goes into the image as schemas/LICENSE, next to the schemas).
LABEL org.opencontainers.image.title="ALP reference broker" \
      org.opencontainers.image.source="https://github.com/AgentLiaisonProtocol/agentliaisonprotocol" \
      org.opencontainers.image.licenses="FSL-1.1-ALv2 AND Apache-2.0"
# Security events go to standard output for the container's log driver; ALP_SECURITY_EVENTS=file keeps
# security-events.jsonl in /data instead.
ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=8080 \
    WEB_HOST=0.0.0.0 \
    WEB_PORT=8081 \
    ALP_DATA_DIR=/data \
    ALP_SECURITY_EVENTS=stdout
WORKDIR /app
COPY schemas ./schemas
COPY LICENSE ./schemas/LICENSE
COPY reference/package.json reference/tsconfig.json reference/LICENSE.md ./reference/
COPY reference/migrations ./reference/migrations
COPY reference/src ./reference/src
COPY --from=deps /app/reference/node_modules ./reference/node_modules
RUN mkdir -p /data /config && chown node:node /data
USER node
WORKDIR /app/reference
VOLUME ["/data"]
# 8080: the public listener (put TLS in front of it). 8081: the person's web view; publish it on the host's
# loopback only (-p 127.0.0.1:8081:8081).
EXPOSE 8080 8081
# /healthz answers while the process serves. Node's own fetch makes the check, so it needs no other tool in the image.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:'+(process.env.PORT||8080)+'/healthz').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"]
CMD ["node", "src/main.ts"]
