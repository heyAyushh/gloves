FROM oven/bun:1.3.8-slim

WORKDIR /workspace

COPY package.json bun.lock tsconfig.json ./
COPY packages ./packages
COPY docker ./docker

RUN bun install --frozen-lockfile

USER bun

ENTRYPOINT ["bun", "docker/agent-sandbox.ts"]
