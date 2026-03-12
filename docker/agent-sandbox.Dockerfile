FROM rust:1.88-bookworm AS build

WORKDIR /workspace

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY src ./src

RUN cargo build --release --bin gloves --bin gloves-mcp

FROM oven/bun:1.3.8-slim

WORKDIR /workspace

COPY package.json bun.lock tsconfig.json ./
COPY packages ./packages
COPY docker ./docker
COPY --from=build /workspace/target/release/gloves /usr/local/bin/gloves
COPY --from=build /workspace/target/release/gloves-mcp /usr/local/bin/gloves-mcp

RUN bun install --frozen-lockfile

USER bun

ENTRYPOINT ["bun", "/workspace/docker/agent-sandbox.ts"]
