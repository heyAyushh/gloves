FROM rust:1.88-bookworm AS build

WORKDIR /workspace

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY src ./src

RUN cargo build --release --bin gloves --bin gloves-mcp

FROM debian:bookworm-slim

RUN useradd --create-home --uid 1000 gloves

COPY --from=build /workspace/target/release/gloves /usr/local/bin/gloves
COPY --from=build /workspace/target/release/gloves-mcp /usr/local/bin/gloves-mcp

USER gloves

ENTRYPOINT ["gloves-mcp"]
