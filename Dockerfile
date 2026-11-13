FROM rust:1.94.1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY tools.json ./tools.json
RUN cargo build --release --locked -j 2

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir /data && chown 10001:10001 /data
COPY --from=build /src/target/release/dokploy-mcp /usr/local/bin/dokploy-mcp
USER 10001:10001
ENV PORT=8787 DATABASE_PATH=/data/oauth.sqlite
EXPOSE 8787
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD ["dokploy-mcp", "--healthcheck"]
ENTRYPOINT ["dokploy-mcp"]
