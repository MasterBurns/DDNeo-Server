FROM rust:1-bookworm AS builder
WORKDIR /build
COPY Cargo.toml ./
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim
RUN useradd --system --create-home --home-dir /app ddneo
WORKDIR /app
COPY --from=builder /build/target/release/ddneo-server /app/ddneo-server
COPY server_config.example.json /app/server_config.json
RUN mkdir -p /app/saves && chown -R ddneo:ddneo /app
USER ddneo
EXPOSE 27777/tcp 27779/tcp
VOLUME ["/app/saves"]
ENTRYPOINT ["/app/ddneo-server", "--config", "/app/server_config.json"]
