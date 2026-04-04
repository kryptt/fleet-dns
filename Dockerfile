# syntax=docker/dockerfile:1
FROM rust:1-alpine AS builder

RUN apk add --no-cache musl-dev ca-certificates

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/

# --- Test stage: docker buildx build --target test . ---
FROM builder AS test
RUN --mount=type=cache,target=/usr/local/cargo/registry,id=cargo-registry \
    --mount=type=cache,target=/usr/local/cargo/git,id=cargo-git \
    cargo test -- --test-threads=1

# --- Release build ---
FROM builder AS release
RUN --mount=type=cache,target=/usr/local/cargo/registry,id=cargo-registry \
    --mount=type=cache,target=/usr/local/cargo/git,id=cargo-git \
    cargo build --release --target x86_64-unknown-linux-musl

# --- Runtime ---
FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=release /build/target/x86_64-unknown-linux-musl/release/fleet-dns /fleet-dns

EXPOSE 9090

ENTRYPOINT ["/fleet-dns"]
