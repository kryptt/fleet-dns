# syntax=docker/dockerfile:1
FROM rust:1-alpine AS builder

RUN apk add --no-cache musl-dev ca-certificates

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/

# Resolve the native musl target triple so the same Dockerfile builds on
# amd64 and arm64 hosts (e.g. under QEMU emulation in GH Actions buildx).
# rustc prints lines like "host: x86_64-unknown-linux-musl"; grab that.
RUN rustc -vV | awk '/^host:/ {print $2}' > /tmp/target-triple && \
    cat /tmp/target-triple

# --- Test stage: docker buildx build --target test . ---
FROM builder AS test
RUN --mount=type=cache,target=/usr/local/cargo/registry,id=cargo-registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,id=cargo-git,sharing=locked \
    TARGET="$(cat /tmp/target-triple)" && \
    cargo test --target "$TARGET" -- --test-threads=1

# --- Release build ---
FROM builder AS release
RUN --mount=type=cache,target=/usr/local/cargo/registry,id=cargo-registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,id=cargo-git,sharing=locked \
    TARGET="$(cat /tmp/target-triple)" && \
    cargo build --release --target "$TARGET" && \
    cp "target/$TARGET/release/fleet-dns" /fleet-dns

# --- Runtime ---
FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=release /fleet-dns /fleet-dns

EXPOSE 9090

ENTRYPOINT ["/fleet-dns"]
