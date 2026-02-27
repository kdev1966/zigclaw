# syntax=docker/dockerfile:1

# ── Stage 1: Build ────────────────────────────────────────────
FROM alpine:3.23 AS builder

RUN apk add --no-cache zig musl-dev

WORKDIR /app
COPY build.zig build.zig.zon ./
COPY src/ src/

RUN zig build -Doptimize=ReleaseSmall

# ── Stage 2: Data Directory Prep ─────────────────────────────
FROM busybox:1.37 AS config

RUN mkdir -p /zigclaw-data/.zigclaw /zigclaw-data/workspace

# No config.json embedded — mount your own via docker-compose volumes.
# See config.example.json for a template.

# Default runtime runs as non-root (uid/gid 65534).
# Keep writable ownership for HOME/workspace in safe mode.
RUN chown -R 65534:65534 /zigclaw-data

# ── Stage 3: Runtime Base (shared) ────────────────────────────
FROM alpine:3.23 AS release-base

LABEL org.opencontainers.image.source=https://github.com/kdev1966/zigclaw

RUN apk add --no-cache ca-certificates curl tzdata

COPY --from=builder /app/zig-out/bin/zigclaw /usr/local/bin/zigclaw
COPY --from=config /zigclaw-data /zigclaw-data

ENV ZIGCLAW_WORKSPACE=/zigclaw-data/workspace
ENV HOME=/zigclaw-data
ENV ZIGCLAW_GATEWAY_PORT=3000

WORKDIR /zigclaw-data
EXPOSE 3000
ENTRYPOINT ["zigclaw"]
CMD ["gateway", "--port", "3000", "--host", "::"]

# Optional autonomous mode (explicit opt-in):
#   docker build --target release-root -t zigclaw:root .
FROM release-base AS release-root
USER 0:0

# Safe default image (used when no --target is provided)
FROM release-base AS release
USER 65534:65534
