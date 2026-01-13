# syntax=docker/dockerfile:1.4

# Sentinel JavaScript Agent Container Image
#
# Targets:
#   - prebuilt: For CI with pre-built binaries

################################################################################
# Pre-built binary stage (for CI builds)
################################################################################
FROM gcr.io/distroless/cc-debian12:nonroot AS prebuilt

COPY sentinel-js-agent /sentinel-js-agent

LABEL org.opencontainers.image.title="Sentinel JavaScript Agent" \
      org.opencontainers.image.description="Sentinel JavaScript Agent for Sentinel reverse proxy" \
      org.opencontainers.image.vendor="Raskell" \
      org.opencontainers.image.source="https://github.com/raskell-io/sentinel-agent-js"

ENV RUST_LOG=info,sentinel_js_agent=debug \
    SOCKET_PATH=/var/run/sentinel/js.sock

USER nonroot:nonroot

ENTRYPOINT ["/sentinel-js-agent"]
