# syntax=docker/dockerfile:1.4

# Zentinel JavaScript Agent Container Image
#
# Targets:
#   - prebuilt: For CI with pre-built binaries

################################################################################
# Pre-built binary stage (for CI builds)
################################################################################
FROM gcr.io/distroless/cc-debian12:nonroot AS prebuilt

COPY zentinel-js-agent /zentinel-js-agent

LABEL org.opencontainers.image.title="Zentinel JavaScript Agent" \
      org.opencontainers.image.description="Zentinel JavaScript Agent for Zentinel reverse proxy" \
      org.opencontainers.image.vendor="Raskell" \
      org.opencontainers.image.source="https://github.com/zentinelproxy/zentinel-agent-js"

ENV RUST_LOG=info,zentinel_js_agent=debug \
    SOCKET_PATH=/var/run/zentinel/js.sock

USER nonroot:nonroot

ENTRYPOINT ["/zentinel-js-agent"]
