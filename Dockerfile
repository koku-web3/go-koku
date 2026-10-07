# =============================================================================
# Stage 1: Build all 3 Go binaries
# =============================================================================
FROM --platform=linux/${TARGETARCH:-arm64} golang:1.26-alpine AS builder

# Re-declare TARGETARCH inside the stage so it is in scope for the RUN below.
# A global ARG (declared before the first FROM) is NOT automatically available
# inside a build stage, which previously left GOARCH hardcoded to amd64 and
# produced binaries the arm64 runtime image could not execute.
ARG TARGETARCH

# Install build dependencies
RUN apk add --no-cache git ca-certificates

WORKDIR /src

# Use Chinese mirror for Go modules (more reliable in some network conditions)
ENV GOPROXY=https://goproxy.cn,direct

# Download dependencies first (layer cache optimisation)
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build all 3 binaries in one layer.
# GOARCH/TARGETARCH follow the builder platform so this works on both
# Apple Silicon (arm64) and Intel (amd64) without an explicit edit.
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH:-arm64} go build -ldflags="-w -s" -o /out/coordinator  ./cmd/coordinator && \
    CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH:-arm64} go build -ldflags="-w -s" -o /out/signer       ./cmd/signer       && \
    CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH:-arm64} go build -ldflags="-w -s" -o /out/key-creator  ./cmd/key-creator

# =============================================================================
# Stage 2: Runtime image
# =============================================================================
FROM alpine:3.20 AS runtime

# Create non-root user and app directory
RUN addgroup -g 10001 -S appgroup && \
    adduser -u 10001 -S appuser -G appgroup && \
    mkdir -p /app && chown -R appuser:appgroup /app
USER appuser

WORKDIR /app

# Copy binaries from builder
COPY --from=builder /out/* /app/

# Config files are mounted via docker-compose; the directory must exist
RUN mkdir -p /app/config

EXPOSE 50051

# NOTE: deliberately no ENTRYPOINT here. This single image ships three binaries
# (coordinator / signer / key-creator), so hardcoding one of them as ENTRYPOINT
# would make every service run the wrong program. Compose `command:` overrides
# CMD but NOT ENTRYPOINT, so a fixed ENTRYPOINT would be prepended to each
# service's command and break flag parsing (Go's flag package stops at the first
# non-flag argument, silently falling back to the default config path).
# Each service therefore supplies its full command, e.g.
#   command: ["/app/coordinator", "--config", "/app/config/coordinator.docker.toml"]
# CMD is only a harmless fallback for `docker run <image>` with no arguments.
CMD ["/app/coordinator"]
