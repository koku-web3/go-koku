# =============================================================================
# Stage 1: Build all 3 Go binaries
# =============================================================================
FROM --platform=linux/amd64 golang:1.26-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates

WORKDIR /src

# Download dependencies first (layer cache optimisation)
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build all 3 binaries in one layer
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o /out/coordinator  ./cmd/coordinator && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o /out/signer       ./cmd/signer       && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o /out/key-creator  ./cmd/key-creator

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

EXPOSE 50051 50052 50053

ENTRYPOINT ["/app/coordinator"]
