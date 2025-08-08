# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application (inject version if provided at build time)
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-s -w -X main.version=${VERSION}" -o nexo

# Final stage
FROM alpine:latest

WORKDIR /app

# Install CA certificates for HTTPS
RUN apk add --no-cache ca-certificates

# Create config and cert directories and non-root user
RUN adduser -D -u 10001 nexo && \
    mkdir -p /etc/nexo /etc/nexo/certs && \
    chown -R nexo:nexo /etc/nexo

# Copy the binary from builder
COPY --from=builder /app/nexo .

# Create volume for persistent config/certs
VOLUME ["/etc/nexo"]

# Default to non-root port 8443 to avoid privileged port
ENV NEXO_LISTEN_ADDR=:8443

# Expose HTTPS and admin ports
EXPOSE 8443 8080

# Run as non-root user, use 8443 by default unless overridden
USER nexo
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["/app/nexo", "server"]