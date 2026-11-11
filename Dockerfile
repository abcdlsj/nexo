# Build stage
FROM golang:1.25.12-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application with version metadata for fleet version-skew detection
ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_DATE=unknown
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-s -w \
    -X github.com/abcdlsj/nexo/internal/buildinfo.Version=${VERSION} \
    -X github.com/abcdlsj/nexo/internal/buildinfo.Commit=${COMMIT} \
    -X github.com/abcdlsj/nexo/internal/buildinfo.Date=${BUILD_DATE}" -o nexo

# Final stage
FROM alpine:3.23

WORKDIR /app

# Install CA certificates for HTTPS
RUN apk add --no-cache ca-certificates

# Create config directory
RUN mkdir -p /etc/nexo

# Copy the binary from builder
COPY --from=builder /app/nexo .
COPY example/config.yaml /etc/nexo/config.yaml

# Create volume for persistent config
VOLUME ["/etc/nexo"]

# Expose HTTPS port and WebUI port
EXPOSE 443 8080

# Run the application
ENTRYPOINT ["/app/nexo", "server"]
