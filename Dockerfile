# Build stage
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder

# Docker buildx automatically provides these
ARG TARGETOS
ARG TARGETARCH

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache git

# Copy go mod files
COPY go.mod go.sum* ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Tidy dependencies
RUN go mod tidy

# Build the application using native cross-compilation (no QEMU needed)
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o netmon .

# Runtime stage
FROM alpine:3.23

# Install ca-certificates for HTTPS
RUN apk add --no-cache ca-certificates

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /build/netmon /app/netmon

# Copy example config as default config
COPY config.example.json* /app/config.json

# Keep example config for reference
COPY config.example.json* /app/config.example.json

# Run as root (required for network monitoring)
RUN chmod +x /app/netmon

# Default command with common flags
ENTRYPOINT ["/app/netmon"]
CMD ["-interval", "5s"]
