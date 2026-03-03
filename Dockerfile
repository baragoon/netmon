# Build stage
FROM golang:alpine@sha256:d4c4845f5d60c6a974c6000ce58ae079328d03ab7f721a0734277e69905473e5 AS builder

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

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o netmon .

# Runtime stage
FROM alpine:3.23@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659

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
