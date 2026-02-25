# Build stage
FROM golang:1.26-alpine3.20 AS builder

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache git

# Copy go mod files
COPY go.mod go.sum* ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o netmon .

# Runtime stage
FROM alpine:3.20

# Install ca-certificates for HTTPS
RUN apk add --no-cache ca-certificates

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /build/netmon /app/netmon

# Copy example config (optional)
COPY config.example.json* /app/config.example.json

# Run as root (required for network monitoring)
RUN chmod +x /app/netmon

# Default command with common flags
ENTRYPOINT ["/app/netmon"]
CMD ["-interval", "5s"]
