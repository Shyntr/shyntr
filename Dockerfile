# Stage 1: Builder
FROM golang:1.25.7-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git

# Copy module files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -o shyntr ./cmd/server/main.go

# Stage 2: Runner
FROM alpine:3.23.3

WORKDIR /app

ENV GIN_MODE=release
ENV GO_ENV=production

# Install CA certificates for SSL
RUN apk add --no-cache ca-certificates

# Copy binary from builder
COPY --from=builder /app/shyntr .

# Expose port
EXPOSE 7496 7497

RUN adduser -D -u 1000 appuser && chown -R 1000:1000 /app
USER 1000

# Default command (can be overridden to 'migrate' or other CLI commands)
CMD ["./shyntr", "serve"]
