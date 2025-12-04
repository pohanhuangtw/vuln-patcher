# Build stage
FROM golang:1.25.4-alpine AS builder

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY *.go ./

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o vuln-patcher .

# Runtime stage
FROM alpine:3.19

# Install required tools
RUN apk add --no-cache \
    ca-certificates \
    docker-cli \
    curl \
    bash


WORKDIR /app

RUN curl -fsSL https://github.com/project-copacetic/copacetic/releases/download/v0.12.0/copa_0.12.0_linux_amd64.tar.gz -o /app/copa.tar.gz
RUN tar -xzvf /app/copa.tar.gz -C /app/
RUN chmod +x /app/copa

# Create directories for reports
RUN mkdir -p /app/vul-report
COPY vul-report/ /app/vul-report/
# Copy the binary from builder
COPY --from=builder /build/vuln-patcher .
# Set environment variables
ENV PATH="/app:${PATH}"

# Default command
CMD ["./vuln-patcher"]
