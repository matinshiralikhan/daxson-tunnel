# Stage 1: Build
FROM golang:1.22-alpine AS builder

WORKDIR /src

# Cache dependency downloads separately from the build.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build both binaries with aggressive size optimization.
RUN CGO_ENABLED=0 GOOS=linux go build \
      -ldflags="-s -w -X main.BuildVersion=$(git describe --tags --always 2>/dev/null || echo dev)" \
      -trimpath \
      -o /out/daxsond ./cmd/daxsond && \
    CGO_ENABLED=0 GOOS=linux go build \
      -ldflags="-s -w" \
      -trimpath \
      -o /out/daxson ./cmd/daxson

# Stage 2: Minimal runtime image
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S daxson && adduser -S -G daxson daxson

WORKDIR /app

COPY --from=builder /out/daxsond /out/daxson /usr/local/bin/

# Certificates volume: mount Let's Encrypt certs here.
VOLUME ["/etc/daxson/certs"]
# Config volume.
VOLUME ["/etc/daxson"]

USER daxson

EXPOSE 443 9090

ENTRYPOINT ["daxsond"]
CMD ["--config", "/etc/daxson/server.yaml"]
