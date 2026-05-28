# Daxson Tunnel — Makefile
#
# Common targets:
#   make build          Build both binaries
#   make test           Run all tests
#   make bench          Run benchmarks
#   make chaos          Run chaos tests (slow)
#   make lint           Run golangci-lint
#   make docker         Build Docker image
#   make clean          Remove build artifacts

MODULE := github.com/daxson/tunnel
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -ldflags="-s -w -X main.BuildVersion=$(VERSION)"
GOFLAGS := -trimpath $(LDFLAGS)

BINS := bin/daxsond bin/daxson

.PHONY: all build test bench chaos lint docker clean fmt tidy

all: build

## ── Build ────────────────────────────────────────────────────────────────────

build: $(BINS)

bin/daxsond: $(shell find cmd/daxsond internal pkg -name '*.go')
	@mkdir -p bin
	go build $(GOFLAGS) -o $@ ./cmd/daxsond

bin/daxson: $(shell find cmd/daxson internal pkg -name '*.go')
	@mkdir -p bin
	go build $(GOFLAGS) -o $@ ./cmd/daxson

## Cross-compile for common targets.
build-linux-amd64:
	GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -o bin/daxsond-linux-amd64 ./cmd/daxsond
	GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -o bin/daxson-linux-amd64  ./cmd/daxson

build-linux-arm64:
	GOOS=linux GOARCH=arm64 go build $(GOFLAGS) -o bin/daxsond-linux-arm64 ./cmd/daxsond
	GOOS=linux GOARCH=arm64 go build $(GOFLAGS) -o bin/daxson-linux-arm64  ./cmd/daxson

build-windows-amd64:
	GOOS=windows GOARCH=amd64 go build $(GOFLAGS) -o bin/daxsond-windows-amd64.exe ./cmd/daxsond
	GOOS=windows GOARCH=amd64 go build $(GOFLAGS) -o bin/daxson-windows-amd64.exe  ./cmd/daxson

build-android-arm64:
	GOOS=android GOARCH=arm64 go build $(GOFLAGS) -o bin/daxson-android-arm64 ./cmd/daxson

## ── Test ─────────────────────────────────────────────────────────────────────

test:
	go test ./... -timeout 60s -race

test-unit:
	go test ./internal/... ./pkg/... -timeout 30s -race

test-integration:
	go test ./tests/integration/... -v -timeout 60s -race

bench:
	go test ./tests/benchmarks/... -bench=. -benchmem -benchtime=10s -count=1

bench-compare: ## Requires benchstat: go install golang.org/x/perf/cmd/benchstat@latest
	go test ./tests/benchmarks/... -bench=. -benchmem -count=10 | tee /tmp/bench-new.txt
	benchstat /tmp/bench-new.txt

chaos:
	go test ./tests/chaos/... -v -timeout 120s

## ── Code Quality ─────────────────────────────────────────────────────────────

fmt:
	gofmt -w -s .
	goimports -w .

lint:
	golangci-lint run ./...

vet:
	go vet ./...

tidy:
	go mod tidy

## ── Fuzzing (requires Go 1.18+) ──────────────────────────────────────────────

fuzz-frame:
	go test ./pkg/protocol -fuzz=FuzzFrameRead -fuzztime=60s

## ── Docker ───────────────────────────────────────────────────────────────────

docker:
	docker build -t daxson/tunnel:$(VERSION) -f deploy/docker/Dockerfile .
	docker tag daxson/tunnel:$(VERSION) daxson/tunnel:latest

docker-compose-up:
	docker compose -f deploy/docker/docker-compose.yml up -d

docker-compose-down:
	docker compose -f deploy/docker/docker-compose.yml down

## ── Install (Linux) ──────────────────────────────────────────────────────────

install-server: bin/daxsond
	install -m 0755 bin/daxsond /usr/local/bin/daxsond
	install -m 0640 configs/server.example.yaml /etc/daxson/server.yaml.example
	install -m 0644 deploy/systemd/daxsond.service /etc/systemd/system/daxsond.service
	systemctl daemon-reload
	@echo "Run: systemctl enable --now daxsond"

install-relay: bin/daxson
	install -m 0755 bin/daxson /usr/local/bin/daxson
	install -m 0640 configs/relay.example.yaml /etc/daxson/relay.yaml.example
	install -m 0644 deploy/systemd/daxson-relay.service /etc/systemd/system/daxson-relay.service
	systemctl daemon-reload
	@echo "Run: systemctl enable --now daxson-relay"

## ── Profiling ────────────────────────────────────────────────────────────────

pprof-cpu:
	go tool pprof http://localhost:6060/debug/pprof/profile?seconds=30

pprof-heap:
	go tool pprof http://localhost:6060/debug/pprof/heap

pprof-goroutine:
	go tool pprof http://localhost:6060/debug/pprof/goroutine

## ── Cleanup ──────────────────────────────────────────────────────────────────

clean:
	rm -rf bin/
