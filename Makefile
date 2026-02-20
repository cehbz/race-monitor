.PHONY: build install clean test test-verbose test-coverage lint deps generate

BINARY := race-monitor
CALIBRATE_BINARY := race-calibrate
INSTALL_PATH := $(HOME)/bin
COVERAGE_FILE := coverage.out

# Generate eBPF bytecode from C source (requires clang, linux headers)
generate:
	go generate ./internal/bpf/

build: generate
	go build -o $(BINARY) ./cmd/race-monitor
	go build -o $(CALIBRATE_BINARY) ./cmd/race-calibrate

# Build without regenerating eBPF (use pre-generated files)
build-quick:
	go build -o $(BINARY) ./cmd/race-monitor
	go build -o $(CALIBRATE_BINARY) ./cmd/race-calibrate

BPF_CAPS := cap_bpf,cap_perfmon,cap_sys_resource,cap_sys_admin+ep
SETCAP := $(shell command -v setcap 2>/dev/null || echo /sbin/setcap)

install: build
	install -d $(INSTALL_PATH)
	install $(BINARY) $(INSTALL_PATH)/
	install $(CALIBRATE_BINARY) $(INSTALL_PATH)/
	sudo $(SETCAP) '$(BPF_CAPS)' $(INSTALL_PATH)/$(BINARY)
	sudo $(SETCAP) '$(BPF_CAPS)' $(INSTALL_PATH)/$(CALIBRATE_BINARY)

clean:
	rm -f $(BINARY) $(CALIBRATE_BINARY) $(COVERAGE_FILE)

# Run all tests
test:
	go test ./...

# Run tests with verbose output
test-verbose:
	go test -v ./...

# Run tests with coverage
test-coverage:
	go test -coverprofile=$(COVERAGE_FILE) ./...
	go tool cover -html=$(COVERAGE_FILE) -o coverage.html
	@echo "Coverage report: coverage.html"

# Run tests with race detection
test-race:
	go test -race ./...

# Run short tests only (skip slow integration tests)
test-short:
	go test -short ./...

# Run benchmarks
bench:
	go test -bench=. -benchmem ./...

# Update dependencies
deps:
	go mod tidy

# Lint (requires golangci-lint)
lint:
	golangci-lint run ./...

# Format code
fmt:
	go fmt ./...
	goimports -w .

# Check for common issues
vet:
	go vet ./...

# Run all checks before commit
check: fmt vet test

# Build for Linux amd64 (eBPF is Linux-only)
build-linux:
	GOOS=linux GOARCH=amd64 go build -o $(BINARY)-linux-amd64 ./cmd/race-monitor
	GOOS=linux GOARCH=amd64 go build -o $(CALIBRATE_BINARY)-linux-amd64 ./cmd/race-calibrate
