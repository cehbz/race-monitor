.PHONY: build install clean test test-verbose test-coverage lint deps

BINARY := race-monitor
INSTALL_PATH := $(HOME)/bin
COVERAGE_FILE := coverage.out

build:
	go build -o $(BINARY) ./cmd/race-monitor

install: build
	install -d $(INSTALL_PATH)
	install $(BINARY) $(INSTALL_PATH)/

clean:
	rm -f $(BINARY) $(COVERAGE_FILE)

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

# Build for multiple platforms
build-all:
	GOOS=linux GOARCH=amd64 go build -o $(BINARY)-linux-amd64 ./cmd/race-monitor
	GOOS=linux GOARCH=arm64 go build -o $(BINARY)-linux-arm64 ./cmd/race-monitor
