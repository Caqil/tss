# Makefile for MPC-TSS

.PHONY: all build test lint clean install help

# Variables
GOBIN := $(shell go env GOPATH)/bin
BINARY_NAME := mpc-tss
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS := -X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME)

## help: Display this help message
help:
	@echo "MPC-TSS Makefile Commands:"
	@echo ""
	@grep -E '^##' Makefile | sed 's/## /  /'
	@echo ""

## all: Run tests and build
all: test build

## build: Build the project
build:
	@echo "Building..."
	@go build -v -ldflags="$(LDFLAGS)" ./...

## build-examples: Build example applications
build-examples:
	@echo "Building examples..."
	@cd cmd/examples/simple-dkg && go build -v -o ../../../bin/simple-dkg
	@cd cmd/examples/simple-signing && go build -v -o ../../../bin/simple-signing
	@cd cmd/examples/key-refresh && go build -v -o ../../../bin/key-refresh
	@cd cmd/examples/multi-party-demo && go build -v -o ../../../bin/multi-party-demo
	@echo "Examples built in bin/"

## test: Run all tests
test:
	@echo "Running tests..."
	@go test -v -race ./...

## test-coverage: Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	@go test -v -race -coverprofile=coverage.out -covermode=atomic ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

## test-integration: Run integration tests
test-integration:
	@echo "Running integration tests..."
	@go test -v -tags=integration ./tests/integration/...

## test-security: Run security tests
test-security:
	@echo "Running security tests..."
	@go test -v ./tests/security/...

## bench: Run benchmarks
bench:
	@echo "Running benchmarks..."
	@go test -bench=. -benchmem -run=^$$ ./tests/benchmarks/... | tee bench-results.txt

## lint: Run linters
lint:
	@echo "Running linters..."
	@golangci-lint run --timeout=5m

## lint-fix: Run linters with auto-fix
lint-fix:
	@echo "Running linters with auto-fix..."
	@golangci-lint run --fix --timeout=5m

## security: Run security scans
security:
	@echo "Running security scans..."
	@gosec -fmt=text -out=gosec-report.txt ./...
	@echo "Security report: gosec-report.txt"

## vuln-check: Check for known vulnerabilities
vuln-check:
	@echo "Checking for vulnerabilities..."
	@go install golang.org/x/vuln/cmd/govulncheck@latest
	@govulncheck ./...

## fmt: Format code
fmt:
	@echo "Formatting code..."
	@gofmt -s -w .
	@goimports -w .

## clean: Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -rf bin/
	@rm -rf dist/
	@rm -f coverage.out coverage.html
	@rm -f gosec-report.txt
	@rm -f bench-results.txt
	@go clean -cache -testcache

## deps: Download dependencies
deps:
	@echo "Downloading dependencies..."
	@go mod download
	@go mod verify

## deps-update: Update dependencies
deps-update:
	@echo "Updating dependencies..."
	@go get -u ./...
	@go mod tidy

## install-tools: Install development tools
install-tools:
	@echo "Installing development tools..."
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@go install github.com/securego/gosec/v2/cmd/gosec@latest
	@go install golang.org/x/tools/cmd/goimports@latest
	@go install golang.org/x/vuln/cmd/govulncheck@latest
	@echo "Tools installed to $(GOBIN)"

## pre-commit: Run all checks before commit
pre-commit: fmt lint test
	@echo "✓ All pre-commit checks passed!"

## ci: Run CI pipeline locally
ci: deps lint security test test-integration
	@echo "✓ CI pipeline completed!"

## docs: Generate documentation
docs:
	@echo "Generating documentation..."
	@go doc -all ./... > docs/godoc.txt
	@echo "Documentation generated in docs/"

## mod-tidy: Tidy go.mod
mod-tidy:
	@echo "Tidying go.mod..."
	@go mod tidy -v

## verify: Verify dependencies
verify:
	@echo "Verifying dependencies..."
	@go mod verify

## version: Display version
version:
	@echo "Version: $(VERSION)"
	@echo "Build Time: $(BUILD_TIME)"

## init-git: Initialize git hooks
init-git:
	@echo "Setting up git hooks..."
	@mkdir -p .git/hooks
	@echo "#!/bin/sh" > .git/hooks/pre-commit
	@echo "make pre-commit" >> .git/hooks/pre-commit
	@chmod +x .git/hooks/pre-commit
	@echo "✓ Git hooks installed"

.DEFAULT_GOAL := help
