.PHONY: build test lint clean install examples integration-test package help

BINARY_NAME=schemapin
VERSION=$(shell git describe --tags --always --dirty)
LDFLAGS=-ldflags "-X github.com/ThirdKeyAi/schemapin/go/internal/version.Version=$(VERSION)"

# Build targets
build:
	@echo "Building CLI tools..."
	go build $(LDFLAGS) -o bin/schemapin-keygen ./cmd/schemapin-keygen
	go build $(LDFLAGS) -o bin/schemapin-sign ./cmd/schemapin-sign
	go build $(LDFLAGS) -o bin/schemapin-verify ./cmd/schemapin-verify
	@echo "✓ Built all CLI tools in bin/"

build-release:
	@echo "Building release binaries..."
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/schemapin-keygen-linux-amd64 ./cmd/schemapin-keygen
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/schemapin-sign-linux-amd64 ./cmd/schemapin-sign
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/schemapin-verify-linux-amd64 ./cmd/schemapin-verify
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o bin/schemapin-keygen-darwin-amd64 ./cmd/schemapin-keygen
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o bin/schemapin-sign-darwin-amd64 ./cmd/schemapin-sign
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o bin/schemapin-verify-darwin-amd64 ./cmd/schemapin-verify
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o bin/schemapin-keygen-windows-amd64.exe ./cmd/schemapin-keygen
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o bin/schemapin-sign-windows-amd64.exe ./cmd/schemapin-sign
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o bin/schemapin-verify-windows-amd64.exe ./cmd/schemapin-verify
	@echo "✓ Built release binaries for Linux, macOS, and Windows"

# Test targets
test:
	@echo "Running unit tests..."
	go test -v -race -coverprofile=coverage.out ./...
	@echo "✓ Unit tests completed"

test-coverage:
	@echo "Running tests with coverage..."
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "✓ Coverage report generated: coverage.html"

integration-test:
	@echo "Running integration tests..."
	go test -v ./tests/
	@echo "✓ Integration tests completed"

benchmark:
	@echo "Running benchmarks..."
	go test -bench=. -benchmem ./pkg/crypto/
	go test -bench=. -benchmem ./pkg/core/
	@echo "✓ Benchmarks completed"

# Example targets
examples: build
	@echo "Running examples..."
	@echo "=== Developer Example ==="
	cd examples/developer && go run main.go
	@echo "\n=== Client Example ==="
	cd examples/client && go run main.go
	@echo "\n=== Interactive Demo ==="
	cd examples/interactive-demo && go run main.go
	@echo "\n=== Cross-Language Demo ==="
	cd examples/cross-language-demo && go run main.go
	@echo "✓ All examples completed"

example-developer: build
	@echo "Running developer example..."
	cd examples/developer && go run main.go

example-client: build
	@echo "Running client example..."
	cd examples/client && go run main.go

example-interactive: build
	@echo "Running interactive demo..."
	cd examples/interactive-demo && go run main.go

example-cross-language: build
	@echo "Running cross-language demo..."
	cd examples/cross-language-demo && go run main.go

# CLI demo targets
demo-keygen: build
	@echo "Demo: Generating keys..."
	./bin/schemapin-keygen --developer "Demo Developer" --contact "demo@example.com" --well-known
	@echo "✓ Keys generated"

demo-sign: build demo-keygen
	@echo "Demo: Signing schema..."
	echo '{"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}' | ./bin/schemapin-sign --key schemapin_private.pem --stdin --output demo_signed.json
	@echo "✓ Schema signed"

demo-verify: build demo-sign
	@echo "Demo: Verifying schema..."
	./bin/schemapin-verify --schema demo_signed.json --public-key schemapin_public.pem
	@echo "✓ Schema verified"

demo-full: demo-verify
	@echo "✓ Full CLI demo completed"
	@echo "Generated files:"
	@ls -la schemapin_private.pem schemapin_public.pem schemapin.json demo_signed.json

# Quality targets
lint:
	@echo "Running linter..."
	golangci-lint run
	@echo "✓ Linting completed"

fmt:
	@echo "Formatting code..."
	go fmt ./...
	@echo "✓ Code formatted"

vet:
	@echo "Running go vet..."
	go vet ./...
	@echo "✓ Vet completed"

# Dependency targets
deps:
	@echo "Downloading dependencies..."
	go mod download
	go mod tidy
	@echo "✓ Dependencies updated"

deps-update:
	@echo "Updating dependencies..."
	go get -u ./...
	go mod tidy
	@echo "✓ Dependencies updated"

# Installation targets
install: build
	@echo "Installing CLI tools..."
	go install $(LDFLAGS) ./cmd/schemapin-keygen
	go install $(LDFLAGS) ./cmd/schemapin-sign
	go install $(LDFLAGS) ./cmd/schemapin-verify
	@echo "✓ CLI tools installed to GOPATH/bin"

install-local: build
	@echo "Installing CLI tools locally..."
	mkdir -p ~/.local/bin
	cp bin/schemapin-keygen ~/.local/bin/
	cp bin/schemapin-sign ~/.local/bin/
	cp bin/schemapin-verify ~/.local/bin/
	@echo "✓ CLI tools installed to ~/.local/bin"

# Package targets
package: build-release
	@echo "Creating packages..."
	mkdir -p dist
	tar -czf dist/schemapin-go-linux-amd64.tar.gz -C bin schemapin-keygen-linux-amd64 schemapin-sign-linux-amd64 schemapin-verify-linux-amd64
	tar -czf dist/schemapin-go-darwin-amd64.tar.gz -C bin schemapin-keygen-darwin-amd64 schemapin-sign-darwin-amd64 schemapin-verify-darwin-amd64
	zip -j dist/schemapin-go-windows-amd64.zip bin/schemapin-keygen-windows-amd64.exe bin/schemapin-sign-windows-amd64.exe bin/schemapin-verify-windows-amd64.exe
	@echo "✓ Packages created in dist/"

# Cleanup targets
clean:
	@echo "Cleaning build artifacts..."
	rm -rf bin/ coverage.out coverage.html dist/
	rm -f private_key.pem public_key.pem well_known.json demo_signed.json
	rm -f examples/*/demo_*.json examples/*/demo_*.pem
	rm -f examples/*/*.db
	@echo "✓ Cleanup completed"

clean-examples:
	@echo "Cleaning example artifacts..."
	rm -f examples/*/demo_*.json examples/*/demo_*.pem examples/*/*.db
	@echo "✓ Example cleanup completed"

# Development targets
dev-setup:
	@echo "Setting up development environment..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go mod download
	@echo "✓ Development environment ready"

dev-test: fmt vet lint test
	@echo "✓ Development tests completed"

# CI targets
ci: deps fmt vet lint test integration-test
	@echo "✓ CI pipeline completed"

ci-coverage: deps fmt vet lint test-coverage integration-test
	@echo "✓ CI pipeline with coverage completed"

# Documentation targets
docs:
	@echo "Generating documentation..."
	go doc -all ./pkg/crypto > docs/crypto.md
	go doc -all ./pkg/core > docs/core.md
	go doc -all ./pkg/utils > docs/utils.md
	go doc -all ./pkg/pinning > docs/pinning.md
	go doc -all ./pkg/interactive > docs/interactive.md
	go doc -all ./pkg/discovery > docs/discovery.md
	@echo "✓ Documentation generated in docs/"

# Help target
help:
	@echo "SchemaPin Go Implementation - Available targets:"
	@echo ""
	@echo "Build targets:"
	@echo "  build              Build CLI tools"
	@echo "  build-release      Build release binaries for multiple platforms"
	@echo ""
	@echo "Test targets:"
	@echo "  test               Run unit tests"
	@echo "  test-coverage      Run tests with coverage report"
	@echo "  integration-test   Run integration tests"
	@echo "  benchmark          Run performance benchmarks"
	@echo ""
	@echo "Example targets:"
	@echo "  examples           Run all examples"
	@echo "  example-developer  Run developer workflow example"
	@echo "  example-client     Run client verification example"
	@echo "  example-interactive Run interactive pinning demo"
	@echo "  example-cross-language Run cross-language compatibility demo"
	@echo ""
	@echo "CLI demo targets:"
	@echo "  demo-keygen        Demo key generation"
	@echo "  demo-sign          Demo schema signing"
	@echo "  demo-verify        Demo schema verification"
	@echo "  demo-full          Run complete CLI demo"
	@echo ""
	@echo "Quality targets:"
	@echo "  lint               Run golangci-lint"
	@echo "  fmt                Format code with go fmt"
	@echo "  vet                Run go vet"
	@echo ""
	@echo "Installation targets:"
	@echo "  install            Install CLI tools to GOPATH/bin"
	@echo "  install-local      Install CLI tools to ~/.local/bin"
	@echo ""
	@echo "Package targets:"
	@echo "  package            Create distribution packages"
	@echo ""
	@echo "Development targets:"
	@echo "  dev-setup          Set up development environment"
	@echo "  dev-test           Run development tests (fmt, vet, lint, test)"
	@echo "  ci                 Run CI pipeline"
	@echo "  ci-coverage        Run CI pipeline with coverage"
	@echo ""
	@echo "Utility targets:"
	@echo "  deps               Download and tidy dependencies"
	@echo "  deps-update        Update dependencies"
	@echo "  clean              Clean build artifacts"
	@echo "  clean-examples     Clean example artifacts"
	@echo "  docs               Generate documentation"
	@echo "  help               Show this help message"