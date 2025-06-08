.PHONY: build test lint clean install

BINARY_NAME=schemapin
VERSION=$(shell git describe --tags --always --dirty)
LDFLAGS=-ldflags "-X github.com/jascha/schemapin-go/internal/version.Version=$(VERSION)"

build:
	go build $(LDFLAGS) -o bin/schemapin-keygen ./cmd/schemapin-keygen
	go build $(LDFLAGS) -o bin/schemapin-sign ./cmd/schemapin-sign
	go build $(LDFLAGS) -o bin/schemapin-verify ./cmd/schemapin-verify

test:
	go test -v -race -coverprofile=coverage.out ./...

lint:
	golangci-lint run

clean:
	rm -rf bin/ coverage.out

install:
	go install $(LDFLAGS) ./cmd/...