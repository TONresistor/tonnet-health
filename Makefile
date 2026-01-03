.PHONY: build clean test run

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

build:
	go build $(LDFLAGS) -o tonnet-health ./cmd

run: build
	./tonnet-health

run-json: build
	./tonnet-health --json

clean:
	rm -f tonnet-health

test:
	go test -v ./...

deps:
	go mod download
	go mod tidy

check: build
	./tonnet-health --verbose
