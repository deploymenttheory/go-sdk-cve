.PHONY: help build test lint clean examples

help:
	@echo "Available targets:"
	@echo "  build     - Build all packages"
	@echo "  test      - Run tests"
	@echo "  lint      - Run linters"
	@echo "  clean     - Clean build artifacts"
	@echo "  examples  - Build all examples"

build:
	go build ./...

test:
	go test -v -race -cover ./...

lint:
	golangci-lint run

clean:
	go clean ./...
	rm -rf dist/ build/ bin/

examples:
	@echo "Building examples..."
	@cd examples/cves/list_by_keyword && go build
	@cd examples/cves/get_by_id && go build
	@cd examples/cves/filter_by_severity && go build
	@cd examples/cves/date_range_sync && go build
	@cd examples/cves/kev_catalog && go build
	@cd examples/cve_history/track_changes && go build
	@cd examples/comprehensive && go build
	@echo "All examples built successfully"
