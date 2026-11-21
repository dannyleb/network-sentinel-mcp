BINARY  := network-sentinel-mcp
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

# Dev tools run through `go run` at pinned versions. They are not module
# dependencies and never end up in the binary.
STATICCHECK := honnef.co/go/tools/cmd/staticcheck@v0.8.2
GOVULNCHECK := golang.org/x/vuln/cmd/govulncheck@v1.9.0
INSPECTOR   := @modelcontextprotocol/inspector@2.14.0

.PHONY: build test lint vuln check inspector release clean

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/$(BINARY)

test:
	go vet ./...
	go test -race ./...

lint:
	@unformatted="$$(gofmt -l .)"; if [ -n "$$unformatted" ]; then echo "gofmt needed:"; echo "$$unformatted"; exit 1; fi
	go run $(STATICCHECK) ./...

vuln:
	go run $(GOVULNCHECK) ./...

check: lint test vuln

# Opens MCP Inspector against a local build. Network Sentinel must be running.
inspector: build
	npx -y $(INSPECTOR) ./bin/$(BINARY)

release:
	rm -rf dist && mkdir -p dist
	GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-darwin-arm64 ./cmd/$(BINARY)
	GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-darwin-amd64 ./cmd/$(BINARY)
	GOOS=linux  GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-amd64 ./cmd/$(BINARY)
	GOOS=linux  GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-arm64 ./cmd/$(BINARY)
	cd dist && shasum -a 256 $(BINARY)-* > SHA256SUMS

clean:
	rm -rf bin dist
