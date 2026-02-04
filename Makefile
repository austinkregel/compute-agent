BINDIR ?= dist
APP    ?= backup-agent

PLATFORMS = \
	linux/amd64 \
	linux/arm64 \
	linux/arm \
	darwin/amd64 \
	darwin/arm64 \
	windows/amd64

# Build for host platform with kiosk support (requires CGO + platform deps)
# Linux: apt install libgtk-3-dev libwebkit2gtk-4.0-dev
# macOS: WebKit included by default
# Windows: WebView2 runtime required
.PHONY: build
build:
	@mkdir -p $(BINDIR)
	CGO_ENABLED=1 go build -o $(BINDIR)/$(APP) ./cmd/agent

# Build without kiosk support (no CGO, faster, cross-platform compatible)
.PHONY: build-headless
build-headless:
	@mkdir -p $(BINDIR)
	CGO_ENABLED=0 go build -o $(BINDIR)/$(APP) ./cmd/agent

# Cross-compile for all platforms (headless only, no kiosk - CGO disabled)
.PHONY: build-all
build-all:
	@mkdir -p $(BINDIR)
	@set -e; \
	for platform in $(PLATFORMS); do \
		os=$${platform%%/*}; \
		arch=$${platform##*/}; \
		out="$(BINDIR)/$(APP)-$${os}-$${arch}"; \
		if [ "$${os}" = "windows" ]; then out="$${out}.exe"; fi; \
		echo ">> building $${os}/$${arch} -> $${out}"; \
		GOOS=$${os} GOARCH=$${arch} CGO_ENABLED=0 go build -o "$${out}" ./cmd/agent || exit $$?; \
	done

.PHONY: tidy
tidy:
	go mod tidy

# Run tests without CGO (works in CI and environments without WebView deps)
.PHONY: test
test:
	CGO_ENABLED=0 go test ./...

# Run tests with CGO (requires WebView dependencies)
.PHONY: test-cgo
test-cgo:
	CGO_ENABLED=1 go test ./...

.PHONY: coverage
coverage:
	CGO_ENABLED=0 go test ./... -coverpkg=./... -coverprofile=coverage.out
	go tool cover -html=coverage.out -o coverage.html







