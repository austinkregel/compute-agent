BINDIR ?= dist
APP    ?= backup-agent

PLATFORMS = \
	linux/amd64 \
	linux/arm64 \
	linux/arm \
	darwin/amd64 \
	darwin/arm64 \
	windows/amd64

.PHONY: build
build:
	@mkdir -p $(BINDIR)
	go build -o $(BINDIR)/$(APP) ./cmd/agent

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

.PHONY: test
test:
	go test ./...

.PHONY: coverage
coverage:
	go test ./... -coverpkg=./... -coverprofile=coverage.out
	go tool cover -html=coverage.out -o coverage.html







