BINDIR ?= dist
APP    ?= backup-agent

PLATFORMS = \
	linux/amd64 \
	linux/arm64 \
	linux/arm \
	darwin/amd64 \
	darwin/arm64 \
	windows/amd64

# Android (phone-class agents). Deliberately NOT in PLATFORMS: unlike every
# other target this one needs CGO and an NDK cross-compiler, so it can't go
# through the CGO_ENABLED=0 build-all loop.
#
# CGO is required for DNS, not for kiosk: with CGO_ENABLED=0 Go uses its pure
# resolver, which reads /etc/resolv.conf — a file Android does not have. The
# agent then falls back to 127.0.0.1:53, nothing is listening there, and every
# hostname lookup fails. Building GOOS=android with the NDK links bionic's
# resolver, which asks netd and so honours the device's real DNS (Wi-Fi,
# cellular, VPN and Private DNS alike).
ANDROID_SDK   ?= $(HOME)/Android/Sdk
ANDROID_NDK   ?= $(ANDROID_SDK)/ndk/29.0.14206865
# Minimum API level. 26 matches the companion app's minSdk (app/companion/build.gradle.kts).
ANDROID_API   ?= 26
ANDROID_HOST  ?= linux-x86_64
ANDROID_CC     = $(ANDROID_NDK)/toolchains/llvm/prebuilt/$(ANDROID_HOST)/bin/aarch64-linux-android$(ANDROID_API)-clang

# Build for host platform with kiosk support (requires CGO + platform deps)
# Linux (Ubuntu 22.04+): apt install libgtk-3-dev libwebkit2gtk-4.1-dev
# Linux (Ubuntu 20.04):  apt install libgtk-3-dev libwebkit2gtk-4.0-dev
#                        then use `make build-kiosk-gtk40`
# macOS: WebKit included by default
# Windows: Microsoft Edge required
.PHONY: build
build:
	@mkdir -p $(BINDIR)
	CGO_ENABLED=1 go build -o $(BINDIR)/$(APP) ./cmd/agent

# Build with webkit2gtk-4.0 (for Ubuntu 20.04 / Debian 11 / older distros)
.PHONY: build-kiosk-gtk40
build-kiosk-gtk40:
	@mkdir -p $(BINDIR)
	CGO_ENABLED=1 go build -tags webkit_4_0 -o $(BINDIR)/$(APP) ./cmd/agent

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

# Cross-compile for Android/arm64 (phone-class agents running under adb shell
# or Termux). Requires the NDK: `app/setup-android-sdk.sh --with-ndk`.
.PHONY: build-android
build-android:
	@if [ ! -x "$(ANDROID_CC)" ]; then \
		echo "error: NDK compiler not found at $(ANDROID_CC)"; \
		echo "       install it with: app/setup-android-sdk.sh --with-ndk"; \
		echo "       or point ANDROID_NDK at an existing NDK install"; \
		exit 1; \
	fi
	@mkdir -p $(BINDIR)
	@echo ">> building android/arm64 -> $(BINDIR)/$(APP)-android-arm64"
	CC="$(ANDROID_CC)" GOOS=android GOARCH=arm64 CGO_ENABLED=1 \
		go build -trimpath -ldflags "-s -w" -o "$(BINDIR)/$(APP)-android-arm64" ./cmd/agent

# Container image (what the release workflow publishes as
# ghcr.io/austinkregel/compute-agent). Single-arch, for local testing; the
# multi-arch manifest is built by .github/workflows/release.yml.
IMAGE ?= ghcr.io/austinkregel/compute-agent
TAG   ?= dev

.PHONY: docker-build
docker-build:
	docker build \
		--build-arg VERSION=$(TAG) \
		--build-arg COMMIT=$$(git rev-parse HEAD 2>/dev/null || echo unknown) \
		--build-arg BUILD_DATE=$$(date -u +%Y-%m-%dT%H:%M:%SZ) \
		-t $(IMAGE):$(TAG) .

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







