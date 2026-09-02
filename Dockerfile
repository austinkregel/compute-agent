# syntax=docker/dockerfile:1

# Container image for the compute agent: `docker run` it on a machine and it
# starts reporting to the control plane. Published as
# ghcr.io/austinkregel/compute-agent by .github/workflows/release.yml.
#
# The build stage runs on the *build* platform and cross-compiles for the
# target — Go does that natively, so multi-arch builds don't pay for QEMU
# emulation of the compiler. CGO stays off: the container agent is the headless
# variant (kiosk needs GTK/WebKit, which has no place in a server image).
FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS build

ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

RUN set -eux; \
    case "${TARGETVARIANT}" in \
      v6) export GOARM=6 ;; \
      v7) export GOARM=7 ;; \
    esac; \
    CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
    go build \
      -trimpath \
      -ldflags "-s -w \
        -X 'github.com/austinkregel/compute-agent/pkg/version.Version=${VERSION}' \
        -X 'github.com/austinkregel/compute-agent/pkg/version.Commit=${COMMIT}' \
        -X 'github.com/austinkregel/compute-agent/pkg/version.BuildDate=${BUILD_DATE}'" \
      -o /out/backup-agent ./cmd/agent

FROM alpine:3.20 AS runtime

# bash  — interactive shell sessions (shell.command) and this entrypoint
# jq    — renders the agent config from env vars / Supervisor options
# rsync — used by pkg/backup for file transfers
# tzdata, ca-certificates — correct timestamps and TLS to the control plane
RUN apk add --no-cache bash ca-certificates jq rsync tzdata

ENV CLIENT_CONFIG_PATH=/data/agent-config.json \
    LOG_FILE=/data/agent.log \
    TZ=UTC

COPY --from=build /out/backup-agent /usr/local/bin/backup-agent
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/backup-agent /usr/local/bin/entrypoint.sh

# /data holds the rendered config, the log, and any agent state. Runs as root
# on purpose: the agent reads host telemetry, executes allowlisted admin
# commands, and (when the socket is mounted) talks to the Docker daemon.
RUN mkdir -p /data
VOLUME ["/data"]
WORKDIR /data

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["/usr/local/bin/backup-agent", "--config", "/data/agent-config.json"]
