#!/usr/bin/env bash
# Container entrypoint for the compute agent.
#
# pkg/config.Load() fails if the config file is missing, so a config must exist
# on disk before the binary starts. This script materializes one, serving both
# deployment shapes from a single image:
#
#   * plain Docker / compose — settings arrive as environment variables
#   * Home Assistant add-on  — the Supervisor writes /data/options.json
#
# Source precedence, highest first:
#   1. AGENT_CONFIG_JSON        — a complete config document, used verbatim
#   2. /data/options.json       — Home Assistant Supervisor options
#   3. a user-supplied config file already at $CLIENT_CONFIG_PATH
#   4. environment variables    — rendered into a config below
#
# (3) is distinguished from a config this script wrote on a previous boot by a
# sibling ".generated" marker: without it the file is the operator's and is left
# untouched, with it the file is ours and is re-rendered so changed env vars
# actually take effect.
#
# Anything the Go side already reads from the environment (SERVER_URL,
# AUTH_TOKEN, CLIENT_ID, STATS_INTERVAL_SEC, ... — see applyEnvOverrides in
# pkg/config/config.go) still applies on top of whichever source wins, so a
# mounted config can be adjusted without editing it.
set -euo pipefail

log() { echo "[entrypoint] $*"; }
die() { echo "[entrypoint] ERROR: $*" >&2; exit 1; }

CONFIG_PATH="${CLIENT_CONFIG_PATH:-/data/agent-config.json}"
GENERATED_MARKER="${CONFIG_PATH}.generated"
OPTIONS_FILE="/data/options.json"
# Host filesystem mount point, when the operator passes `-v /:/host:ro`.
HOST_MOUNT="${HOST_MOUNT:-/host}"

mkdir -p "$(dirname "$CONFIG_PATH")"

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

# env_or NAME DEFAULT — value of $NAME, or DEFAULT when unset/empty.
env_or() {
  local val="${!1:-}"
  if [ -z "$val" ]; then echo "$2"; else echo "$val"; fi
}

# opt_or KEY DEFAULT — value of .KEY in options.json, or DEFAULT when absent/empty.
opt_or() {
  local val
  val=$(jq -r ".$1 // empty" "$OPTIONS_FILE")
  if [ -z "$val" ]; then echo "$2"; else echo "$val"; fi
}

# to_bool NAME VALUE — canonical JSON true/false. Accepts the spellings people
# actually type in compose files; anything else fails here with a readable
# message rather than as a jq or JSON-unmarshal error further down.
to_bool() {
  case "$(echo "${2:-}" | tr '[:upper:]' '[:lower:]')" in
    1|true|yes|on)   echo "true" ;;
    0|false|no|off)  echo "false" ;;
    *) die "$1 must be true or false, got '${2:-}'" ;;
  esac
}

# to_int NAME VALUE — a bare integer, or a readable failure.
to_int() {
  case "${2:-}" in
    ''|*[!0-9]*) die "$1 must be a whole number, got '${2:-}'" ;;
    *) echo "$2" ;;
  esac
}

# json_list_from_csv "a,b,c" — a JSON array; empty input yields [].
json_list_from_csv() {
  if [ -z "${1:-}" ]; then
    echo '[]'
  else
    jq -cn --arg csv "$1" '$csv | split(",") | map(select(length > 0))'
  fi
}

# render_config — writes $CONFIG_PATH from the CFG_* variables set by a collector.
# Written with mode 0600 first: it holds the auth token.
render_config() {
  local tmp="${CONFIG_PATH}.tmp"
  ( umask 077
    jq -n \
      --arg clientId "$CFG_CLIENT_ID" \
      --arg serverUrl "$CFG_SERVER_URL" \
      --arg authToken "$CFG_AUTH_TOKEN" \
      --argjson statsIntervalSec "$CFG_STATS_INTERVAL" \
      --argjson heartbeatIntervalSec "$CFG_HEARTBEAT_INTERVAL" \
      --argjson pongTimeoutSec "$CFG_PONG_TIMEOUT" \
      --argjson updateCheckEnabled "$CFG_UPDATE_CHECK" \
      --arg logLevel "$CFG_LOG_LEVEL" \
      --argjson skipTlsVerify "$CFG_SKIP_TLS" \
      --arg transportPath "$CFG_TRANSPORT_PATH" \
      --argjson maxClockSkewSec "$CFG_MAX_CLOCK_SKEW" \
      --argjson enableShell "$CFG_ENABLE_SHELL" \
      --argjson shellIdleTimeoutSec "$CFG_SHELL_IDLE_TIMEOUT" \
      --argjson allowedCommands "$CFG_ALLOWED_COMMANDS" \
      --argjson allowedCwds "$CFG_ALLOWED_CWDS" \
      --argjson adminMaxConcurrent "$CFG_ADMIN_MAX_CONCURRENT" \
      --argjson adminDefaultTimeoutSec "$CFG_ADMIN_DEFAULT_TIMEOUT" \
      --argjson requireToken "$CFG_REQUIRE_TOKEN" \
      --arg commandToken "$CFG_COMMAND_TOKEN" \
      --argjson enableAlerts "$CFG_ENABLE_ALERTS" \
      --argjson alertsScanIntervalSec "$CFG_ALERTS_SCAN_INTERVAL" \
      --argjson backupSourceRoots "$CFG_BACKUP_SOURCE_ROOTS" \
      --argjson backupDestRoots "$CFG_BACKUP_DEST_ROOTS" \
      --argjson dirBrowseRoots "$CFG_DIRBROWSE_ROOTS" \
      --argjson dockerEnabled "$CFG_DOCKER_ENABLED" \
      --arg dockerSocket "$CFG_DOCKER_SOCKET" \
      --arg logFile "$CFG_LOG_FILE" \
      '{
        clientId: $clientId,
        serverUrl: $serverUrl,
        authToken: $authToken,
        statsIntervalSec: $statsIntervalSec,
        heartbeatIntervalSec: $heartbeatIntervalSec,
        pongTimeoutSec: $pongTimeoutSec,
        updateCheckEnabled: $updateCheckEnabled,
        connectivity: { dnsTestHost: "", tcpTestHost: "", tcpTestPort: 53 },
        admin: {
          enableShell: $enableShell,
          allowedCommands: $allowedCommands,
          allowedCwds: $allowedCwds,
          maxConcurrent: $adminMaxConcurrent,
          defaultTimeoutSec: $adminDefaultTimeoutSec,
          requireToken: $requireToken,
          commandToken: $commandToken,
          rateLimitMax: 0,
          rateLimitWindowSec: 0
        },
        backup: {
          allowedSourceRoots: $backupSourceRoots,
          allowedDestRoots: $backupDestRoots
        },
        transport: {
          skipTlsVerify: $skipTlsVerify,
          path: $transportPath,
          maxClockSkewSec: $maxClockSkewSec
        },
        logging: { file: $logFile, level: $logLevel },
        shell: { command: "/bin/bash", args: ["-l"], idleTimeoutSec: $shellIdleTimeoutSec },
        dirBrowse: {
          allowedRoots: $dirBrowseRoots,
          sshHostKeyPolicy: "known_hosts",
          smbProfiles: {}
        },
        kiosk: { enabled: false },
        alerts: {
          enabled: $enableAlerts,
          scanIntervalSec: $alertsScanIntervalSec,
          maxAlerts: 50,
          lookbackHours: 24,
          categories: []
        },
        docker: { enabled: $dockerEnabled, socketPath: $dockerSocket },
        variant: { desired: "headless" }
      }' > "$tmp"
  )
  mv "$tmp" "$CONFIG_PATH"
  : > "$GENERATED_MARKER"
}

# ---------------------------------------------------------------------------
# collectors
# ---------------------------------------------------------------------------

# Values shared by both collectors. The container agent never self-updates: the
# binary lives in a read-only image layer, so a new version arrives as a new
# image, not as a downloaded replacement.
collect_common_defaults() {
  CFG_UPDATE_CHECK="false"
  CFG_LOG_FILE="/data/agent.log"
  CFG_DOCKER_SOCKET=""
}

collect_from_options() {
  log "Home Assistant add-on mode (reading $OPTIONS_FILE)"
  collect_common_defaults

  CFG_CLIENT_ID=$(opt_or "client_id" "$(hostname)")
  CFG_SERVER_URL=$(opt_or "server_url" "")
  CFG_AUTH_TOKEN=$(opt_or "auth_token" "")
  CFG_STATS_INTERVAL=$(opt_or "stats_interval_sec" "60")
  CFG_HEARTBEAT_INTERVAL=$(opt_or "heartbeat_interval_sec" "20")
  CFG_PONG_TIMEOUT=$(opt_or "pong_timeout_sec" "90")
  CFG_LOG_LEVEL=$(opt_or "log_level" "info")
  CFG_SKIP_TLS=$(opt_or "skip_tls_verify" "false")
  CFG_TRANSPORT_PATH=$(opt_or "transport_path" "/ws/agent")
  CFG_MAX_CLOCK_SKEW=$(opt_or "max_clock_skew_sec" "300")
  CFG_ENABLE_SHELL=$(opt_or "enable_shell" "false")
  CFG_SHELL_IDLE_TIMEOUT=$(opt_or "shell_idle_timeout_sec" "60")
  CFG_ADMIN_MAX_CONCURRENT=$(opt_or "admin_max_concurrent" "1")
  CFG_ADMIN_DEFAULT_TIMEOUT=$(opt_or "admin_default_timeout_sec" "30")
  CFG_REQUIRE_TOKEN=$(opt_or "require_command_token" "false")
  CFG_COMMAND_TOKEN=$(opt_or "command_token" "")
  CFG_ENABLE_ALERTS=$(opt_or "enable_alerts" "true")
  CFG_ALERTS_SCAN_INTERVAL=$(opt_or "alerts_scan_interval_sec" "300")
  CFG_ALLOWED_COMMANDS=$(jq -c '.allowed_commands // []' "$OPTIONS_FILE")
  CFG_ALLOWED_CWDS=$(jq -c '.allowed_cwds // []' "$OPTIONS_FILE")

  # Supervisor-mapped volumes (see the add-on's config.yaml `map:` block).
  CFG_BACKUP_SOURCE_ROOTS='["/homeassistant","/ssl","/media"]'
  CFG_BACKUP_DEST_ROOTS='["/backup","/share"]'
  CFG_DIRBROWSE_ROOTS='["/homeassistant","/backup","/share","/ssl","/media","/data"]'
  # No Docker socket is mapped into an add-on container.
  CFG_DOCKER_ENABLED="false"
}

collect_from_env() {
  log "environment mode"
  collect_common_defaults

  CFG_CLIENT_ID=$(env_or CLIENT_ID "$(hostname)")
  if [ -z "${CLIENT_ID:-}" ]; then
    # Without --network host or --hostname, this is the container ID, which
    # changes on every recreate and shows up as a brand-new machine in the
    # fleet roster.
    log "WARNING: CLIENT_ID unset, falling back to hostname '$CFG_CLIENT_ID'"
  fi
  CFG_SERVER_URL=$(env_or SERVER_URL "")
  CFG_AUTH_TOKEN=$(env_or AUTH_TOKEN "")
  CFG_STATS_INTERVAL=$(to_int STATS_INTERVAL_SEC "$(env_or STATS_INTERVAL_SEC "60")")
  CFG_HEARTBEAT_INTERVAL=$(to_int HEARTBEAT_INTERVAL_SEC "$(env_or HEARTBEAT_INTERVAL_SEC "20")")
  CFG_PONG_TIMEOUT=$(to_int PONG_TIMEOUT_SEC "$(env_or PONG_TIMEOUT_SEC "90")")
  CFG_LOG_LEVEL=$(env_or LOG_LEVEL "info")
  CFG_SKIP_TLS=$(to_bool AGENT_SKIP_TLS_VERIFY "$(env_or AGENT_SKIP_TLS_VERIFY "false")")
  CFG_TRANSPORT_PATH=$(env_or TRANSPORT_PATH "/ws/agent")
  CFG_MAX_CLOCK_SKEW=$(to_int MAX_CLOCK_SKEW_SEC "$(env_or MAX_CLOCK_SKEW_SEC "300")")
  CFG_ENABLE_SHELL=$(to_bool ENABLE_SHELL "$(env_or ENABLE_SHELL "false")")
  CFG_SHELL_IDLE_TIMEOUT=$(to_int SHELL_IDLE_TIMEOUT_SEC "$(env_or SHELL_IDLE_TIMEOUT_SEC "60")")
  CFG_ADMIN_MAX_CONCURRENT=$(to_int ADMIN_MAX_CONCURRENT "$(env_or ADMIN_MAX_CONCURRENT "1")")
  CFG_ADMIN_DEFAULT_TIMEOUT=$(to_int ADMIN_DEFAULT_TIMEOUT_SEC "$(env_or ADMIN_DEFAULT_TIMEOUT_SEC "30")")
  CFG_REQUIRE_TOKEN=$(to_bool REQUIRE_COMMAND_TOKEN "$(env_or REQUIRE_COMMAND_TOKEN "false")")
  CFG_COMMAND_TOKEN=$(env_or COMMAND_TOKEN "")
  CFG_ENABLE_ALERTS=$(to_bool ENABLE_ALERTS "$(env_or ENABLE_ALERTS "true")")
  CFG_ALERTS_SCAN_INTERVAL=$(to_int ALERTS_SCAN_INTERVAL_SEC "$(env_or ALERTS_SCAN_INTERVAL_SEC "300")")
  CFG_ALLOWED_COMMANDS=$(json_list_from_csv "${ADMIN_ALLOWED_COMMANDS:-}")
  CFG_ALLOWED_CWDS=$(json_list_from_csv "${ADMIN_ALLOWED_CWDS:-}")

  CFG_DOCKER_ENABLED=$(to_bool AGENT_DOCKER_ENABLED "$(env_or AGENT_DOCKER_ENABLED "true")")
  CFG_DOCKER_SOCKET=$(env_or AGENT_DOCKER_SOCKET "")

  # Default file roots stay narrow: the agent's own /data volume, plus the host
  # filesystem only when the operator explicitly mounted it. Widen deliberately
  # with BACKUP_SOURCE_ROOTS / BACKUP_DEST_ROOTS / DIRBROWSE_ROOTS.
  local default_roots="/data"
  if [ -d "$HOST_MOUNT" ]; then
    log "host filesystem detected at $HOST_MOUNT"
    default_roots="/data,$HOST_MOUNT"
  fi
  CFG_BACKUP_SOURCE_ROOTS=$(json_list_from_csv "$(env_or BACKUP_SOURCE_ROOTS "$default_roots")")
  CFG_BACKUP_DEST_ROOTS=$(json_list_from_csv "$(env_or BACKUP_DEST_ROOTS "/data")")
  CFG_DIRBROWSE_ROOTS=$(json_list_from_csv "$(env_or DIRBROWSE_ROOTS "$default_roots")")
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

if [ -n "${AGENT_CONFIG_JSON:-}" ]; then
  log "writing config from AGENT_CONFIG_JSON -> $CONFIG_PATH"
  ( umask 077; printf '%s' "$AGENT_CONFIG_JSON" > "${CONFIG_PATH}.tmp" )
  mv "${CONFIG_PATH}.tmp" "$CONFIG_PATH"
  rm -f "$GENERATED_MARKER"
elif [ -f "$OPTIONS_FILE" ]; then
  collect_from_options
  [ -n "$CFG_SERVER_URL" ] || die "server_url is required"
  [ -n "$CFG_AUTH_TOKEN" ] || die "auth_token is required"
  render_config
  log "config written to $CONFIG_PATH"
elif [ -f "$CONFIG_PATH" ] && [ ! -f "$GENERATED_MARKER" ]; then
  log "using operator-supplied config at $CONFIG_PATH"
else
  collect_from_env
  [ -n "$CFG_SERVER_URL" ] || die "SERVER_URL is required (or mount a config at $CONFIG_PATH)"
  [ -n "$CFG_AUTH_TOKEN" ] || die "AUTH_TOKEN is required (or mount a config at $CONFIG_PATH)"
  render_config
  log "config written to $CONFIG_PATH"
fi

log "starting $(/usr/local/bin/backup-agent --version 2>/dev/null || echo backup-agent)"
exec "$@"
