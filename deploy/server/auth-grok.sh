#!/usr/bin/env bash
set -euo pipefail

umask 077

ACTION="${1:-status}"

fail() {
  printf 'java-tron-security-review Grok auth: %s\n' "$*" >&2
  exit 1
}

validate_absolute_directory() {
  local name="$1"
  local value="$2"
  [[ "$value" == /* ]] || fail "$name must be an absolute path"
  [[ "$value" != *","* ]] || fail "$name must not contain a comma"
  case "$value" in
    /|/bin|/boot|/dev|/etc|/home|/opt|/proc|/root|/run|/sbin|/srv|/sys|/tmp|/usr|/var|/var/lib)
      fail "$name is too broad: $value"
      ;;
  esac
}

[[ "$(id -u)" -eq 0 ]] || fail "run through the installed systemd Grok auth service"
case "$ACTION" in
  login|status|logout) ;;
  *) fail "action must be login, status, or logout" ;;
esac

for command in docker flock realpath; do
  command -v "$command" >/dev/null 2>&1 || fail "required command not found: $command"
done

JTSR_IMAGE="${JTSR_IMAGE:-java-tron-security-review:local}"
JTSR_GROK_AUTH_ROOT="${JTSR_GROK_AUTH_ROOT:-/var/lib/java-tron-security-review/grok-auth}"
JTSR_OUTPUT_ROOT="${JTSR_OUTPUT_ROOT:-/var/lib/java-tron-security-review/scans}"
JTSR_WORK_ROOT="${JTSR_WORK_ROOT:-/var/lib/java-tron-security-review/work}"
JTSR_DOCKER_NETWORK="${JTSR_DOCKER_NETWORK:-bridge}"
JTSR_SCANNER_UID="${JTSR_SCANNER_UID:-10001}"
JTSR_SCANNER_GID="${JTSR_SCANNER_GID:-10001}"

[[ "$JTSR_IMAGE" =~ ^[A-Za-z0-9][A-Za-z0-9._/:@-]*$ ]] || fail "JTSR_IMAGE has an invalid format"
[[ "$JTSR_DOCKER_NETWORK" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || fail "JTSR_DOCKER_NETWORK has an invalid format"
[[ "$JTSR_SCANNER_UID" =~ ^[1-9][0-9]*$ ]] || fail "JTSR_SCANNER_UID must be a positive integer"
[[ "$JTSR_SCANNER_GID" =~ ^[1-9][0-9]*$ ]] || fail "JTSR_SCANNER_GID must be a positive integer"

JTSR_GROK_AUTH_ROOT="$(realpath -m -- "$JTSR_GROK_AUTH_ROOT")"
JTSR_OUTPUT_ROOT="$(realpath -m -- "$JTSR_OUTPUT_ROOT")"
JTSR_WORK_ROOT="$(realpath -m -- "$JTSR_WORK_ROOT")"
validate_absolute_directory JTSR_GROK_AUTH_ROOT "$JTSR_GROK_AUTH_ROOT"
validate_absolute_directory JTSR_OUTPUT_ROOT "$JTSR_OUTPUT_ROOT"
validate_absolute_directory JTSR_WORK_ROOT "$JTSR_WORK_ROOT"
[[ "$JTSR_GROK_AUTH_ROOT" != "$JTSR_OUTPUT_ROOT" && "$JTSR_GROK_AUTH_ROOT" != "$JTSR_OUTPUT_ROOT"/* ]] || fail "Grok auth root must not be inside the output root"
[[ "$JTSR_OUTPUT_ROOT" != "$JTSR_GROK_AUTH_ROOT"/* ]] || fail "output root must not be inside the Grok auth root"
[[ "$JTSR_GROK_AUTH_ROOT" != "$JTSR_WORK_ROOT" && "$JTSR_GROK_AUTH_ROOT" != "$JTSR_WORK_ROOT"/* ]] || fail "Grok auth root must not be inside the work root"
[[ "$JTSR_WORK_ROOT" != "$JTSR_GROK_AUTH_ROOT"/* ]] || fail "work root must not be inside the Grok auth root"

install -d -m 0700 -o "$JTSR_SCANNER_UID" -g "$JTSR_SCANNER_GID" "$JTSR_GROK_AUTH_ROOT"
install -d -m 0700 -o root -g root "$JTSR_WORK_ROOT"

exec 9>"$JTSR_WORK_ROOT/daily-tvm.lock"
flock -n 9 || fail "a scan or another authentication action is already running"

case "$ACTION" in
  login) CLI_ARGS=(login --device-auth) ;;
  status) CLI_ARGS=(models) ;;
  logout) CLI_ARGS=(logout) ;;
esac

DOCKER_ARGS=(
  run --rm
  --name "jtsr-grok-auth-${ACTION}-$$"
  --user "$JTSR_SCANNER_UID:$JTSR_SCANNER_GID"
  --read-only
  --cap-drop ALL
  --security-opt no-new-privileges
  --pids-limit 128
  --memory 1g
  --cpus 1
  --network "$JTSR_DOCKER_NETWORK"
  --tmpfs "/tmp:rw,nosuid,nodev,noexec,size=128m,uid=$JTSR_SCANNER_UID,gid=$JTSR_SCANNER_GID"
  --tmpfs "/home/scanner:rw,nosuid,nodev,noexec,size=64m,uid=$JTSR_SCANNER_UID,gid=$JTSR_SCANNER_GID"
  --mount "type=bind,src=$JTSR_GROK_AUTH_ROOT,dst=/scan/grok-auth"
  --env GROK_HOME=/scan/grok-auth
  --env HOME=/home/scanner
  --env TMPDIR=/tmp
  --env NO_COLOR=1
)

for proxy_name in HTTPS_PROXY HTTP_PROXY ALL_PROXY NO_PROXY; do
  if [[ -n "${!proxy_name:-}" ]]; then
    DOCKER_ARGS+=(--env "$proxy_name")
  fi
done

exec docker "${DOCKER_ARGS[@]}" "$JTSR_IMAGE" grok "${CLI_ARGS[@]}"
