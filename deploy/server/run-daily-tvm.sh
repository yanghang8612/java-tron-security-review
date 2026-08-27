#!/usr/bin/env bash
set -euo pipefail

umask 077

fail() {
  printf 'java-tron-security-review: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
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

if [[ "$(id -u)" -ne 0 ]]; then
  fail "run as root through the installed systemd service"
fi

require_command docker
require_command flock
require_command git
require_command mktemp
require_command realpath

JTSR_IMAGE="${JTSR_IMAGE:-java-tron-security-review:local}"
JTSR_PROVIDER="${JTSR_PROVIDER:-openai}"
JTSR_AUTH="${JTSR_AUTH:-api-key}"
JTSR_TARGET_REPOSITORY_URL="${JTSR_TARGET_REPOSITORY_URL:-https://github.com/tronprotocol/java-tron.git}"
JTSR_TARGET_REF="${JTSR_TARGET_REF:-develop}"
JTSR_OUTPUT_ROOT="${JTSR_OUTPUT_ROOT:-/var/lib/java-tron-security-review/scans}"
JTSR_WORK_ROOT="${JTSR_WORK_ROOT:-/var/lib/java-tron-security-review/work}"
JTSR_AUTH_ROOT="${JTSR_AUTH_ROOT:-/var/lib/java-tron-security-review/auth}"
JTSR_RETENTION_DAYS="${JTSR_RETENTION_DAYS:-90}"
JTSR_MEMORY_LIMIT="${JTSR_MEMORY_LIMIT:-8g}"
JTSR_CPU_LIMIT="${JTSR_CPU_LIMIT:-4}"
JTSR_PIDS_LIMIT="${JTSR_PIDS_LIMIT:-512}"
JTSR_DOCKER_NETWORK="${JTSR_DOCKER_NETWORK:-bridge}"
JTSR_SCANNER_UID="${JTSR_SCANNER_UID:-10001}"
JTSR_SCANNER_GID="${JTSR_SCANNER_GID:-10001}"

JTSR_OUTPUT_ROOT="$(realpath -m -- "$JTSR_OUTPUT_ROOT")"
JTSR_WORK_ROOT="$(realpath -m -- "$JTSR_WORK_ROOT")"
JTSR_AUTH_ROOT="$(realpath -m -- "$JTSR_AUTH_ROOT")"

validate_absolute_directory JTSR_OUTPUT_ROOT "$JTSR_OUTPUT_ROOT"
validate_absolute_directory JTSR_WORK_ROOT "$JTSR_WORK_ROOT"
validate_absolute_directory JTSR_AUTH_ROOT "$JTSR_AUTH_ROOT"
[[ "$JTSR_OUTPUT_ROOT" != "$JTSR_WORK_ROOT" ]] || fail "output and work roots must differ"
[[ "$JTSR_OUTPUT_ROOT" != "$JTSR_WORK_ROOT"/* ]] || fail "output root must not be inside the work root"
[[ "$JTSR_WORK_ROOT" != "$JTSR_OUTPUT_ROOT"/* ]] || fail "work root must not be inside the output root"
[[ "$JTSR_AUTH_ROOT" != "$JTSR_OUTPUT_ROOT" && "$JTSR_AUTH_ROOT" != "$JTSR_OUTPUT_ROOT"/* ]] || fail "auth root must not be inside the output root"
[[ "$JTSR_OUTPUT_ROOT" != "$JTSR_AUTH_ROOT"/* ]] || fail "output root must not be inside the auth root"
[[ "$JTSR_AUTH_ROOT" != "$JTSR_WORK_ROOT" && "$JTSR_AUTH_ROOT" != "$JTSR_WORK_ROOT"/* ]] || fail "auth root must not be inside the work root"
[[ "$JTSR_WORK_ROOT" != "$JTSR_AUTH_ROOT"/* ]] || fail "work root must not be inside the auth root"
[[ "$JTSR_IMAGE" =~ ^[A-Za-z0-9][A-Za-z0-9._/:@-]*$ ]] || fail "JTSR_IMAGE has an invalid format"
[[ "$JTSR_DOCKER_NETWORK" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || fail "JTSR_DOCKER_NETWORK has an invalid format"
[[ "$JTSR_RETENTION_DAYS" =~ ^[1-9][0-9]*$ ]] || fail "JTSR_RETENTION_DAYS must be a positive integer"
[[ "$JTSR_PIDS_LIMIT" =~ ^[1-9][0-9]*$ ]] || fail "JTSR_PIDS_LIMIT must be a positive integer"
[[ "$JTSR_SCANNER_UID" =~ ^[1-9][0-9]*$ ]] || fail "JTSR_SCANNER_UID must be a positive integer"
[[ "$JTSR_SCANNER_GID" =~ ^[1-9][0-9]*$ ]] || fail "JTSR_SCANNER_GID must be a positive integer"
[[ "$JTSR_CPU_LIMIT" =~ ^([1-9][0-9]*([.][0-9]+)?|0[.][0-9]*[1-9][0-9]*)$ ]] || fail "JTSR_CPU_LIMIT must be positive"
[[ "$JTSR_MEMORY_LIMIT" =~ ^[1-9][0-9]*[kKmMgG]?$ ]] || fail "JTSR_MEMORY_LIMIT has an invalid format"
[[ "$JTSR_TARGET_REPOSITORY_URL" == https://* ]] || fail "target repository URL must use HTTPS"
[[ "$JTSR_TARGET_REF" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]*$ ]] || fail "target ref contains unsupported characters"
[[ "$JTSR_TARGET_REF" != *".."* && "$JTSR_TARGET_REF" != *"@{"* ]] || fail "target ref is unsafe"

install -d -m 0700 -o "$JTSR_SCANNER_UID" -g "$JTSR_SCANNER_GID" "$JTSR_OUTPUT_ROOT"
install -d -m 0700 -o root -g root "$JTSR_WORK_ROOT"

exec 9>"$JTSR_WORK_ROOT/daily-tvm.lock"
if ! flock -n 9; then
  printf 'java-tron-security-review: another scan is already running; skipping overlap\n'
  exit 0
fi

RUNTIME_DOCKER_ARGS=()
RUNTIME_SCAN_ARGS=()

case "$JTSR_PROVIDER" in
  openai)
    case "$JTSR_AUTH" in
      api-key)
        if [[ -z "${OPENAI_API_KEY:-}" && -z "${CODEX_API_KEY:-}" ]]; then
          fail "OPENAI_API_KEY or CODEX_API_KEY is required for API-key authentication"
        fi
        if [[ -n "${OPENAI_API_KEY:-}" ]]; then
          RUNTIME_DOCKER_ARGS+=(--env OPENAI_API_KEY)
        fi
        if [[ -n "${CODEX_API_KEY:-}" ]]; then
          RUNTIME_DOCKER_ARGS+=(--env CODEX_API_KEY)
        fi
        RUNTIME_SCAN_ARGS+=(--auth api-key)
        ;;
      chatgpt)
        install -d -m 0700 -o "$JTSR_SCANNER_UID" -g "$JTSR_SCANNER_GID" "$JTSR_AUTH_ROOT"
        RUNTIME_DOCKER_ARGS+=(
          --mount "type=bind,src=$JTSR_AUTH_ROOT,dst=/scan/auth"
          --env CODEX_HOME=/scan/auth
        )
        RUNTIME_SCAN_ARGS+=(--auth chatgpt)

        AUTH_CHECK_ARGS=(
          run --rm
          --name "jtsr-auth-check-$$"
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
          --mount "type=bind,src=$JTSR_AUTH_ROOT,dst=/scan/auth"
          --env CODEX_HOME=/scan/auth
          --env HOME=/home/scanner
          --env TMPDIR=/tmp
          --env NO_COLOR=1
        )
        for proxy_name in HTTPS_PROXY HTTP_PROXY ALL_PROXY NO_PROXY; do
          if [[ -n "${!proxy_name:-}" ]]; then
            AUTH_CHECK_ARGS+=(--env "$proxy_name")
          fi
        done
        if ! docker "${AUTH_CHECK_ARGS[@]}" "$JTSR_IMAGE" codex-security login status; then
          fail "ChatGPT sign-in is missing or expired; run the installed auth@login service"
        fi
        ;;
      *)
        fail "unsupported JTSR_AUTH for the OpenAI provider: $JTSR_AUTH"
        ;;
    esac
    if [[ -n "${JTSR_MODEL:-}" ]]; then
      RUNTIME_SCAN_ARGS+=(--model "$JTSR_MODEL")
    fi
    ;;
  amazon-bedrock)
    [[ -n "${JTSR_MODEL:-}" ]] || fail "JTSR_MODEL is required for Amazon Bedrock"
    [[ -n "${AWS_REGION:-${AWS_DEFAULT_REGION:-}}" ]] || fail "AWS_REGION is required for Amazon Bedrock"
    for aws_name in \
      AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_REGION AWS_DEFAULT_REGION \
      AWS_BEARER_TOKEN_BEDROCK AWS_EC2_METADATA_DISABLED AWS_SDK_LOAD_CONFIG; do
      if [[ -n "${!aws_name:-}" ]]; then
        RUNTIME_DOCKER_ARGS+=(--env "$aws_name")
      fi
    done
    RUNTIME_SCAN_ARGS+=(--provider amazon-bedrock --model "$JTSR_MODEL")
    ;;
  *)
    fail "unsupported JTSR_PROVIDER: $JTSR_PROVIDER"
    ;;
esac

# Retention is restricted to run directories created by this script. State, status,
# and arbitrary directories under the output root are never selected.
find "$JTSR_OUTPUT_ROOT" \
  -mindepth 1 -maxdepth 1 -type d \
  -name '????????T??????Z-daily-tvm-[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]' \
  -mtime "+$JTSR_RETENTION_DAYS" \
  -print -exec rm -rf -- {} +

RUN_WORK="$(mktemp -d "$JTSR_WORK_ROOT/run.XXXXXXXX")"
TARGET_DIR="$RUN_WORK/target"
GIT_HOME="$RUN_WORK/git-home"
install -d -m 0700 "$GIT_HOME"

# git -C was added after the Git version shipped by older systemd 219 hosts.
# A subshell keeps directory changes scoped while remaining compatible with Git 1.8.3.
git_in_target() (
  cd -- "$TARGET_DIR"
  git "$@"
)

cleanup() {
  local cleanup_target="${RUN_WORK:-}"
  if [[ -n "$cleanup_target" && -d "$cleanup_target" && "$cleanup_target" == "$JTSR_WORK_ROOT"/run.* ]]; then
    chmod -R u+w "$cleanup_target" 2>/dev/null || true
    rm -rf -- "$cleanup_target"
  fi
}
trap cleanup EXIT INT TERM

export GIT_CONFIG_NOSYSTEM=1
export GIT_TERMINAL_PROMPT=0
export HOME="$GIT_HOME"

git -c credential.helper= init "$TARGET_DIR"
git_in_target remote add origin "$JTSR_TARGET_REPOSITORY_URL"
git_in_target -c credential.helper= fetch --depth=1 --no-tags origin "$JTSR_TARGET_REF"
git_in_target checkout --detach FETCH_HEAD
TARGET_SHA="$(git_in_target rev-parse HEAD)"
[[ "$TARGET_SHA" =~ ^[0-9a-f]{40}$ ]] || fail "target revision is not a full commit SHA"
# The checkout is created under umask 077, but the container deliberately runs as uid 10001.
# Make only this bind-mounted tree readable/traversable while keeping it immutable. The parent
# work directory remains root-owned mode 0700, so other host users cannot traverse into it.
chmod -R a+rX,a-w "$TARGET_DIR"

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-daily-tvm-${TARGET_SHA:0:12}"
RUN_DIR="$JTSR_OUTPUT_ROOT/$RUN_ID"
install -d -m 0700 -o "$JTSR_SCANNER_UID" -g "$JTSR_SCANNER_GID" "$RUN_DIR"
printf '%s\n' "$TARGET_SHA" > "$RUN_DIR/target-revision.txt"
chown "$JTSR_SCANNER_UID:$JTSR_SCANNER_GID" "$RUN_DIR/target-revision.txt"

DOCKER_ARGS=(
  run --rm
  --name "jtsr-${RUN_ID,,}"
  --user "$JTSR_SCANNER_UID:$JTSR_SCANNER_GID"
  --read-only
  --cap-drop ALL
  --security-opt no-new-privileges
  --pids-limit "$JTSR_PIDS_LIMIT"
  --memory "$JTSR_MEMORY_LIMIT"
  --cpus "$JTSR_CPU_LIMIT"
  --network "$JTSR_DOCKER_NETWORK"
  --tmpfs "/tmp:rw,nosuid,nodev,noexec,size=1g,uid=$JTSR_SCANNER_UID,gid=$JTSR_SCANNER_GID"
  --tmpfs "/home/scanner:rw,nosuid,nodev,noexec,size=256m,uid=$JTSR_SCANNER_UID,gid=$JTSR_SCANNER_GID"
  --mount "type=bind,src=$TARGET_DIR,dst=/scan/target,readonly"
  --mount "type=bind,src=$JTSR_OUTPUT_ROOT,dst=/scan/output"
  --env HOME=/home/scanner
  --env TMPDIR=/tmp
  --env NO_COLOR=1
)
DOCKER_ARGS+=("${RUNTIME_DOCKER_ARGS[@]}")

for proxy_name in HTTPS_PROXY HTTP_PROXY ALL_PROXY NO_PROXY; do
  if [[ -n "${!proxy_name:-}" ]]; then
    DOCKER_ARGS+=(--env "$proxy_name")
  fi
done

SCAN_ARGS=(
  jtsr scan
  --mode daily-tvm
  --target /scan/target
  --head "$TARGET_SHA"
  --output-root /scan/output
  --run-id "$RUN_ID"
  --cli-bin /usr/local/bin/codex-security
)
SCAN_ARGS+=("${RUNTIME_SCAN_ARGS[@]}")

printf 'java-tron-security-review: scanning %s at %s into %s\n' \
  "$JTSR_TARGET_REF" "$TARGET_SHA" "$RUN_DIR"

set +e
docker "${DOCKER_ARGS[@]}" "$JTSR_IMAGE" "${SCAN_ARGS[@]}"
SCAN_EXIT=$?
set -e

COMPLETED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
STATUS_TMP="$JTSR_OUTPUT_ROOT/.last-run.json.$$"
printf '{"completed_at":"%s","exit_code":%d,"run_id":"%s","target_revision":"%s"}\n' \
  "$COMPLETED_AT" "$SCAN_EXIT" "$RUN_ID" "$TARGET_SHA" > "$STATUS_TMP"
chmod 0600 "$STATUS_TMP"
mv -f "$STATUS_TMP" "$JTSR_OUTPUT_ROOT/last-run.json"
ln -sfn "$RUN_ID" "$JTSR_OUTPUT_ROOT/latest"
if [[ "$SCAN_EXIT" -eq 0 ]]; then
  ln -sfn "$RUN_ID" "$JTSR_OUTPUT_ROOT/latest-successful"
fi

if [[ "$SCAN_EXIT" -eq 2 ]]; then
  printf 'java-tron-security-review: scan finished with partial coverage (exit 2)\n' >&2
elif [[ "$SCAN_EXIT" -ne 0 ]]; then
  printf 'java-tron-security-review: scan failed with exit %d\n' "$SCAN_EXIT" >&2
fi
exit "$SCAN_EXIT"
