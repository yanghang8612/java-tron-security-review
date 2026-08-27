#!/usr/bin/env bash
set -euo pipefail

ENABLE_TIMER=false
ENABLE_USERNS=false
SKIP_BUILD=false
IMAGE_NAME="${JTSR_INSTALL_IMAGE:-java-tron-security-review:local}"

usage() {
  printf 'Usage: sudo %s [--enable] [--enable-userns] [--skip-build] [--image IMAGE]\n' "$0"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --enable)
      ENABLE_TIMER=true
      shift
      ;;
    --enable-userns)
      ENABLE_USERNS=true
      shift
      ;;
    --skip-build)
      SKIP_BUILD=true
      shift
      ;;
    --image)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      IMAGE_NAME="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
done

if [[ "$(id -u)" -ne 0 ]]; then
  printf 'install.sh must run as root\n' >&2
  exit 1
fi

if [[ ! "$IMAGE_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9._/:@-]*$ ]]; then
  printf 'invalid image name: %s\n' "$IMAGE_NAME" >&2
  exit 1
fi

for required in docker git flock getent groupadd systemctl useradd; do
  if ! command -v "$required" >/dev/null 2>&1; then
    printf 'required command not found: %s\n' "$required" >&2
    exit 1
  fi
done
if [[ "$ENABLE_USERNS" == true ]] && ! command -v sysctl >/dev/null 2>&1; then
  printf 'required command not found: sysctl\n' >&2
  exit 1
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
CONFIG_DIR=/etc/java-tron-security-review
LIBEXEC_DIR=/usr/local/libexec/java-tron-security-review
OUTPUT_ROOT=/var/lib/java-tron-security-review/scans
WORK_ROOT=/var/lib/java-tron-security-review/work
AUTH_ROOT=/var/lib/java-tron-security-review/auth
SCANNER_USER=jtsr-scanner
SCANNER_UID=10001
SCANNER_GID=10001

if getent group "$SCANNER_USER" >/dev/null; then
  if [[ "$(getent group "$SCANNER_USER" | cut -d: -f3)" != "$SCANNER_GID" ]]; then
    printf 'group %s exists with an unexpected gid\n' "$SCANNER_USER" >&2
    exit 1
  fi
elif getent group "$SCANNER_GID" >/dev/null; then
  printf 'gid %s is already assigned; refusing to expose reports to that group\n' "$SCANNER_GID" >&2
  exit 1
else
  groupadd --gid "$SCANNER_GID" "$SCANNER_USER"
fi

if getent passwd "$SCANNER_USER" >/dev/null; then
  if [[ "$(id -u "$SCANNER_USER")" != "$SCANNER_UID" || "$(id -g "$SCANNER_USER")" != "$SCANNER_GID" ]]; then
    printf 'user %s exists with unexpected uid/gid\n' "$SCANNER_USER" >&2
    exit 1
  fi
elif getent passwd "$SCANNER_UID" >/dev/null; then
  printf 'uid %s is already assigned; refusing to expose reports to that user\n' "$SCANNER_UID" >&2
  exit 1
else
  NOLOGIN_SHELL="$(command -v nologin || printf /bin/false)"
  useradd \
    --uid "$SCANNER_UID" \
    --gid "$SCANNER_GID" \
    --no-create-home \
    --home-dir /nonexistent \
    --shell "$NOLOGIN_SHELL" \
    "$SCANNER_USER"
fi

if [[ "$SKIP_BUILD" == false ]]; then
  docker info >/dev/null
  docker build \
    --file "$PROJECT_DIR/deploy/container/Dockerfile" \
    --tag "$IMAGE_NAME" \
    "$PROJECT_DIR"
  docker run --rm "$IMAGE_NAME" jtsr --version
fi

install -d -m 0750 -o root -g root "$CONFIG_DIR"
install -d -m 0755 -o root -g root "$LIBEXEC_DIR"
install -d -m 0700 -o "$SCANNER_UID" -g "$SCANNER_GID" "$OUTPUT_ROOT"
install -d -m 0700 -o root -g root "$WORK_ROOT"
install -d -m 0700 -o "$SCANNER_UID" -g "$SCANNER_GID" "$AUTH_ROOT"

install -m 0755 "$SCRIPT_DIR/run-daily-tvm.sh" "$LIBEXEC_DIR/run-daily-tvm"
install -m 0755 "$SCRIPT_DIR/auth-chatgpt.sh" "$LIBEXEC_DIR/auth-chatgpt"
install -m 0755 "$SCRIPT_DIR/notify-failure.sh" "$LIBEXEC_DIR/notify-failure"
install -m 0644 "$SCRIPT_DIR/codex-security-seccomp.json" "$CONFIG_DIR/codex-security-seccomp.json"
install -m 0644 "$SCRIPT_DIR/java-tron-security-review-auth@.service" /etc/systemd/system/java-tron-security-review-auth@.service
install -m 0644 "$SCRIPT_DIR/java-tron-security-review.service" /etc/systemd/system/java-tron-security-review.service
install -m 0644 "$SCRIPT_DIR/java-tron-security-review.timer" /etc/systemd/system/java-tron-security-review.timer
install -m 0644 "$SCRIPT_DIR/java-tron-security-review-notify@.service" /etc/systemd/system/java-tron-security-review-notify@.service

if [[ ! -e "$CONFIG_DIR/jtsr.env" ]]; then
  install -m 0600 -o root -g root "$SCRIPT_DIR/jtsr.env.example" "$CONFIG_DIR/jtsr.env"
  printf 'Created %s/jtsr.env with ChatGPT device authentication selected.\n' "$CONFIG_DIR"
else
  chmod 0600 "$CONFIG_DIR/jtsr.env"
fi

systemctl daemon-reload
if [[ "$ENABLE_USERNS" == true ]]; then
  install -m 0644 "$SCRIPT_DIR/java-tron-security-review-userns.conf" \
    /etc/sysctl.d/90-java-tron-security-review-userns.conf
  sysctl -q -w user.max_user_namespaces=1024
fi
if [[ "$ENABLE_TIMER" == true ]]; then
  systemctl enable --now java-tron-security-review.timer
else
  printf 'Timer installed but not enabled. After editing %s/jtsr.env:\n' "$CONFIG_DIR"
  printf 'For JTSR_AUTH=chatgpt, authenticate with:\n'
  printf '  systemctl start --no-block java-tron-security-review-auth@login.service\n'
  printf '  journalctl -fu java-tron-security-review-auth@login.service\n'
  printf 'Then run the acceptance scan and enable the timer:\n'
  printf '  systemctl start java-tron-security-review.service\n'
  printf '  systemctl enable --now java-tron-security-review.timer\n'
fi

if [[ -r /proc/sys/user/max_user_namespaces ]] && \
   [[ "$(cat /proc/sys/user/max_user_namespaces)" == "0" ]]; then
  printf 'Codex Security sandbox is blocked because user.max_user_namespaces=0.\n' >&2
  printf 'Review the security implication, then rerun this installer with --enable-userns.\n' >&2
fi

printf 'Installed scanner image %s and single-server runtime files.\n' "$IMAGE_NAME"
if [[ "$IMAGE_NAME" != "java-tron-security-review:local" ]]; then
  printf 'Set JTSR_IMAGE=%s in %s/jtsr.env.\n' "$IMAGE_NAME" "$CONFIG_DIR"
fi
