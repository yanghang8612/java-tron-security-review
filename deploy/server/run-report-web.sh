#!/usr/bin/env bash
set -euo pipefail
umask 077
JTSR_WEB_IMAGE="${JTSR_WEB_IMAGE:-java-tron-security-review-web:local}"
JTSR_REPORT_ROOT="${JTSR_REPORT_ROOT:-/var/lib/java-tron-security-review/scans}"
[[ "$JTSR_WEB_IMAGE" =~ ^[A-Za-z0-9][A-Za-z0-9._/:@-]*$ ]] || exit 1
[[ "$JTSR_REPORT_ROOT" == /*/scans && "$JTSR_REPORT_ROOT" != *","* && ! -L "$JTSR_REPORT_ROOT" ]] || exit 1
[[ -d "$JTSR_REPORT_ROOT" ]] || exit 1
# Only reports and the portal password hash are mounted. No model auth or Docker socket.
exec docker run --rm --name java-tron-security-review-web \
  --user 10001:10001 \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --memory 512m --cpus 1 --pids-limit 64 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=8m \
  --publish 127.0.0.1:8765:8765 \
  --mount "type=bind,src=$JTSR_REPORT_ROOT,dst=/scan/reports,readonly" \
  --mount type=bind,src=/etc/java-tron-security-review/report-web-auth.json,dst=/run/report-auth.json,readonly \
  "$JTSR_WEB_IMAGE"
