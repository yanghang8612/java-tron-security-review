#!/usr/bin/env bash
set -euo pipefail

UNIT_NAME="${1:-java-tron-security-review.service}"
WEBHOOK_URL="${JTSR_FAILURE_WEBHOOK_URL:-}"

if [[ -z "$WEBHOOK_URL" ]]; then
  exit 0
fi

if ! command -v curl >/dev/null 2>&1; then
  logger -t java-tron-security-review "failure webhook configured but curl is unavailable"
  exit 0
fi

SAFE_UNIT="${UNIT_NAME//[^A-Za-z0-9@_.-]/_}"
HOST_NAME="$(hostname 2>/dev/null || printf unknown)"
SAFE_HOST="${HOST_NAME//[^A-Za-z0-9_.-]/_}"
FAILED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
PAYLOAD="$(printf '{\"event\":\"java-tron-security-review-failed\",\"unit\":\"%s\",\"host\":\"%s\",\"failed_at\":\"%s\"}' "$SAFE_UNIT" "$SAFE_HOST" "$FAILED_AT")"

curl \
  --fail \
  --silent \
  --show-error \
  --max-time 15 \
  --header 'Content-Type: application/json' \
  --data "$PAYLOAD" \
  "$WEBHOOK_URL" >/dev/null
