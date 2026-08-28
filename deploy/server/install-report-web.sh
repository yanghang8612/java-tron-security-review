#!/usr/bin/env bash
set -euo pipefail
umask 077
[[ "$(id -u)" == 0 ]] || { printf 'Run this installer as root.\n' >&2; exit 1; }
REPO_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
NGINX_CONFIG=""
BASE_IMAGE=java-tron-security-review:local
while [[ $# -gt 0 ]]; do
  case "$1" in
    --nginx-config) NGINX_CONFIG="$2"; shift 2 ;;
    --base-image) BASE_IMAGE="$2"; shift 2 ;;
    *) printf 'Unknown option: %s\n' "$1" >&2; exit 1 ;;
  esac
done
for tool in docker systemctl curl ss install; do command -v "$tool" >/dev/null; done
CONFIG_DIR=/etc/java-tron-security-review
LIBEXEC_DIR=/usr/local/libexec/java-tron-security-review
WEB_SERVICE=java-tron-security-review-web.service
docker image inspect "$BASE_IMAGE" >/dev/null
[[ -d /var/lib/java-tron-security-review/scans ]] || { printf 'Install the scanner first.\n' >&2; exit 1; }
if [[ -n "$NGINX_CONFIG" ]]; then
  [[ "$NGINX_CONFIG" == /etc/nginx/conf.d/*.conf && -f "$NGINX_CONFIG" && ! -L "$NGINX_CONFIG" ]] || exit 1
  nginx -t
fi
if ss -lnt '( sport = :8765 )' | tail -n +2 | grep -q .; then
  systemctl is-active --quiet "$WEB_SERVICE" || { printf 'Port 8765 is already in use.\n' >&2; exit 1; }
fi
install -d -m 0750 "$CONFIG_DIR" "$LIBEXEC_DIR"
if [[ ! -f "$CONFIG_DIR/report-web.env" ]]; then
  install -m 0600 "$REPO_DIR/deploy/server/report-web.env.example" "$CONFIG_DIR/report-web.env"
fi
# This is a separate, root-managed environment file. Never source scanner credentials.
source "$CONFIG_DIR/report-web.env"
[[ "$JTSR_WEB_IMAGE" != "$BASE_IMAGE" ]] || { printf 'Web and scanner image tags must differ.\n' >&2; exit 1; }
docker build --network none --build-arg "JTSR_BASE_IMAGE=$BASE_IMAGE" \
  --file "$REPO_DIR/deploy/container/Dockerfile.report" --tag "$JTSR_WEB_IMAGE" "$REPO_DIR"
if [[ ! -e "$CONFIG_DIR/report-web-auth.json" && ! -e "$CONFIG_DIR/report-web-login.txt" ]]; then
  docker run --rm --user 0:0 --network none --read-only --cap-drop ALL \
    --security-opt no-new-privileges \
    --mount "type=bind,src=$CONFIG_DIR,dst=/config" \
    "$JTSR_WEB_IMAGE" jtsr report-init-auth \
      --auth-file /config/report-web-auth.json --login-file /config/report-web-login.txt
fi
[[ -f "$CONFIG_DIR/report-web-auth.json" && ! -L "$CONFIG_DIR/report-web-auth.json" ]] || exit 1
[[ -f "$CONFIG_DIR/report-web-login.txt" && ! -L "$CONFIG_DIR/report-web-login.txt" ]] || exit 1
chown root:10001 "$CONFIG_DIR/report-web-auth.json"
chmod 0440 "$CONFIG_DIR/report-web-auth.json"
chown root:root "$CONFIG_DIR/report-web-login.txt"
chmod 0600 "$CONFIG_DIR/report-web-login.txt"
install -m 0755 "$REPO_DIR/deploy/server/run-report-web.sh" "$LIBEXEC_DIR/run-report-web"
install -m 0644 "$REPO_DIR/deploy/server/$WEB_SERVICE" "/etc/systemd/system/$WEB_SERVICE"
systemctl daemon-reload
systemctl enable "$WEB_SERVICE"
systemctl restart "$WEB_SERVICE"
HEALTH_OK=false
for attempt in {1..20}; do
  if curl --silent --fail --max-time 2 http://127.0.0.1:8765/security/api/health >/dev/null; then
    HEALTH_OK=true; break
  fi
  sleep 1
done
[[ "$HEALTH_OK" == true ]] || { printf 'Report service health check failed; gateway unchanged.\n' >&2; exit 1; }
if [[ -n "$NGINX_CONFIG" ]]; then
  BACKUP="$NGINX_CONFIG.jtsr-backup.$(date -u +%Y%m%dT%H%M%SZ)"
  SNIPPET=/etc/nginx/snippets/jtsr-report-web.conf
  cp -p -- "$NGINX_CONFIG" "$BACKUP"
  install -d -m 0755 /etc/nginx/snippets
  HAD_SNIPPET=false
  if [[ -f "$SNIPPET" ]]; then cp -p -- "$SNIPPET" "$BACKUP.snippet"; HAD_SNIPPET=true; fi
  rollback() {
    cp -p -- "$BACKUP" "$NGINX_CONFIG"
    if [[ "$HAD_SNIPPET" == true ]]; then cp -p -- "$BACKUP.snippet" "$SNIPPET"; fi
    printf 'Nginx configuration restored from %s; review the error before retrying.\n' "$BACKUP" >&2
  }
  trap rollback ERR
  install -m 0644 "$REPO_DIR/deploy/server/nginx-report-web.conf" "$SNIPPET"
  docker run --rm --user 0:0 --network none --read-only \
    --security-opt no-new-privileges \
    --mount type=bind,src=/etc/nginx/conf.d,dst=/nginx \
    --mount "type=bind,src=$REPO_DIR/deploy/server/configure-report-nginx.py,dst=/configure.py,readonly" \
    "$JTSR_WEB_IMAGE" python3 /configure.py "/nginx/$(basename -- "$NGINX_CONFIG")"
  nginx -t
  systemctl reload nginx
  trap - ERR
  printf 'Gateway route installed: http://<gateway>:6060/security/\nBackup: %s\n' "$BACKUP"
fi
printf 'Portal ready. Credentials are in %s/report-web-login.txt (root-only).\nScanner timer was not modified.\n' "$CONFIG_DIR"
