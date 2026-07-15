#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="${PORT:-18082}"
HOST="${HOST:-127.0.0.1}"
BASE_URL="${BASE_URL:-http://${HOST}:${PORT}}"
SERVICE="${SERVICE:-scr}"
ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-admin-password}"
WORKDIR="${SCR_CONFORMANCE_DIR:-$(mktemp -d)}"
SPEC_DIR="${OCI_DISTRIBUTION_SPEC_DIR:-$WORKDIR/distribution-spec}"
RESULTS_DIR="${OCI_RESULTS_DIR:-$WORKDIR/results}"
SERVER_PID=""

info() { printf '\n==> %s\n' "$*"; }
pass() { printf 'ok: %s\n' "$*"; }
fail() { printf 'error: %s\n' "$*" >&2; exit 1; }

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

cleanup() {

  local status=$?
  if [[ -n "${SERVER_PID:-}" ]]; then
    kill "$SERVER_PID" >/dev/null 2>&1 || true
    wait "$SERVER_PID" >/dev/null 2>&1 || true
  fi
  if [[ "${KEEP_CONFORMANCE_DIR:-0}" == "1" || "$status" != "0" ]]; then
    info "kept conformance directory: $WORKDIR"
  else
    rm -rf "$WORKDIR"
  fi

  return "$status"
}
trap cleanup EXIT

require_command curl
require_command git
require_command go

mkdir -p "$WORKDIR/registry" "$RESULTS_DIR"

CONFIG_PATH="$WORKDIR/config.yaml"
SERVER_LOG="$WORKDIR/server.log"
cat > "$CONFIG_PATH" <<YAML
http:
  address: "$HOST"
  port: $PORT

storage:
  rootDirectory: "$WORKDIR/registry"
  gc: true
  gcDelay: "1h"
  gcInterval: "24h"

database:
  driver: "sqlite"
  dsn: "$WORKDIR/scr.db"

auth:
  issuer: "scr"
  service: "$SERVICE"
  tokenTTL: "10m"
YAML

info "starting temporary registry on $BASE_URL"
(
  cd "$ROOT_DIR"
  SCR_BOOTSTRAP_ADMIN_USERNAME="$ADMIN_USERNAME" \
  SCR_BOOTSTRAP_ADMIN_PASSWORD="$ADMIN_PASSWORD" \
  go run ./cmd/simplecontainerregistry -config "$CONFIG_PATH"
) >"$SERVER_LOG" 2>&1 &
SERVER_PID="$!"

for _ in $(seq 1 100); do
  if curl -fsS "$BASE_URL/healthz" >/dev/null 2>&1; then
    pass "server is healthy"
    break
  fi
  if ! kill -0 "$SERVER_PID" >/dev/null 2>&1; then
    sed 's/^/  /' "$SERVER_LOG" >&2 || true
    fail "server exited before becoming healthy"
  fi
  sleep 0.1
done

curl -fsS "$BASE_URL/healthz" >/dev/null || {
  sed 's/^/  /' "$SERVER_LOG" >&2 || true
  fail "server did not become healthy"
}

if [[ ! -d "$SPEC_DIR/.git" ]]; then
  info "cloning OCI distribution-spec conformance suite"
  git clone --depth 1 https://github.com/opencontainers/distribution-spec.git "$SPEC_DIR"
else
  info "using existing OCI distribution-spec checkout: $SPEC_DIR"
fi

info "running OCI distribution conformance tests"
(
  cd "$SPEC_DIR/conformance"
  OCI_RESULTS_DIR="$RESULTS_DIR" \
  OCI_REGISTRY="${HOST}:${PORT}" \
  OCI_TLS="disabled" \
  OCI_REPO1="${OCI_REPO1:-conformance/repo1}" \
  OCI_REPO2="${OCI_REPO2:-conformance/repo2}" \
  OCI_USERNAME="$ADMIN_USERNAME" \
  OCI_PASSWORD="$ADMIN_PASSWORD" \
  OCI_VERSION="${OCI_VERSION:-1.1}" \
  OCI_API_BLOBS_DELETE="${OCI_API_BLOBS_DELETE:-true}" \
  OCI_API_BLOBS_MOUNT_ANONYMOUS="${OCI_API_BLOBS_MOUNT_ANONYMOUS:-false}" \
  OCI_API_BLOBS_UPLOAD_CANCEL="${OCI_API_BLOBS_UPLOAD_CANCEL:-false}" \
  OCI_API_MANIFESTS_TAG_PARAM="${OCI_API_MANIFESTS_TAG_PARAM:-true}" \
  OCI_API_REFERRER="${OCI_API_REFERRER:-true}" \
  go run -buildvcs=true .
)

pass "conformance run completed"
printf 'results:  %s\nserver:   %s\nadmin:    %s / %s\n' \
  "$RESULTS_DIR" "$BASE_URL" "$ADMIN_USERNAME" "$ADMIN_PASSWORD"
