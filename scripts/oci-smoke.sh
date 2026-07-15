#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="${PORT:-18080}"
HOST="${HOST:-127.0.0.1}"
BASE_URL="${BASE_URL:-http://${HOST}:${PORT}}"
SERVICE="${SERVICE:-scr}"
ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-admin-password}"
READER_USERNAME="${READER_USERNAME:-reader-smoke}"
REPO="${REPO:-smoke/demo}"
TAG="${TAG:-v1}"
WORKDIR="${SCR_SMOKE_DIR:-$(mktemp -d)}"
SERVER_PID=""

info() { printf '\n==> %s\n' "$*"; }
pass() { printf 'ok: %s\n' "$*"; }
fail() { printf 'error: %s\n' "$*" >&2; exit 1; }

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

json_field() {
  python3 -c 'import json,sys; print(json.load(sys.stdin)[sys.argv[1]])' "$1"
}

pretty_json() {
  python3 -m json.tool
}

json_has_tag() {
  python3 -c 'import json,sys; data=json.load(sys.stdin); tag=sys.argv[1]; sys.exit(0 if tag in (data.get("tags") or []) else 1)' "$1"
}

json_has_repo() {
  python3 -c 'import json,sys; data=json.load(sys.stdin); repo=sys.argv[1]; names=data.get("repositories") if isinstance(data, dict) else [item.get("name") for item in data]; sys.exit(0 if repo in names else 1)' "$1"
}

header_value() {
  local name="$1"
  local file="$2"
  python3 -c '
import sys
name = sys.argv[1].lower() + ":"
with open(sys.argv[2], "r", encoding="utf-8", errors="replace") as f:
    for line in f:
        line = line.rstrip("\r\n")
        if line.lower().startswith(name):
            print(line.split(":", 1)[1].strip())
            break
' "$name" "$file"
}

url_for_location() {
  local location="$1"
  if [[ "$location" == http://* || "$location" == https://* ]]; then
    printf '%s' "$location"
  else
    printf '%s%s' "$BASE_URL" "$location"
  fi
}

cleanup() {
  if [[ -n "${SERVER_PID:-}" ]]; then
    kill "$SERVER_PID" >/dev/null 2>&1 || true
    wait "$SERVER_PID" >/dev/null 2>&1 || true
  fi
  if [[ "${KEEP_SMOKE_DIR:-0}" == "1" ]]; then
    info "kept smoke directory: $WORKDIR"
  else
    rm -rf "$WORKDIR"
  fi
}
trap cleanup EXIT

get_token() {
  local username="$1"
  local password="$2"
  local scope="${3:-}"

  if [[ -n "$scope" ]]; then
    curl -fsS -u "$username:$password" --get \
      --data-urlencode "service=$SERVICE" \
      --data-urlencode "scope=$scope" \
      "$BASE_URL/token" | json_field token
  else
    curl -fsS -u "$username:$password" --get \
      --data-urlencode "service=$SERVICE" \
      "$BASE_URL/token" | json_field token
  fi
}

expect_status() {
  local expected="$1"
  local actual="$2"
  local label="$3"
  local body_file="${4:-}"
  if [[ "$actual" != "$expected" ]]; then
    if [[ -n "$body_file" && -f "$body_file" ]]; then
      printf '\nresponse body:\n' >&2
      sed 's/^/  /' "$body_file" >&2 || true
    fi
    fail "$label: expected HTTP $expected, got $actual"
  fi
}

push_blob() {
  local token="$1"
  local file="$2"
  local digest size headers body status location upload_url commit_url

  digest="sha256:$(sha256sum "$file" | awk '{print $1}')"
  size="$(wc -c < "$file" | tr -d ' ')"
  headers="$WORKDIR/headers.$(basename "$file").txt"
  body="$WORKDIR/body.$(basename "$file").txt"

  status="$(curl -sS -o "$body" -D "$headers" -w '%{http_code}' \
    -X POST \
    -H "Authorization: Bearer $token" \
    "$BASE_URL/v2/$REPO/blobs/uploads/")"
  expect_status 202 "$status" "start blob upload" "$body"
  location="$(header_value Location "$headers")"
  [[ -n "$location" ]] || fail "upload start did not return a Location header"
  upload_url="$(url_for_location "$location")"

  status="$(curl -sS -o "$body" -D "$headers" -w '%{http_code}' \
    -X PATCH \
    -H "Authorization: Bearer $token" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@$file" \
    "$upload_url")"
  expect_status 202 "$status" "append blob upload" "$body"
  location="$(header_value Location "$headers")"
  [[ -n "$location" ]] || fail "upload patch did not return a Location header"
  commit_url="$(url_for_location "$location")?digest=$digest"

  status="$(curl -sS -o "$body" -D "$headers" -w '%{http_code}' \
    -X PUT \
    -H "Authorization: Bearer $token" \
    "$commit_url")"
  expect_status 201 "$status" "commit blob upload" "$body"

  printf '%s %s\n' "$digest" "$size"
}

require_command curl
require_command go
require_command python3
require_command sha256sum
require_command tar
require_command awk
require_command sed
require_command tr
require_command wc

mkdir -p "$WORKDIR/registry"

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

info "requesting admin token"
ADMIN_API_TOKEN="$(get_token "$ADMIN_USERNAME" "$ADMIN_PASSWORD")"
ADMIN_PUSH_TOKEN="$(get_token "$ADMIN_USERNAME" "$ADMIN_PASSWORD" "repository:$REPO:pull,push")"
ADMIN_DELETE_TOKEN="$(get_token "$ADMIN_USERNAME" "$ADMIN_PASSWORD" "repository:$REPO:delete")"
pass "admin token issued"

info "checking registry API ping with bearer auth"
PING_STATUS="$(curl -sS -o "$WORKDIR/ping.txt" -w '%{http_code}' -H "Authorization: Bearer $ADMIN_API_TOKEN" "$BASE_URL/v2/")"
expect_status 200 "$PING_STATUS" "authenticated /v2/ ping" "$WORKDIR/ping.txt"
pass "authenticated /v2/ ping returned 200"

info "creating reader user with pull-only grant for $REPO"
READER_RESPONSE="$(curl -fsS \
  -H "Authorization: Bearer $ADMIN_API_TOKEN" \
  -H "Content-Type: application/json" \
  --data-binary @- \
  "$BASE_URL/api/users" <<JSON
{"username":"$READER_USERNAME","displayName":"Smoke Reader","role":"reader","grants":[{"repositoryPrefix":"smoke/","actions":["pull"]}]}
JSON
)"
READER_SECRET="$(printf '%s' "$READER_RESPONSE" | json_field secret)"
pass "reader created: $READER_USERNAME"

info "creating OCI image config and layer"
mkdir -p "$WORKDIR/layer-root"
printf 'hello from SCR smoke test\n' > "$WORKDIR/layer-root/hello.txt"
tar -cf "$WORKDIR/layer.tar" -C "$WORKDIR/layer-root" hello.txt
LAYER_DIGEST="sha256:$(sha256sum "$WORKDIR/layer.tar" | awk '{print $1}')"
cat > "$WORKDIR/config.json" <<JSON
{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":["$LAYER_DIGEST"]},"history":[{"created_by":"scripts/oci-smoke.sh"}]}
JSON

info "pushing layer blob as admin"
read -r PUSHED_LAYER_DIGEST LAYER_SIZE < <(push_blob "$ADMIN_PUSH_TOKEN" "$WORKDIR/layer.tar")
[[ "$PUSHED_LAYER_DIGEST" == "$LAYER_DIGEST" ]] || fail "layer digest mismatch"
pass "layer pushed: $PUSHED_LAYER_DIGEST"

info "pushing config blob as admin"
read -r CONFIG_DIGEST CONFIG_SIZE < <(push_blob "$ADMIN_PUSH_TOKEN" "$WORKDIR/config.json")
pass "config pushed: $CONFIG_DIGEST"

info "pushing OCI manifest as admin"
MANIFEST_PATH="$WORKDIR/manifest.json"
cat > "$MANIFEST_PATH" <<JSON
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "config": {
    "mediaType": "application/vnd.oci.image.config.v1+json",
    "digest": "$CONFIG_DIGEST",
    "size": $CONFIG_SIZE
  },
  "layers": [
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar",
      "digest": "$PUSHED_LAYER_DIGEST",
      "size": $LAYER_SIZE,
      "annotations": {"org.opencontainers.image.title": "hello.txt"}
    }
  ],
  "annotations": {"org.opencontainers.image.description": "SCR smoke test"}
}
JSON
MANIFEST_HEADERS="$WORKDIR/manifest.headers.txt"
MANIFEST_BODY="$WORKDIR/manifest.body.txt"
MANIFEST_STATUS="$(curl -sS -o "$MANIFEST_BODY" -D "$MANIFEST_HEADERS" -w '%{http_code}' \
  -X PUT \
  -H "Authorization: Bearer $ADMIN_PUSH_TOKEN" \
  -H "Content-Type: application/vnd.oci.image.manifest.v1+json" \
  --data-binary "@$MANIFEST_PATH" \
  "$BASE_URL/v2/$REPO/manifests/$TAG")"
expect_status 201 "$MANIFEST_STATUS" "push manifest" "$MANIFEST_BODY"
MANIFEST_DIGEST="$(header_value Docker-Content-Digest "$MANIFEST_HEADERS")"
pass "manifest pushed: $REPO:$TAG ($MANIFEST_DIGEST)"

info "requesting reader tokens"
READER_PULL_TOKEN="$(get_token "$READER_USERNAME" "$READER_SECRET" "repository:$REPO:pull")"
READER_PUSH_TOKEN="$(get_token "$READER_USERNAME" "$READER_SECRET" "repository:$REPO:push")"
READER_API_TOKEN="$(get_token "$READER_USERNAME" "$READER_SECRET")"
pass "reader tokens issued"

info "listing tags as reader through OCI Distribution API"
TAGS_JSON="$WORKDIR/tags.json"
curl -fsS -H "Authorization: Bearer $READER_PULL_TOKEN" "$BASE_URL/v2/$REPO/tags/list" > "$TAGS_JSON"
json_has_tag "$TAG" < "$TAGS_JSON" || fail "tag $TAG was not listed"
pretty_json < "$TAGS_JSON"
pass "reader listed $REPO:$TAG"

info "pulling manifest and layer as reader"
PULLED_MANIFEST="$WORKDIR/pulled-manifest.json"
curl -fsS \
  -H "Authorization: Bearer $READER_PULL_TOKEN" \
  -H "Accept: application/vnd.oci.image.manifest.v1+json" \
  "$BASE_URL/v2/$REPO/manifests/$TAG" > "$PULLED_MANIFEST"
cmp -s "$MANIFEST_PATH" "$PULLED_MANIFEST" || fail "pulled manifest differs from pushed manifest"

HEAD_STATUS="$(curl -sS -o /dev/null -w '%{http_code}' \
  -I \
  -H "Authorization: Bearer $READER_PULL_TOKEN" \
  "$BASE_URL/v2/$REPO/manifests/$TAG")"
expect_status 200 "$HEAD_STATUS" "HEAD manifest"

PULLED_LAYER="$WORKDIR/pulled-layer.tar"
curl -fsS -H "Authorization: Bearer $READER_PULL_TOKEN" "$BASE_URL/v2/$REPO/blobs/$PUSHED_LAYER_DIGEST" > "$PULLED_LAYER"
PULLED_LAYER_DIGEST="sha256:$(sha256sum "$PULLED_LAYER" | awk '{print $1}')"
[[ "$PULLED_LAYER_DIGEST" == "$PUSHED_LAYER_DIGEST" ]] || fail "pulled layer digest mismatch"
pass "reader pulled manifest and layer"

info "verifying reader cannot push"
DENY_BODY="$WORKDIR/reader-push-denied.txt"
DENY_STATUS="$(curl -sS -o "$DENY_BODY" -w '%{http_code}' \
  -X POST \
  -H "Authorization: Bearer $READER_PUSH_TOKEN" \
  "$BASE_URL/v2/$REPO/blobs/uploads/")"
expect_status 401 "$DENY_STATUS" "reader push denial" "$DENY_BODY"
pass "reader push denied with HTTP 401"

info "verifying reader cannot use admin API"
ADMIN_DENY_STATUS="$(curl -sS -o "$WORKDIR/reader-api-denied.txt" -w '%{http_code}' \
  -H "Authorization: Bearer $READER_API_TOKEN" \
  "$BASE_URL/api/users")"
expect_status 401 "$ADMIN_DENY_STATUS" "reader admin API denial" "$WORKDIR/reader-api-denied.txt"
pass "reader admin API denied with HTTP 401"

info "checking admin repository and dashboard APIs"
REPOS_JSON="$WORKDIR/repositories.json"
curl -fsS -H "Authorization: Bearer $ADMIN_API_TOKEN" "$BASE_URL/api/repositories" > "$REPOS_JSON"
json_has_repo "$REPO" < "$REPOS_JSON" || fail "admin repositories API did not include $REPO"
pretty_json < "$REPOS_JSON"

CATALOG_JSON="$WORKDIR/catalog.json"
curl -fsS -H "Authorization: Bearer $ADMIN_API_TOKEN" "$BASE_URL/v2/_catalog" > "$CATALOG_JSON"
json_has_repo "$REPO" < "$CATALOG_JSON" || fail "catalog did not include $REPO"
pretty_json < "$CATALOG_JSON"

curl -fsS -H "Authorization: Bearer $ADMIN_API_TOKEN" "$BASE_URL/api/repositories/$REPO/tags" | pretty_json
curl -fsS -H "Authorization: Bearer $ADMIN_API_TOKEN" "$BASE_URL/api/dashboard/summary" | pretty_json
curl -fsS -H "Authorization: Bearer $ADMIN_API_TOKEN" "$BASE_URL/api/audit-events" | pretty_json >/dev/null
pass "admin APIs returned repository, catalog, tag, dashboard, and audit data"

info "deleting manifest as admin"
DELETE_BODY="$WORKDIR/delete-manifest.txt"
DELETE_STATUS="$(curl -sS -o "$DELETE_BODY" -w '%{http_code}' \
  -X DELETE \
  -H "Authorization: Bearer $ADMIN_DELETE_TOKEN" \
  "$BASE_URL/v2/$REPO/manifests/$MANIFEST_DIGEST")"
expect_status 202 "$DELETE_STATUS" "delete manifest" "$DELETE_BODY"
MISSING_STATUS="$(curl -sS -o "$WORKDIR/deleted-manifest.txt" -w '%{http_code}' \
  -H "Authorization: Bearer $READER_PULL_TOKEN" \
  "$BASE_URL/v2/$REPO/manifests/$TAG")"
expect_status 404 "$MISSING_STATUS" "pull deleted manifest" "$WORKDIR/deleted-manifest.txt"
pass "admin deleted manifest and reader pull now returns 404"

info "smoke test passed"
printf 'registry: %s\nrepo:     %s:%s (deleted at end of smoke test)\nadmin:    %s / %s\nreader:   %s / %s\n' \
  "$BASE_URL" "$REPO" "$TAG" "$ADMIN_USERNAME" "$ADMIN_PASSWORD" "$READER_USERNAME" "$READER_SECRET"
