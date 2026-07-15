#!/usr/bin/env bash
set -Eeuo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:5000}"
SERVICE="${SERVICE:-scr}"
ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-change-me}"
REPO="${REPO:-demo/readonly-app}"
TAG="${TAG:-v1}"
READER_USERNAME="${READER_USERNAME:-readonly-demo-$(date +%Y%m%d%H%M%S)}"
READER_DISPLAY_NAME="${READER_DISPLAY_NAME:-Readonly Demo User}"
DENIED_USERNAME="${DENIED_USERNAME:-readonly-denied-$(date +%Y%m%d%H%M%S)}"
DENIED_DISPLAY_NAME="${DENIED_DISPLAY_NAME:-Readonly Denied Demo User}"
DENIED_REPO="${DENIED_REPO:-demo/other-app}"
EXPIRES_AT="${EXPIRES_AT:-$(python3 -c 'from datetime import datetime, timezone, timedelta; print((datetime.now(timezone.utc) + timedelta(days=14)).isoformat().replace("+00:00", "Z"))')}"
WORKDIR="${SCR_FUNCTIONAL_DEMO_DIR:-$(mktemp -d)}"

info() { printf '\n==> %s\n' "$*"; }
pass() { printf 'ok: %s\n' "$*"; }
fail() { printf 'error: %s\n' "$*" >&2; exit 1; }

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

json_field() {
  python3 -c 'import json,sys; print(json.load(sys.stdin)[sys.argv[1]])' "$1"
}

json_has_tag() {
  python3 -c 'import json,sys; data=json.load(sys.stdin); tag=sys.argv[1]; sys.exit(0 if tag in (data.get("tags") or []) else 1)' "$1"
}

json_has_repo() {
  python3 -c 'import json,sys; data=json.load(sys.stdin); repo=sys.argv[1]; names=data.get("repositories") if isinstance(data, dict) else [item.get("name") for item in data]; sys.exit(0 if repo in names else 1)' "$1"
}

json_has_denied_audit() {
  python3 -c 'import json,sys; events=json.load(sys.stdin); repo=sys.argv[1]; sys.exit(0 if any(event.get("action") == "registry.access.denied" and event.get("targetType") == "repository" and event.get("targetId") == repo and event.get("result") == "denied" for event in events) else 1)' "$1"
}

pretty_json() {
  python3 -m json.tool
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
  if [[ "${KEEP_FUNCTIONAL_DEMO_DIR:-0}" == "1" ]]; then
    info "kept functional demo directory: $WORKDIR"
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

require_command awk
require_command cmp
require_command curl
require_command python3
require_command sed
require_command sha256sum
require_command tar
require_command tr
require_command wc

mkdir -p "$WORKDIR"

info "checking SCR health at $BASE_URL"
curl -fsS "$BASE_URL/healthz" >/dev/null || fail "SCR is not healthy at $BASE_URL"
pass "server is healthy"

info "requesting admin tokens"
ADMIN_API_TOKEN="$(get_token "$ADMIN_USERNAME" "$ADMIN_PASSWORD")"
ADMIN_REPO_TOKEN="$(get_token "$ADMIN_USERNAME" "$ADMIN_PASSWORD" "repository:$REPO:pull,push,delete")"
pass "admin tokens issued"

info "creating OCI fixture for $REPO:$TAG"
mkdir -p "$WORKDIR/layer-root"
printf 'hello from SCR functional demo\nrepo=%s\ntag=%s\n' "$REPO" "$TAG" > "$WORKDIR/layer-root/hello.txt"
tar -cf "$WORKDIR/layer.tar" -C "$WORKDIR/layer-root" hello.txt
LAYER_DIGEST="sha256:$(sha256sum "$WORKDIR/layer.tar" | awk '{print $1}')"
cat > "$WORKDIR/config.json" <<JSON
{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":["$LAYER_DIGEST"]},"history":[{"created_by":"scripts/functional-demo.sh"}]}
JSON

info "pushing layer and config blobs"
read -r PUSHED_LAYER_DIGEST LAYER_SIZE < <(push_blob "$ADMIN_REPO_TOKEN" "$WORKDIR/layer.tar")
[[ "$PUSHED_LAYER_DIGEST" == "$LAYER_DIGEST" ]] || fail "layer digest mismatch"
read -r CONFIG_DIGEST CONFIG_SIZE < <(push_blob "$ADMIN_REPO_TOKEN" "$WORKDIR/config.json")
pass "blobs pushed"

info "pushing manifest"
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
  "annotations": {"org.opencontainers.image.description": "SCR functional demo"}
}
JSON
MANIFEST_HEADERS="$WORKDIR/manifest.headers.txt"
MANIFEST_BODY="$WORKDIR/manifest.body.txt"
MANIFEST_STATUS="$(curl -sS -o "$MANIFEST_BODY" -D "$MANIFEST_HEADERS" -w '%{http_code}' \
  -X PUT \
  -H "Authorization: Bearer $ADMIN_REPO_TOKEN" \
  -H "Content-Type: application/vnd.oci.image.manifest.v1+json" \
  --data-binary "@$MANIFEST_PATH" \
  "$BASE_URL/v2/$REPO/manifests/$TAG")"
expect_status 201 "$MANIFEST_STATUS" "push manifest" "$MANIFEST_BODY"
MANIFEST_DIGEST="$(header_value Docker-Content-Digest "$MANIFEST_HEADERS")"
pass "manifest pushed: $REPO:$TAG ($MANIFEST_DIGEST)"

info "creating read-only expiring user for $REPO"
CREATE_USER_BODY="$WORKDIR/create-user.json"
CREATE_USER_RESPONSE="$WORKDIR/create-user-response.json"
cat > "$CREATE_USER_BODY" <<JSON
{
  "username": "$READER_USERNAME",
  "displayName": "$READER_DISPLAY_NAME",
  "role": "reader",
  "expiresAt": "$EXPIRES_AT",
  "grants": [
    {
      "repositoryPrefix": "$REPO",
      "actions": ["pull"]
    }
  ]
}
JSON
curl -fsS \
  -H "Authorization: Bearer $ADMIN_API_TOKEN" \
  -H "Content-Type: application/json" \
  --data-binary "@$CREATE_USER_BODY" \
  "$BASE_URL/api/users" > "$CREATE_USER_RESPONSE"
READER_SECRET="$(json_field secret < "$CREATE_USER_RESPONSE")"
READER_ID="$(python3 -c 'import json,sys; data=json.load(sys.stdin); print(data["user"]["id"])' < "$CREATE_USER_RESPONSE")"
pass "created reader $READER_USERNAME ($READER_ID), expires $EXPIRES_AT"

info "creating second read-only user without access to $REPO"
CREATE_DENIED_USER_BODY="$WORKDIR/create-denied-user.json"
CREATE_DENIED_USER_RESPONSE="$WORKDIR/create-denied-user-response.json"
cat > "$CREATE_DENIED_USER_BODY" <<JSON
{
  "username": "$DENIED_USERNAME",
  "displayName": "$DENIED_DISPLAY_NAME",
  "role": "reader",
  "expiresAt": "$EXPIRES_AT",
  "grants": [
    {
      "repositoryPrefix": "$DENIED_REPO",
      "actions": ["pull"]
    }
  ]
}
JSON
curl -fsS \
  -H "Authorization: Bearer $ADMIN_API_TOKEN" \
  -H "Content-Type: application/json" \
  --data-binary "@$CREATE_DENIED_USER_BODY" \
  "$BASE_URL/api/users" > "$CREATE_DENIED_USER_RESPONSE"
DENIED_SECRET="$(json_field secret < "$CREATE_DENIED_USER_RESPONSE")"
DENIED_ID="$(python3 -c 'import json,sys; data=json.load(sys.stdin); print(data["user"]["id"])' < "$CREATE_DENIED_USER_RESPONSE")"
pass "created denied reader $DENIED_USERNAME ($DENIED_ID), grant $DENIED_REPO"

info "verifying read-only user can pull $REPO:$TAG"
READER_PULL_TOKEN="$(get_token "$READER_USERNAME" "$READER_SECRET" "repository:$REPO:pull")"
TAGS_JSON="$WORKDIR/tags.json"
curl -fsS -H "Authorization: Bearer $READER_PULL_TOKEN" "$BASE_URL/v2/$REPO/tags/list" > "$TAGS_JSON"
json_has_tag "$TAG" < "$TAGS_JSON" || fail "tag $TAG was not listed for reader"
PULLED_MANIFEST="$WORKDIR/pulled-manifest.json"
curl -fsS \
  -H "Authorization: Bearer $READER_PULL_TOKEN" \
  -H "Accept: application/vnd.oci.image.manifest.v1+json" \
  "$BASE_URL/v2/$REPO/manifests/$TAG" > "$PULLED_MANIFEST"
cmp -s "$MANIFEST_PATH" "$PULLED_MANIFEST" || fail "reader pulled manifest differs from pushed manifest"
PULLED_LAYER="$WORKDIR/pulled-layer.tar"
curl -fsS -H "Authorization: Bearer $READER_PULL_TOKEN" "$BASE_URL/v2/$REPO/blobs/$PUSHED_LAYER_DIGEST" > "$PULLED_LAYER"
PULLED_LAYER_DIGEST="sha256:$(sha256sum "$PULLED_LAYER" | awk '{print $1}')"
[[ "$PULLED_LAYER_DIGEST" == "$PUSHED_LAYER_DIGEST" ]] || fail "reader pulled layer digest mismatch"
pass "reader can list tags and pull manifest/blob"

info "verifying second read-only user cannot access $REPO"
DENIED_PULL_TOKEN="$(get_token "$DENIED_USERNAME" "$DENIED_SECRET" "repository:$REPO:pull")"
DENIED_PULL_BODY="$WORKDIR/denied-reader-pull.txt"
DENIED_PULL_STATUS="$(curl -sS -o "$DENIED_PULL_BODY" -w '%{http_code}' \
  -H "Authorization: Bearer $DENIED_PULL_TOKEN" \
  "$BASE_URL/v2/$REPO/tags/list")"
expect_status 401 "$DENIED_PULL_STATUS" "second reader repo pull denial" "$DENIED_PULL_BODY"
DENIED_OTHER_TOKEN="$(get_token "$DENIED_USERNAME" "$DENIED_SECRET" "repository:$DENIED_REPO:pull")"
DENIED_OTHER_BODY="$WORKDIR/denied-reader-other-repo.txt"
DENIED_OTHER_STATUS="$(curl -sS -o "$DENIED_OTHER_BODY" -w '%{http_code}' \
  -H "Authorization: Bearer $DENIED_OTHER_TOKEN" \
  "$BASE_URL/v2/$DENIED_REPO/tags/list")"
expect_status 200 "$DENIED_OTHER_STATUS" "second reader own empty repo tag list" "$DENIED_OTHER_BODY"
pass "second reader denied for $REPO but authorized for its own empty repo scope"

info "verifying read-only user cannot push or use admin API"
READER_PUSH_TOKEN="$(get_token "$READER_USERNAME" "$READER_SECRET" "repository:$REPO:push")"
DENY_BODY="$WORKDIR/reader-push-denied.txt"
DENY_STATUS="$(curl -sS -o "$DENY_BODY" -w '%{http_code}' \
  -X POST \
  -H "Authorization: Bearer $READER_PUSH_TOKEN" \
  "$BASE_URL/v2/$REPO/blobs/uploads/")"
expect_status 401 "$DENY_STATUS" "reader push denial" "$DENY_BODY"
READER_API_TOKEN="$(get_token "$READER_USERNAME" "$READER_SECRET")"
ADMIN_DENY_BODY="$WORKDIR/reader-admin-denied.txt"
ADMIN_DENY_STATUS="$(curl -sS -o "$ADMIN_DENY_BODY" -w '%{http_code}' \
  -H "Authorization: Bearer $READER_API_TOKEN" \
  "$BASE_URL/api/users")"
expect_status 401 "$ADMIN_DENY_STATUS" "reader admin API denial" "$ADMIN_DENY_BODY"
pass "reader push and admin API denied"

info "verifying admin APIs expose repository and tag metadata"
REPOS_JSON="$WORKDIR/repositories.json"
curl -fsS -H "Authorization: Bearer $ADMIN_API_TOKEN" "$BASE_URL/api/repositories" > "$REPOS_JSON"
json_has_repo "$REPO" < "$REPOS_JSON" || fail "admin repositories API did not include $REPO"
curl -fsS -H "Authorization: Bearer $ADMIN_API_TOKEN" "$BASE_URL/api/repositories/$REPO/tags" | pretty_json
curl -fsS -H "Authorization: Bearer $ADMIN_API_TOKEN" "$BASE_URL/api/dashboard/summary" | pretty_json
pass "admin APIs returned seeded data"

info "verifying denied registry access is audited"
AUDIT_JSON="$WORKDIR/audit-events.json"
curl -fsS -H "Authorization: Bearer $ADMIN_API_TOKEN" "$BASE_URL/api/audit-events" > "$AUDIT_JSON"
json_has_denied_audit "$REPO" < "$AUDIT_JSON" || fail "audit events did not include denied registry access for $REPO"
pass "denied registry access is present in audit events"

info "functional demo passed"
printf 'registry: %s\nrepo:     %s:%s\ndigest:   %s\nadmin:    %s / %s\nreader:   %s / %s\nexpires:  %s\n' \
  "$BASE_URL" "$REPO" "$TAG" "$MANIFEST_DIGEST" "$ADMIN_USERNAME" "$ADMIN_PASSWORD" "$READER_USERNAME" "$READER_SECRET" "$EXPIRES_AT"
printf 'denied:   %s / %s\ngrant:    %s\n' "$DENIED_USERNAME" "$DENIED_SECRET" "$DENIED_REPO"
