# Simple Container Registry

[![CI](https://github.com/ByteBardOrg/simplecontainerregistry/actions/workflows/ci.yml/badge.svg)](https://github.com/ByteBardOrg/simplecontainerregistry/actions/workflows/ci.yml)

Current development status: `pre-release`

This repository contains the Go implementation for a self-hosted OCI container registry with managed user access, SQLite-backed management data, filesystem-backed registry storage, audit logging, and a server-rendered admin UI.

Registry content is stored on disk. Users, repository grants, repository metadata, usage counters, audit events, and signing keys are stored in SQLite.
<img width="1162" height="705" alt="image" src="https://github.com/user-attachments/assets/dfb9409b-4d0b-47d2-ad50-5890f511d3a5" />

## Getting started

Start the registry with the published Docker image:

```bash
export SCR_BOOTSTRAP_ADMIN_PASSWORD="$(openssl rand -base64 32)"
mkdir -p data
cat > config.local.yaml <<'EOF'
http:
  # Docker publishes this container port only on 127.0.0.1 below.
  address: "0.0.0.0"
  port: 5000
  secureCookies: false
  allowInsecureHTTP: true
  publicURL: ""
  trustForwardedHeaders: false
  trustedProxyCIDRs: []
  readTimeout: "30m"
  writeTimeout: "30m"
  idleTimeout: "2m"
  maxHeaderBytes: 1048576
storage:
  rootDirectory: "/var/lib/scr/registry"
  gc: true
  gcDelay: "1h"
  gcInterval: "24h"
database:
  driver: "sqlite"
  dsn: "/var/lib/scr/scr.db"
auth:
  issuer: "scr"
  service: "scr"
  tokenTTL: "10m"
EOF
docker run --rm --name scr \
  -p 127.0.0.1:5000:5000 \
  -v scr-data:/var/lib/scr \
  -v "$PWD/config.local.yaml:/etc/scr/config.yaml:ro" \
  -e SCR_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e SCR_BOOTSTRAP_ADMIN_PASSWORD \
  bytebardorg/simplecontainerregistry:latest
```

The container listens on port `5000`, uses `/etc/scr/config.yaml`, and stores registry content plus SQLite state under `/var/lib/scr`. The named volume keeps data across container restarts.

Open the admin UI:

```text
http://localhost:5000/ui
```

Sign in with the bootstrap admin username and password. The bootstrap admin is created only if that username does not already exist.

Log in with a Docker-compatible client and push an image:

```bash
printf '%s\n' "$SCR_BOOTSTRAP_ADMIN_PASSWORD" | docker login localhost:5000 -u admin --password-stdin
docker pull busybox:latest
docker tag busybox:latest localhost:5000/getting-started/busybox:latest
docker push localhost:5000/getting-started/busybox:latest
docker pull localhost:5000/getting-started/busybox:latest
```

The host port is bound only to loopback. This mounted local configuration explicitly opts into insecure HTTP and disables secure cookies. For non-local deployments, keep secure cookies enabled and run SCR behind TLS, usually through a reverse proxy.

### Deploy with Dokploy

Create a Docker Compose service in Dokploy from this repository and set the Compose path to `compose.yaml`. Add these environment variables in Dokploy before deploying:

```dotenv
SCR_PUBLIC_URL=https://registry.example.com
SCR_BOOTSTRAP_ADMIN_USERNAME=admin
SCR_BOOTSTRAP_ADMIN_PASSWORD=replace-with-a-strong-password
```

In the Dokploy **Domains** tab, add the hostname from `SCR_PUBLIC_URL`, select the `registry` service, set the container port to `5000`, and enable HTTPS. The public URL must be the origin only, without a trailing slash or path.

The Compose deployment builds the image from this repository and stores the SQLite database and registry content in the `registry-data` named volume. For monitoring, configure Dokploy to request `GET /healthz` on port `5000`.

## Configuration

The published Docker image starts SCR with `-config /etc/scr/config.yaml`. The included file is equivalent to:

```yaml
http:
  address: "0.0.0.0"
  port: 5000
  secureCookies: true
  allowInsecureHTTP: false
  publicURL: ""
  trustForwardedHeaders: false
  trustedProxyCIDRs: []
  readTimeout: "30m"
  writeTimeout: "30m"
  idleTimeout: "2m"
  maxHeaderBytes: 1048576

storage:
  rootDirectory: "/var/lib/scr/registry"
  gc: true
  gcDelay: "1h"
  gcInterval: "24h"

database:
  driver: "sqlite"
  dsn: "/var/lib/scr/scr.db"

auth:
  issuer: "scr"
  service: "scr"
  tokenTTL: "10m"
```

This secure default intentionally fails validation until you configure an HTTPS `http.publicURL`; this prevents accidentally serving the plaintext listener without an explicit deployment choice. The check applies only to non-loopback binds: when `http.address` is a loopback address the listener cannot be reached off-host, so plain HTTP needs no opt-in there. For direct local HTTP, use `config.local.example.yaml`, which binds `127.0.0.1`. To serve plain HTTP on a reachable address anyway, set `http.allowInsecureHTTP: true` in a mounted configuration file.

To use a custom configuration file, mount it over `/etc/scr/config.yaml`:

```bash
docker run --rm --name scr \
  -p 5000:5000 \
  -v scr-data:/var/lib/scr \
  -v "$PWD/config.yaml:/etc/scr/config.yaml:ro" \
  -e SCR_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e SCR_BOOTSTRAP_ADMIN_PASSWORD=change-me \
  bytebardorg/simplecontainerregistry:latest
```

Configuration supports these sections:

- `http.address` and `http.port`
- `http.secureCookies`; defaults to `true`. Leave enabled when SCR is accessed over HTTPS, including behind an HTTPS-terminating reverse proxy.
- `http.allowInsecureHTTP`; defaults to `false`. Set to `true` to serve plain HTTP, an `http://` `http.publicURL`, or `secureCookies: false` on a non-loopback bind. Loopback binds such as `127.0.0.1`, `::1`, and `localhost` do not need this opt-in.
- `http.publicURL`; HTTPS public origin such as `https://registry.example.com`, used as the canonical token-service challenge URL. It is required on non-loopback binds unless `http.allowInsecureHTTP` is explicitly enabled. When it is empty, the challenge realm falls back to the request `Host` header, so leave it empty only for loopback binds.
- `http.trustForwardedHeaders`; defaults to `false`. When enabled, requires an HTTPS `http.publicURL` and non-empty `http.trustedProxyCIDRs`.
- `http.trustedProxyCIDRs`; CIDRs of reverse proxies allowed to supply `X-Forwarded-For` or `X-Real-IP` for audit and client address handling. Entries must be properly masked network prefixes and may not be `0.0.0.0/0` or `::/0`, since trusting every peer would let any client forge its own address.
- `http.readTimeout`, `http.writeTimeout`, and `http.idleTimeout`; finite connection limits, defaulting to 30 minutes, 30 minutes, and 2 minutes respectively to accommodate streamed OCI transfers.
- `http.maxHeaderBytes`; maximum request-header size, defaulting to 1048576 bytes.
- `storage.rootDirectory`
- `storage.gc`
- `storage.gcDelay`
- `storage.gcInterval`
- `database.driver` set to `sqlite`; other database drivers are not supported
- `database.dsn`
- `auth.issuer`
- `auth.service`
- `auth.tokenTTL`
- optional `bootstrap.adminUsername`
- optional `bootstrap.adminPassword`

Default container paths:

- configuration: `/etc/scr/config.yaml`
- persistent data: `/var/lib/scr`
- registry storage: `/var/lib/scr/registry`
- SQLite database: `/var/lib/scr/scr.db`
- HTTP port: `5000`

Bootstrap admin username and password are normally provided with environment variables:

- `SCR_BOOTSTRAP_ADMIN_USERNAME`
- `SCR_BOOTSTRAP_ADMIN_PASSWORD`

If bootstrap admin values are omitted from the config file, SCR fills them from those environment variables. Provide both values together. The application reads no HTTP configuration from runtime environment variables; configure HTTP settings in the mounted YAML file. Compose variables are expanded by Compose while it generates that file.

### Admin UI cookies and reverse proxies

SCR stores admin UI sessions in an `HttpOnly`, `SameSite=Lax` cookie. By default, `http.secureCookies` is `true`, which also marks that cookie `Secure` so browsers only send it over HTTPS.

Keep `http.secureCookies: true` for production deployments, including the common setup where a reverse proxy terminates HTTPS and forwards plain HTTP to SCR. The browser only sees the public HTTPS URL, so the `Secure` cookie works normally even if the proxy-to-SCR hop is HTTP.

When SCR is behind a reverse proxy, set `http.publicURL` to the HTTPS public registry origin. To retain forwarded client IPs in audit records, set `http.trustForwardedHeaders: true` and list only the proxy networks in `http.trustedProxyCIDRs`; SCR ignores forwarded client-address headers from every other peer. SCR evaluates `X-Forwarded-For` right-to-left and skips trusted proxy addresses, but the proxy must still strip or overwrite client-supplied forwarding headers and direct client access to the backend must be network-isolated. Bearer challenges always use the configured canonical public URL and never use forwarded host or protocol headers.

Set `http.secureCookies: false` only when users access SCR directly over plain HTTP, such as a local development instance or a trusted internal HTTP-only deployment. On a non-loopback bind this also requires `http.allowInsecureHTTP: true`; existing direct HTTP configurations that disable secure cookies, or that use an `http://` public URL, must add that explicit opt-in. Loopback binds are exempt because the listener is unreachable from other hosts. Do not disable secure cookies for an HTTPS reverse-proxy deployment, including one that proxies to a loopback bind on the same host: the browser sees HTTPS and the `Secure` flag still belongs on the cookie.

## Authentication and access

Registry clients use Docker-compatible bearer-token authentication:

- Call `GET /token?service=scr&scope=repository:{name}:pull,push` with HTTP Basic auth.
- Use the returned bearer token against `/v2/...` endpoints.
- Registry responses include `WWW-Authenticate` bearer challenges when auth is missing or insufficient.

Admin API routes require an admin bearer token from `/token`.

Access model:

- Each user is the login identity and access secret.
- User creation returns the secret once.
- Reader users need repository-prefix grants for pull, push, or delete access.
- Repository grants can target `*` for all repositories or a repository name/namespace such as `shieldedstack/`.
- Non-wildcard grant prefixes match the exact repository or slash-delimited descendants, not glob or regex patterns. For example, `team/` matches repositories under that namespace, while `team/app` matches `team/app` and `team/app/api` but not `team/application`.
- Admin users can request repository access without grants.
- Users may have an optional valid-from date and optional expiry date.
- Token validation re-checks current user status and validity, so disabled, future-valid, and expired users are rejected even if a token was issued earlier.

## Runtime behavior

Security and storage behavior:

- User secrets are hashed with Argon2id.
- JWT signing keys are persisted in SQLite.
- Registry blobs and manifests are stored in the configured filesystem root.
- Repository metadata and dashboard traffic are derived from real push/pull activity.
- Audit events are recorded for token issuance/denial, admin mutations, registry push/pull/delete activity, and authenticated registry access denials.
- Registry webhook delivery can be configured from the admin Settings UI. When enabled, SCR sends best-effort JSON POST events for registry pull, push, delete, and admin UI repository-delete activity. Webhook failures are logged and do not fail registry requests.
- Garbage collection removes untagged manifest records after the configured grace period. Blob delete is supported through the OCI API; automated blob/layer garbage collection is intentionally deferred because blobs can be shared across manifests.

## Registry webhooks

Admins can configure a registry webhook URL from `/ui/settings`. Leave the URL empty to disable delivery.

SCR sends registry webhooks as best-effort HTTP `POST` requests with `Content-Type: application/json` and `User-Agent: simplecontainerregistry-webhook`. Webhook delivery is asynchronous, has a short timeout, and does not fail the original registry or admin UI request if the destination is slow, unavailable, or returns a non-2xx response.

Webhook delivery rejects loopback, private, link-local, multicast, and unspecified IP destinations, including hostnames that resolve to those addresses.

Delivered events:

- `registry.manifest.pulled` with group `registry.pull`
- `registry.blob.pulled` with group `registry.pull`
- `registry.manifest.pushed` with group `registry.push`
- `registry.manifest.tagged` with group `registry.push`
- `registry.blob.pushed` with group `registry.push`
- `registry.manifest.deleted` with group `registry.delete`
- `registry.blob.deleted` with group `registry.delete`
- `repository.deleted` with group `registry.delete` when an admin deletes a repository from the UI

Webhook payload schema:

```json
{
  "id": "aud_...",
  "event": "registry.manifest.pushed",
  "group": "registry.push",
  "targetType": "repository",
  "targetId": "team/app",
  "actorUserId": "usr_...",
  "result": "success",
  "ipAddress": "203.0.113.10",
  "userAgent": "docker/27.0.0 go/go1.22 git-commit/... kernel/... os/linux arch/amd64 UpstreamClient(Docker-Client/27.0.0)",
  "createdAt": "2026-07-11T12:34:56Z"
}
```

Payload fields:

- `id`: stable audit event ID for this webhook event.
- `event`: exact event name.
- `group`: coarse event group, one of `registry.pull`, `registry.push`, or `registry.delete`.
- `targetType`: event target type. Registry webhook events currently use `repository`.
- `targetId`: repository name, such as `team/app`.
- `actorUserId`: authenticated user ID when available. This field is omitted for anonymous/system events.
- `result`: audit result. Registry webhook events currently emit successful events only.
- `ipAddress`: client IP resolved from `X-Forwarded-For`, `X-Real-IP`, or the remote address.
- `userAgent`: request user agent.
- `createdAt`: event creation timestamp in RFC 3339 format.

OCI clients can make multiple registry API calls for one high-level image operation. For example, a single `docker pull` usually emits one manifest pull event plus one or more blob pull events.

Registry access denials are stored in audit events as `registry.access.denied` with result `denied`. They are not delivered to registry webhooks.

## Tag management

Tags can be added after a manifest is pushed in either of these ways:

- OCI clients can push the existing manifest body to `/v2/{name}/manifests/{new_tag}`, or push it by digest with `?tag={new_tag}`.
- Admins can link an existing repository-local manifest without uploading its body with `POST /api/repository-tags/{name}` and a JSON body such as `{"tag":"stable","digest":"sha256:..."}`.

The admin UI exposes the link-only operation on the Repositories page. The digest must already exist in that exact repository; manifests and blobs are not linked across repositories.

Each repository has a tag overwrite protection policy managed with `GET` and `PUT /api/repository-tag-policies/{name}`. The supported modes are:

- `mutable`: all tags may be moved.
- `immutable`: existing tags cannot be moved to another digest.
- `pattern`: tags matching the supplied Go/RE2 regular expression cannot be moved to another digest.

The policy defaults to `mutable`. Same-digest retries are allowed. SCR's protection is intentionally overwrite-only: protected tags can still be deleted and the name can later be reused for another digest.

## API surface

OCI Distribution API:

- `GET /v2/`
- `GET /v2/_catalog`
- `POST /v2/{name}/blobs/uploads/`
- `PATCH /v2/{name}/blobs/uploads/{upload_id}`
- `GET /v2/{name}/blobs/uploads/{upload_id}`
- `PUT /v2/{name}/blobs/uploads/{upload_id}?digest={digest}`
- `GET /v2/{name}/blobs/{digest}`
- `HEAD /v2/{name}/blobs/{digest}`
- `DELETE /v2/{name}/blobs/{digest}`
- `PUT /v2/{name}/manifests/{reference}` including digest references and `?tag={tag}` query parameters
- `GET /v2/{name}/manifests/{reference}`
- `HEAD /v2/{name}/manifests/{reference}`
- `DELETE /v2/{name}/manifests/{reference}`
- `GET /v2/{name}/tags/list` including `n` and `last` pagination
- `GET /v2/{name}/referrers/{digest}` including `artifactType` filtering

Implemented OCI Distribution behavior includes sha256 and sha512 digests, blob range requests, monolithic and chunked blob uploads, upload status checks, digest-validated manifest pushes, OCI referrers, `OCI-Subject` and `OCI-Tag` response headers, manifest delete, blob delete, tag delete, and catalog/tag pagination.

Authentication and health:

- `GET /healthz`
- `GET /token`

Admin API:

- `GET /api/users`
- `POST /api/users`
- `GET /api/users/{id}`
- `DELETE /api/users/{id}`
- `POST /api/users/{id}/disable`
- `POST /api/users/{id}/enable`
- `GET /api/grants`
- `POST /api/grants`
- `DELETE /api/grants/{id}`
- `GET /api/dashboard/summary`
- `GET /api/repositories`
- `GET /api/repositories/{name}`
- `GET /api/repositories/{name}/tags`
- `GET /api/repository-tags/{name}`
- `POST /api/repository-tags/{name}`
- `GET /api/repository-tag-policies/{name}`
- `PUT /api/repository-tag-policies/{name}`
- `GET /api/audit-events`

Admin UI:

- `GET /ui`
- `GET /ui/login`
- `POST /ui/login`
- `POST /ui/logout`
- `GET /ui/repositories`
- `POST /ui/repositories/delete`
- `POST /ui/repositories/delete-tag`
- `POST /ui/repositories/add-tag`
- `POST /ui/repositories/tag-policy`
- `GET /ui/users`
- `POST /ui/users`
- `POST /ui/users/{id}/access`
- `POST /ui/users/{id}/delete`
- `GET /ui/audit`
- `GET /ui/settings`
- `POST /ui/settings/gc`
- `POST /ui/settings/webhook`

`GET /` redirects to `/v2/` so container clients see the registry API root by default.

## Current status

Implemented:

- SQLite schema and store layer
- Filesystem-backed OCI blob and manifest storage
- Manifest delete, blob delete, referrers, catalog listing, tag pagination, and blob range requests
- Background garbage collection for untagged manifests
- Docker-compatible bearer-token flow
- Repository-prefix grant intersection
- One-secret-per-user onboarding
- Date-only user validity management in the UI
- Repository UI tag deletion and delete-all repository actions
- Link-only post-push tag creation through the admin API and UI
- Per-repository tag overwrite protection with mutable, all-tag, and regex-selected modes
- Atomic tag reference replacement and policy-aware OCI manifest pushes
- Repository UI accordion view with tag metadata, newest-pushed-first ordering, and client-side tag table sorting
- Customer access UI for repository-prefix grants, including wildcard `*`, pull, push, and delete actions
- Audit UI filtering by query and action class
- Settings UI for garbage collection enablement, grace period, run interval, and registry webhook URL
- Registry webhook delivery for pull, push, delete, and admin UI repository-delete activity
- User creation, disable/enable, deletion, and grant deletion
- Repository read model and dashboard summary counters
- Server-rendered admin UI for dashboard, repositories, users, and audit log
- Audit UI username resolution for user IDs where possible
- End-to-end smoke script for admin push/delete, reader list/pull, reader push denial, catalog, admin APIs, dashboard, and audit
- Local OCI Distribution Spec conformance script

Not implemented yet:

- Blob/layer garbage collection
- Richer activity feeds
- Separate admin-account management UI

## License

Simple Container Registry is distributed under `LICENSE.BSL`, a source-available license that permits internal use, modification, distribution, and production use, but prohibits offering the registry as a hosted or managed third-party service without a commercial license. Each major version converts to the MIT License five years after its initial public release.

## Contributing and local build

The container default config is sourced from `config.container.yaml`. `config.example.yaml` mirrors the production/container defaults, and `config.local.example.yaml` uses writable `data/` paths for local development.

Run the test suite:

```bash
go test ./...
```

Start the server locally with a bootstrap admin:

```bash
SCR_BOOTSTRAP_ADMIN_USERNAME=admin \
SCR_BOOTSTRAP_ADMIN_PASSWORD=change-me \
go run ./cmd/simplecontainerregistry -config config.local.example.yaml
```

Open the admin UI at `http://localhost:5000/ui`. Sign in with the bootstrap admin username and password.

Build a local Docker image:

```bash
docker build -t scr:local .
```

Run the local image with a named volume:

```bash
docker run --rm --name scr \
  -p 5000:5000 \
  -v scr-data:/var/lib/scr \
  -e SCR_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e SCR_BOOTSTRAP_ADMIN_PASSWORD=change-me \
  scr:local
```

Run an end-to-end OCI smoke test with a temporary database and registry root:

```bash
scripts/oci-smoke.sh
```

The smoke test starts the server, creates an admin and pull-only reader, pushes an OCI manifest/blob, lists tags, pulls as reader, verifies reader push/admin access is denied, checks catalog/repository/dashboard/audit APIs, and deletes the pushed manifest.

Seed and verify a running SCR instance without deleting the created data:

```bash
BASE_URL=http://127.0.0.1:5000 \
ADMIN_USERNAME=admin \
ADMIN_PASSWORD=change-me \
scripts/functional-demo.sh
```

The functional demo script pushes an OCI repository, creates one expiring read-only user for that repository, creates a second expiring read-only user for a different repository, verifies the first user can pull, verifies the second user cannot access the seeded repository, verifies push/admin access is denied, verifies the denied registry access appears in audit events, and leaves the repository and users in place for admin UI testing.

Useful smoke test overrides:

- `PORT=18081`
- `REPO=smoke/demo`
- `TAG=v1`
- `KEEP_SMOKE_DIR=1`

Example:

```bash
PORT=18081 REPO=smoke/demo TAG=v1 scripts/oci-smoke.sh
```

Run the upstream OCI Distribution Spec conformance suite locally against a temporary SCR instance:

```bash
KEEP_CONFORMANCE_DIR=1 scripts/oci-conformance.sh
```

The script starts a temporary registry, clones or reuses `opencontainers/distribution-spec`, runs the conformance suite, and writes `results.yaml`, `report.html`, and `junit.xml` under the printed results directory.

Current local conformance profile:

- OCI Distribution Spec version `1.1`
- blob delete enabled
- referrers enabled
- manifest tag parameters enabled
- sha512 data enabled
- anonymous blob mount disabled
- upload cancel disabled
- sparse manifests disabled by the upstream default

The latest local run passed with `972` passing tests, `0` failures, `4` disabled, and `2` skipped.

The GitHub Actions workflow lives at `.github/workflows/ci.yml`; the CI badge at the top of this README points to the workflow for `ByteBardOrg/simplecontainerregistry`.

Maintainers can publish a multi-architecture image to Docker Hub:

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t docker.io/bytebardorg/simplecontainerregistry:latest \
  --push .
```

Use an explicit version tag for releases:

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t docker.io/bytebardorg/simplecontainerregistry:latest \
  -t docker.io/bytebardorg/simplecontainerregistry:v0.1.0 \
  --push .
```
