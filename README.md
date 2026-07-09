# Simple Container Registry

[![CI](https://github.com/ByteBardOrg/simplecontainerregistry/actions/workflows/ci.yml/badge.svg)](https://github.com/ByteBardOrg/simplecontainerregistry/actions/workflows/ci.yml)

Current development status: `pre-release`

This repository contains the Go implementation for a self-hosted OCI container registry with managed user access, SQLite-backed management data, filesystem-backed registry storage, audit logging, and a server-rendered admin UI.

Registry content is stored on disk. Users, repository grants, repository metadata, usage counters, audit events, and signing keys are stored in SQLite.

## Implemented endpoints

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
- `GET /api/audit-events`

Admin UI:

- `GET /ui`
- `GET /ui/login`
- `POST /ui/login`
- `POST /ui/logout`
- `GET /ui/repositories`
- `POST /ui/repositories/delete`
- `POST /ui/repositories/delete-tag`
- `GET /ui/users`
- `POST /ui/users`
- `POST /ui/users/{id}/access`
- `POST /ui/users/{id}/delete`
- `GET /ui/audit`
- `GET /ui/settings`
- `POST /ui/settings/gc`

`GET /` redirects to `/v2/` so container clients see the registry API root by default.

## Local development

1. Run the test suite:

```bash
go test ./...
```

2. Start the server with a bootstrap admin:

```bash
SCR_BOOTSTRAP_ADMIN_USERNAME=admin \
SCR_BOOTSTRAP_ADMIN_PASSWORD=change-me \
go run ./cmd/simplecontainerregistry -config config.local.example.yaml
```

3. Open the admin UI:

```text
http://localhost:5000/ui
```

Sign in with the bootstrap admin username and password. The bootstrap admin is created only if that username does not already exist.

## Docker

Build a local image:

```bash
docker build -t scr:local .
```

Run SCR with a named volume for registry content and SQLite state:

```bash
docker run --rm \
  -p 5000:5000 \
  -v scr-data:/var/lib/scr \
  -e SCR_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e SCR_BOOTSTRAP_ADMIN_PASSWORD=change-me \
  scr:local
```

The container image uses `/etc/scr/config.yaml` and stores persistent data under `/var/lib/scr`.

Publish a multi-architecture image to Docker Hub:

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

## Quick smoke test

Run an end-to-end OCI smoke test with a temporary database and registry root:

```bash
scripts/oci-smoke.sh
```

The smoke test starts the server, creates an admin and pull-only reader, pushes an OCI manifest/blob, lists tags, pulls as reader, verifies reader push/admin access is denied, checks catalog/repository/dashboard/audit APIs, and deletes the pushed manifest.

Useful overrides:

- `PORT=18081`
- `REPO=smoke/demo`
- `TAG=v1`
- `KEEP_SMOKE_DIR=1`

Example:

```bash
PORT=18081 REPO=smoke/demo TAG=v1 scripts/oci-smoke.sh
```

## OCI conformance

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

## Authentication

Registry clients use Docker-compatible bearer-token authentication:

- Call `GET /token?service=scr&scope=repository:{name}:pull,push` with HTTP Basic auth.
- Use the returned bearer token against `/v2/...` endpoints.
- Registry responses include `WWW-Authenticate` bearer challenges when auth is missing or insufficient.

Admin API routes require an admin bearer token from `/token`.

Access model:

- Each user is the login identity and access secret.
- User creation returns the secret once.
- Reader users need repository-prefix grants for pull/push access.
- Repository grants can target `*` for all repositories, a namespace prefix such as `shieldedstack/`, or an exact image repository such as `shieldedstack/proxy`.
- Admin users can request repository access without grants.
- Users may have an optional valid-from date and optional expiry date.
- Token validation re-checks current user status and validity, so disabled, future-valid, and expired users are rejected even if a token was issued earlier.

## License

Simple Container Registry is distributed under `LICENSE.BSL`, a source-available license that permits internal use, modification, distribution, and production use, but prohibits offering the registry as a hosted or managed third-party service without a commercial license. Each major version converts to the MIT License five years after its initial public release.

## Operational defaults

Configuration lives in `config.example.yaml` for production/container defaults. `config.local.example.yaml` uses writable `data/` paths for local development. Configuration supports these sections:

- `http.address` and `http.port`
- `storage.rootDirectory`
- `storage.commit`
- `storage.gc`
- `storage.gcDelay`
- `storage.gcInterval`
- `database.driver` set to `sqlite`
- `database.dsn`
- `auth.issuer`
- `auth.service`
- `auth.tokenTTL`

Default local/container paths:

- configuration: `/etc/scr/config.yaml` in the container image
- persistent data: `/var/lib/scr`
- registry storage: `/var/lib/scr/registry`
- SQLite database: `/var/lib/scr/scr.db`
- HTTP port: `5000`

Bootstrap admin username and password are normally provided with environment variables:

- `SCR_BOOTSTRAP_ADMIN_USERNAME`
- `SCR_BOOTSTRAP_ADMIN_PASSWORD`

Security and storage behavior:

- User secrets are hashed with Argon2id.
- JWT signing keys are persisted in SQLite.
- Registry blobs and manifests are stored in the configured filesystem root.
- Repository metadata and dashboard traffic are derived from real push/pull activity.
- Audit events are recorded for token issuance/denial, admin mutations, and registry push/pull activity.
- Garbage collection removes untagged manifest records after the configured grace period. Blob delete is supported through the OCI API; automated blob/layer garbage collection is intentionally deferred because blobs can be shared across manifests.

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
- Repository UI accordion view with tag metadata, newest-pushed-first ordering, and client-side tag table sorting
- Customer access UI for repository-prefix grants, including wildcard `*`, pull, push, and delete actions
- Audit UI filtering by query and action class
- Settings UI for garbage collection enablement, grace period, and run interval
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
