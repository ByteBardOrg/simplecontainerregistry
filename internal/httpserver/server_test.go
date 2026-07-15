package httpserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"simplecontainerregistry/internal/auth"
	"simplecontainerregistry/internal/config"
	"simplecontainerregistry/internal/db"
	"simplecontainerregistry/internal/domain"
)

func TestHTTPTokenAndAdminFlow(t *testing.T) {
	ctx := context.Background()
	cfg := config.Default()
	cfg.Storage.RootDirectory = filepath.Join(t.TempDir(), "registry")
	cfg.Database.DSN = filepath.Join(t.TempDir(), "test.db")
	store, err := db.Open(ctx, cfg.Database.DSN)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.InitSchema(ctx); err != nil {
		t.Fatalf("InitSchema() error = %v", err)
	}
	if err := store.EnsureActiveSigningKey(ctx); err != nil {
		t.Fatalf("EnsureActiveSigningKey() error = %v", err)
	}
	if err := auth.BootstrapAdmin(ctx, store, "admin", "secret", time.Now().UTC()); err != nil {
		t.Fatalf("BootstrapAdmin() error = %v", err)
	}

	handler := New(Options{Config: cfg, Store: store})

	ping := httptest.NewRecorder()
	handler.ServeHTTP(ping, httptest.NewRequest(http.MethodGet, "/v2/", nil))
	if ping.Code != http.StatusUnauthorized {
		t.Fatalf("expected /v2/ unauthorized, got %d", ping.Code)
	}
	if ping.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("expected bearer challenge")
	}

	tokenRequest := httptest.NewRequest(http.MethodGet, "/token?service=scr", nil)
	tokenRequest.SetBasicAuth("admin", "secret")
	tokenResponse := httptest.NewRecorder()
	handler.ServeHTTP(tokenResponse, tokenRequest)
	if tokenResponse.Code != http.StatusOK {
		t.Fatalf("expected token status 200, got %d: %s", tokenResponse.Code, tokenResponse.Body.String())
	}
	var tokenPayload struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(tokenResponse.Body).Decode(&tokenPayload); err != nil {
		t.Fatalf("Decode token response error = %v", err)
	}
	if tokenPayload.Token == "" {
		t.Fatal("expected token")
	}

	badTokenRequest := httptest.NewRequest(http.MethodGet, "/token?service=scr", nil)
	badTokenRequest.SetBasicAuth("admin", "wrong-secret")
	badTokenResponse := httptest.NewRecorder()
	handler.ServeHTTP(badTokenResponse, badTokenRequest)
	if badTokenResponse.Code != http.StatusUnauthorized {
		t.Fatalf("expected bad token status 401, got %d: %s", badTokenResponse.Code, badTokenResponse.Body.String())
	}

	usersRequest := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	usersRequest.Header.Set("Authorization", "Bearer "+tokenPayload.Token)
	usersResponse := httptest.NewRecorder()
	handler.ServeHTTP(usersResponse, usersRequest)
	if usersResponse.Code != http.StatusOK {
		t.Fatalf("expected users status 200, got %d: %s", usersResponse.Code, usersResponse.Body.String())
	}

	createUserBody := strings.NewReader(`{"username":"audited-reader","displayName":"Audited Reader","role":"reader"}`)
	createUserRequest := httptest.NewRequest(http.MethodPost, "/api/users", createUserBody)
	createUserRequest.Header.Set("Authorization", "Bearer "+tokenPayload.Token)
	createUserResponse := httptest.NewRecorder()
	handler.ServeHTTP(createUserResponse, createUserRequest)
	if createUserResponse.Code != http.StatusCreated {
		t.Fatalf("expected create user status 201, got %d: %s", createUserResponse.Code, createUserResponse.Body.String())
	}

	auditRequest := httptest.NewRequest(http.MethodGet, "/api/audit-events", nil)
	auditRequest.Header.Set("Authorization", "Bearer "+tokenPayload.Token)
	auditResponse := httptest.NewRecorder()
	handler.ServeHTTP(auditResponse, auditRequest)
	if auditResponse.Code != http.StatusOK {
		t.Fatalf("expected audit status 200, got %d: %s", auditResponse.Code, auditResponse.Body.String())
	}
	var events []domain.AuditEvent
	if err := json.NewDecoder(auditResponse.Body).Decode(&events); err != nil {
		t.Fatalf("Decode audit response error = %v", err)
	}
	actions := make([]string, 0, len(events))
	for _, event := range events {
		actions = append(actions, event.Action)
	}
	if !slices.Contains(actions, "token.issued") {
		t.Fatalf("expected token.issued audit event, got %#v", actions)
	}
	if !slices.Contains(actions, "token.denied") {
		t.Fatalf("expected token.denied audit event, got %#v", actions)
	}
	if !slices.Contains(actions, "user.created") {
		t.Fatalf("expected user.created audit event, got %#v", actions)
	}
}

func TestRegistryBlobManifestAndTagsFlow(t *testing.T) {
	ctx := context.Background()
	cfg := config.Default()
	cfg.Storage.RootDirectory = filepath.Join(t.TempDir(), "registry")
	cfg.Database.DSN = filepath.Join(t.TempDir(), "test.db")
	store, err := db.Open(ctx, cfg.Database.DSN)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.InitSchema(ctx); err != nil {
		t.Fatalf("InitSchema() error = %v", err)
	}
	if err := store.EnsureActiveSigningKey(ctx); err != nil {
		t.Fatalf("EnsureActiveSigningKey() error = %v", err)
	}
	now := time.Now().UTC()
	user := createHTTPTestUser(t, ctx, store, "reader", "Reader", domain.RoleReader, "secret", now)
	if _, err := store.CreateGrant(ctx, db.CreateGrantParams{SubjectType: "user", SubjectID: user.ID, RepositoryPrefix: "team-a/", Actions: []domain.Action{domain.ActionPull, domain.ActionPush}}, now); err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}

	handler := New(Options{Config: cfg, Store: store})
	token := requestToken(t, handler, "reader", "secret", "repository:team-a/app:pull,push")

	start := authenticatedRequest(handler, http.MethodPost, "/v2/team-a/app/blobs/uploads/", token, nil)
	if start.Code != http.StatusAccepted {
		t.Fatalf("expected upload start 202, got %d: %s", start.Code, start.Body.String())
	}
	location := start.Header().Get("Location")
	if location == "" {
		t.Fatal("expected upload location")
	}

	blob := []byte("hello registry")
	patch := authenticatedRequest(handler, http.MethodPatch, location, token, bytes.NewReader(blob))
	if patch.Code != http.StatusAccepted {
		t.Fatalf("expected upload patch 202, got %d: %s", patch.Code, patch.Body.String())
	}
	digest := sha256Digest(blob)
	commit := authenticatedRequest(handler, http.MethodPut, location+"?digest="+digest, token, nil)
	if commit.Code != http.StatusCreated {
		t.Fatalf("expected upload commit 201, got %d: %s", commit.Code, commit.Body.String())
	}

	fetchBlob := authenticatedRequest(handler, http.MethodGet, "/v2/team-a/app/blobs/"+digest, token, nil)
	if fetchBlob.Code != http.StatusOK {
		t.Fatalf("expected blob get 200, got %d: %s", fetchBlob.Code, fetchBlob.Body.String())
	}
	if fetchBlob.Body.String() != string(blob) {
		t.Fatalf("unexpected blob body %q", fetchBlob.Body.String())
	}

	manifest := []byte(`{"schemaVersion":2}`)
	putManifest := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/v2/team-a/app/manifests/latest", bytes.NewReader(manifest))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
	handler.ServeHTTP(putManifest, req)
	if putManifest.Code != http.StatusCreated {
		t.Fatalf("expected manifest put 201, got %d: %s", putManifest.Code, putManifest.Body.String())
	}
	manifestDigest := putManifest.Header().Get("Docker-Content-Digest")
	if manifestDigest == "" {
		t.Fatal("expected manifest digest header")
	}

	getManifest := authenticatedRequest(handler, http.MethodGet, "/v2/team-a/app/manifests/latest", token, nil)
	if getManifest.Code != http.StatusOK {
		t.Fatalf("expected manifest get 200, got %d: %s", getManifest.Code, getManifest.Body.String())
	}
	if getManifest.Body.String() != string(manifest) {
		t.Fatalf("unexpected manifest body %q", getManifest.Body.String())
	}

	tags := authenticatedRequest(handler, http.MethodGet, "/v2/team-a/app/tags/list", token, nil)
	if tags.Code != http.StatusOK {
		t.Fatalf("expected tags list 200, got %d: %s", tags.Code, tags.Body.String())
	}
	if !strings.Contains(tags.Body.String(), "latest") {
		t.Fatalf("expected latest tag, got %s", tags.Body.String())
	}

	createHTTPTestUser(t, ctx, store, "admin", "Admin", domain.RoleAdmin, "admin-secret", now)
	adminToken := requestToken(t, handler, "admin", "admin-secret", "")
	adminDeleteToken := requestToken(t, handler, "admin", "admin-secret", "repository:team-a/app:delete")

	repositories := authenticatedRequest(handler, http.MethodGet, "/api/repositories", adminToken, nil)
	if repositories.Code != http.StatusOK {
		t.Fatalf("expected repositories 200, got %d: %s", repositories.Code, repositories.Body.String())
	}
	if !strings.Contains(repositories.Body.String(), "team-a/app") {
		t.Fatalf("expected repository read model, got %s", repositories.Body.String())
	}

	repositoryTags := authenticatedRequest(handler, http.MethodGet, "/api/repositories/team-a/app/tags", adminToken, nil)
	if repositoryTags.Code != http.StatusOK {
		t.Fatalf("expected repository tags 200, got %d: %s", repositoryTags.Code, repositoryTags.Body.String())
	}
	if !strings.Contains(repositoryTags.Body.String(), "latest") || !strings.Contains(repositoryTags.Body.String(), manifestDigest) {
		t.Fatalf("expected repository tag metadata, got %s", repositoryTags.Body.String())
	}

	catalog := authenticatedRequest(handler, http.MethodGet, "/v2/_catalog", adminToken, nil)
	if catalog.Code != http.StatusOK {
		t.Fatalf("expected catalog 200, got %d: %s", catalog.Code, catalog.Body.String())
	}
	if !strings.Contains(catalog.Body.String(), "team-a/app") {
		t.Fatalf("expected catalog to include repository, got %s", catalog.Body.String())
	}
	catalogPage := authenticatedRequest(handler, http.MethodGet, "/v2/_catalog?n=1", adminToken, nil)
	if catalogPage.Code != http.StatusOK {
		t.Fatalf("expected paginated catalog 200, got %d: %s", catalogPage.Code, catalogPage.Body.String())
	}
	if catalogPage.Header().Get("Link") != "" && !strings.Contains(catalogPage.Header().Get("Link"), "/v2/_catalog?") {
		t.Fatalf("expected catalog pagination link, got %q", catalogPage.Header().Get("Link"))
	}

	dashboard := authenticatedRequest(handler, http.MethodGet, "/api/dashboard/summary", adminToken, nil)
	if dashboard.Code != http.StatusOK {
		t.Fatalf("expected dashboard 200, got %d: %s", dashboard.Code, dashboard.Body.String())
	}
	if !strings.Contains(dashboard.Body.String(), `"repositories":1`) || !strings.Contains(dashboard.Body.String(), `"tags":1`) {
		t.Fatalf("expected dashboard repository counts, got %s", dashboard.Body.String())
	}

	deleteManifest := authenticatedRequest(handler, http.MethodDelete, "/v2/team-a/app/manifests/"+manifestDigest, adminDeleteToken, nil)
	if deleteManifest.Code != http.StatusAccepted {
		t.Fatalf("expected manifest delete 202, got %d: %s", deleteManifest.Code, deleteManifest.Body.String())
	}
	missingManifest := authenticatedRequest(handler, http.MethodGet, "/v2/team-a/app/manifests/latest", token, nil)
	if missingManifest.Code != http.StatusNotFound {
		t.Fatalf("expected deleted manifest to be missing, got %d: %s", missingManifest.Code, missingManifest.Body.String())
	}
	emptyTags := authenticatedRequest(handler, http.MethodGet, "/v2/team-a/app/tags/list", token, nil)
	if emptyTags.Code != http.StatusOK {
		t.Fatalf("expected tag list after delete 200, got %d: %s", emptyTags.Code, emptyTags.Body.String())
	}
	if strings.Contains(emptyTags.Body.String(), "latest") {
		t.Fatalf("expected deleted tag to be removed, got %s", emptyTags.Body.String())
	}

	audit := authenticatedRequest(handler, http.MethodGet, "/api/audit-events", adminToken, nil)
	if audit.Code != http.StatusOK {
		t.Fatalf("expected audit 200, got %d: %s", audit.Code, audit.Body.String())
	}
	var events []domain.AuditEvent
	if err := json.NewDecoder(audit.Body).Decode(&events); err != nil {
		t.Fatalf("Decode audit response error = %v", err)
	}
	actions := make([]string, 0, len(events))
	for _, event := range events {
		actions = append(actions, event.Action)
	}
	if !slices.Contains(actions, "registry.manifest.pushed") {
		t.Fatalf("expected registry.manifest.pushed audit event, got %#v", actions)
	}
	if !slices.Contains(actions, "registry.manifest.pulled") {
		t.Fatalf("expected registry.manifest.pulled audit event, got %#v", actions)
	}
	if !slices.Contains(actions, "registry.manifest.deleted") {
		t.Fatalf("expected registry.manifest.deleted audit event, got %#v", actions)
	}
}

func TestPullOnlyReaderCanListAndPullButNotPush(t *testing.T) {
	ctx := context.Background()
	cfg := config.Default()
	cfg.Storage.RootDirectory = filepath.Join(t.TempDir(), "registry")
	cfg.Database.DSN = filepath.Join(t.TempDir(), "test.db")
	store, err := db.Open(ctx, cfg.Database.DSN)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.InitSchema(ctx); err != nil {
		t.Fatalf("InitSchema() error = %v", err)
	}
	if err := store.EnsureActiveSigningKey(ctx); err != nil {
		t.Fatalf("EnsureActiveSigningKey() error = %v", err)
	}
	now := time.Now().UTC()
	createHTTPTestUser(t, ctx, store, "admin", "Admin", domain.RoleAdmin, "admin-secret", now)
	reader := createHTTPTestUser(t, ctx, store, "reader", "Reader", domain.RoleReader, "reader-secret", now)
	if _, err := store.CreateGrant(ctx, db.CreateGrantParams{SubjectType: "user", SubjectID: reader.ID, RepositoryPrefix: "team-read/", Actions: []domain.Action{domain.ActionPull}}, now); err != nil {
		t.Fatalf("CreateGrant(reader) error = %v", err)
	}

	handler := New(Options{Config: cfg, Store: store})
	adminToken := requestToken(t, handler, "admin", "admin-secret", "repository:team-read/app:pull,push")
	manifest := []byte(`{"schemaVersion":2}`)
	putManifest := httptest.NewRecorder()
	putRequest := httptest.NewRequest(http.MethodPut, "/v2/team-read/app/manifests/v1", bytes.NewReader(manifest))
	putRequest.Header.Set("Authorization", "Bearer "+adminToken)
	putRequest.Header.Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
	handler.ServeHTTP(putManifest, putRequest)
	if putManifest.Code != http.StatusCreated {
		t.Fatalf("expected admin manifest push 201, got %d: %s", putManifest.Code, putManifest.Body.String())
	}

	readerPullToken := requestToken(t, handler, "reader", "reader-secret", "repository:team-read/app:pull")
	tags := authenticatedRequest(handler, http.MethodGet, "/v2/team-read/app/tags/list", readerPullToken, nil)
	if tags.Code != http.StatusOK {
		t.Fatalf("expected reader tags list 200, got %d: %s", tags.Code, tags.Body.String())
	}
	if !strings.Contains(tags.Body.String(), "v1") {
		t.Fatalf("expected reader tags list to include v1, got %s", tags.Body.String())
	}
	getManifest := authenticatedRequest(handler, http.MethodGet, "/v2/team-read/app/manifests/v1", readerPullToken, nil)
	if getManifest.Code != http.StatusOK {
		t.Fatalf("expected reader manifest pull 200, got %d: %s", getManifest.Code, getManifest.Body.String())
	}
	deleteAttempt := authenticatedRequest(handler, http.MethodDelete, "/v2/team-read/app/manifests/v1", readerPullToken, nil)
	if deleteAttempt.Code != http.StatusUnauthorized {
		t.Fatalf("expected pull-only reader delete 401, got %d: %s", deleteAttempt.Code, deleteAttempt.Body.String())
	}
	catalogAttempt := authenticatedRequest(handler, http.MethodGet, "/v2/_catalog", readerPullToken, nil)
	if catalogAttempt.Code != http.StatusUnauthorized {
		t.Fatalf("expected reader catalog request 401, got %d: %s", catalogAttempt.Code, catalogAttempt.Body.String())
	}

	readerPushToken := requestToken(t, handler, "reader", "reader-secret", "repository:team-read/app:push")
	pushAttempt := authenticatedRequest(handler, http.MethodPost, "/v2/team-read/app/blobs/uploads/", readerPushToken, nil)
	if pushAttempt.Code != http.StatusUnauthorized {
		t.Fatalf("expected pull-only reader push 401, got %d: %s", pushAttempt.Code, pushAttempt.Body.String())
	}

	readerAPIToken := requestToken(t, handler, "reader", "reader-secret", "")
	adminAPI := authenticatedRequest(handler, http.MethodGet, "/api/users", readerAPIToken, nil)
	if adminAPI.Code != http.StatusUnauthorized {
		t.Fatalf("expected reader admin API request 401, got %d: %s", adminAPI.Code, adminAPI.Body.String())
	}
}

func TestOCIConformanceProtocolEdges(t *testing.T) {
	ctx := context.Background()
	cfg := config.Default()
	cfg.Storage.RootDirectory = filepath.Join(t.TempDir(), "registry")
	cfg.Database.DSN = filepath.Join(t.TempDir(), "test.db")
	store, err := db.Open(ctx, cfg.Database.DSN)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.InitSchema(ctx); err != nil {
		t.Fatalf("InitSchema() error = %v", err)
	}
	if err := store.EnsureActiveSigningKey(ctx); err != nil {
		t.Fatalf("EnsureActiveSigningKey() error = %v", err)
	}
	createHTTPTestUser(t, ctx, store, "admin", "Admin", domain.RoleAdmin, "admin-secret", time.Now().UTC())

	handler := New(Options{Config: cfg, Store: store})
	token := requestToken(t, handler, "admin", "admin-secret", "repository:edge/app:pull,push,delete")

	blob := []byte("0123456789")
	blobDigest := sha256Digest(blob)
	postBlob := httptest.NewRecorder()
	postBlobRequest := httptest.NewRequest(http.MethodPost, "/v2/edge/app/blobs/uploads/?digest="+blobDigest, bytes.NewReader(blob))
	postBlobRequest.Header.Set("Authorization", "Bearer "+token)
	postBlobRequest.Header.Set("Content-Type", "application/octet-stream")
	handler.ServeHTTP(postBlob, postBlobRequest)
	if postBlob.Code != http.StatusCreated {
		t.Fatalf("expected monolithic blob upload 201, got %d: %s", postBlob.Code, postBlob.Body.String())
	}

	rangeRequest := httptest.NewRequest(http.MethodGet, "/v2/edge/app/blobs/"+blobDigest, nil)
	rangeRequest.Header.Set("Authorization", "Bearer "+token)
	rangeRequest.Header.Set("Range", "bytes=2-5")
	rangeResponse := httptest.NewRecorder()
	handler.ServeHTTP(rangeResponse, rangeRequest)
	if rangeResponse.Code != http.StatusPartialContent || rangeResponse.Body.String() != "2345" {
		t.Fatalf("expected ranged blob response 206 with 2345, got %d %q", rangeResponse.Code, rangeResponse.Body.String())
	}

	deleteBlob := authenticatedRequest(handler, http.MethodDelete, "/v2/edge/app/blobs/"+blobDigest, token, nil)
	if deleteBlob.Code != http.StatusAccepted {
		t.Fatalf("expected blob delete 202, got %d: %s", deleteBlob.Code, deleteBlob.Body.String())
	}
	missingBlob := authenticatedRequest(handler, http.MethodHead, "/v2/edge/app/blobs/"+blobDigest, token, nil)
	if missingBlob.Code != http.StatusNotFound {
		t.Fatalf("expected deleted blob HEAD 404, got %d", missingBlob.Code)
	}

	start := authenticatedRequest(handler, http.MethodPost, "/v2/edge/app/blobs/uploads/", token, nil)
	if start.Code != http.StatusAccepted {
		t.Fatalf("expected upload start 202, got %d: %s", start.Code, start.Body.String())
	}
	outOfOrder := httptest.NewRecorder()
	outOfOrderRequest := httptest.NewRequest(http.MethodPatch, start.Header().Get("Location"), strings.NewReader("bad"))
	outOfOrderRequest.Header.Set("Authorization", "Bearer "+token)
	outOfOrderRequest.Header.Set("Content-Range", "3-5")
	handler.ServeHTTP(outOfOrder, outOfOrderRequest)
	if outOfOrder.Code != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("expected out-of-order upload 416, got %d: %s", outOfOrder.Code, outOfOrder.Body.String())
	}
	uploadStatus := authenticatedRequest(handler, http.MethodGet, start.Header().Get("Location"), token, nil)
	if uploadStatus.Code != http.StatusNoContent || uploadStatus.Header().Get("Range") != "0-0" {
		t.Fatalf("expected upload status 204 with empty range, got %d range=%q", uploadStatus.Code, uploadStatus.Header().Get("Range"))
	}
	outOfOrderPut := httptest.NewRecorder()
	outOfOrderPutRequest := httptest.NewRequest(http.MethodPut, start.Header().Get("Location")+"?digest="+sha256Digest([]byte("bad")), strings.NewReader("bad"))
	outOfOrderPutRequest.Header.Set("Authorization", "Bearer "+token)
	outOfOrderPutRequest.Header.Set("Content-Range", "3-5")
	handler.ServeHTTP(outOfOrderPut, outOfOrderPutRequest)
	if outOfOrderPut.Code != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("expected out-of-order final upload 416, got %d: %s", outOfOrderPut.Code, outOfOrderPut.Body.String())
	}

	manifest := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","size":0},"layers":[]}`)
	manifestDigest := sha512Digest(manifest)
	putManifest := httptest.NewRecorder()
	putManifestRequest := httptest.NewRequest(http.MethodPut, "/v2/edge/app/manifests/"+manifestDigest+"?tag=image", bytes.NewReader(manifest))
	putManifestRequest.Header.Set("Authorization", "Bearer "+token)
	putManifestRequest.Header.Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
	handler.ServeHTTP(putManifest, putManifestRequest)
	if putManifest.Code != http.StatusCreated || putManifest.Header().Get("Docker-Content-Digest") != manifestDigest {
		t.Fatalf("expected sha512 manifest push 201 with digest, got %d digest=%q body=%s", putManifest.Code, putManifest.Header().Get("Docker-Content-Digest"), putManifest.Body.String())
	}
	if putManifest.Header().Get("OCI-Tag") != "image" {
		t.Fatalf("expected OCI-Tag image, got %q", putManifest.Header().Get("OCI-Tag"))
	}
	getManifest := authenticatedRequest(handler, http.MethodGet, "/v2/edge/app/manifests/"+manifestDigest, token, nil)
	if getManifest.Code != http.StatusOK || getManifest.Body.String() != string(manifest) {
		t.Fatalf("expected sha512 manifest pull by digest, got %d: %s", getManifest.Code, getManifest.Body.String())
	}
	badManifest := httptest.NewRecorder()
	badManifestRequest := httptest.NewRequest(http.MethodPut, "/v2/edge/app/manifests/sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", bytes.NewReader(manifest))
	badManifestRequest.Header.Set("Authorization", "Bearer "+token)
	badManifestRequest.Header.Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
	handler.ServeHTTP(badManifest, badManifestRequest)
	if badManifest.Code != http.StatusBadRequest {
		t.Fatalf("expected mismatched manifest digest 400, got %d: %s", badManifest.Code, badManifest.Body.String())
	}

	subjectManifest := []byte(`{"schemaVersion":2}`)
	putSubject := httptest.NewRecorder()
	putSubjectRequest := httptest.NewRequest(http.MethodPut, "/v2/edge/app/manifests/index", bytes.NewReader(subjectManifest))
	putSubjectRequest.Header.Set("Authorization", "Bearer "+token)
	putSubjectRequest.Header.Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
	handler.ServeHTTP(putSubject, putSubjectRequest)
	if putSubject.Code != http.StatusCreated {
		t.Fatalf("expected subject manifest push 201, got %d: %s", putSubject.Code, putSubject.Body.String())
	}
	subjectDigest := putSubject.Header().Get("Docker-Content-Digest")
	artifact := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","artifactType":"application/vnd.example.test","config":{"mediaType":"application/vnd.example.config","digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","size":0},"layers":[],"subject":{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"%s","size":%d}}`, subjectDigest, len(subjectManifest)))
	artifactDigest := sha256Digest(artifact)
	putArtifact := httptest.NewRecorder()
	putArtifactRequest := httptest.NewRequest(http.MethodPut, "/v2/edge/app/manifests/"+artifactDigest, bytes.NewReader(artifact))
	putArtifactRequest.Header.Set("Authorization", "Bearer "+token)
	putArtifactRequest.Header.Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
	handler.ServeHTTP(putArtifact, putArtifactRequest)
	if putArtifact.Code != http.StatusCreated {
		t.Fatalf("expected artifact push 201, got %d: %s", putArtifact.Code, putArtifact.Body.String())
	}
	if putArtifact.Header().Get("OCI-Subject") != subjectDigest {
		t.Fatalf("expected OCI-Subject %q, got %q", subjectDigest, putArtifact.Header().Get("OCI-Subject"))
	}
	referrers := authenticatedRequest(handler, http.MethodGet, "/v2/edge/app/referrers/"+subjectDigest+"?artifactType=application/vnd.example.test", token, nil)
	if referrers.Code != http.StatusOK || !strings.Contains(referrers.Body.String(), artifactDigest) || referrers.Header().Get("OCI-Filters-Applied") != "artifactType" {
		t.Fatalf("expected filtered referrers response with artifact digest, got status=%d filters=%q body=%s", referrers.Code, referrers.Header().Get("OCI-Filters-Applied"), referrers.Body.String())
	}

	tags := authenticatedRequest(handler, http.MethodGet, "/v2/edge/app/tags/list?last=image", token, nil)
	if tags.Code != http.StatusOK {
		t.Fatalf("expected paged tags 200, got %d: %s", tags.Code, tags.Body.String())
	}
	if strings.Contains(tags.Body.String(), "image") || !strings.Contains(tags.Body.String(), "index") {
		t.Fatalf("expected tags pagination to exclude last=image and include index, got %s", tags.Body.String())
	}
}

func TestUILoginAndDashboard(t *testing.T) {
	ctx := context.Background()
	cfg := config.Default()
	cfg.Storage.RootDirectory = filepath.Join(t.TempDir(), "registry")
	cfg.Database.DSN = filepath.Join(t.TempDir(), "test.db")
	store, err := db.Open(ctx, cfg.Database.DSN)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.InitSchema(ctx); err != nil {
		t.Fatalf("InitSchema() error = %v", err)
	}
	if err := store.EnsureActiveSigningKey(ctx); err != nil {
		t.Fatalf("EnsureActiveSigningKey() error = %v", err)
	}
	if err := auth.BootstrapAdmin(ctx, store, "admin", "secret", time.Now().UTC()); err != nil {
		t.Fatalf("BootstrapAdmin() error = %v", err)
	}
	handler := New(Options{Config: cfg, Store: store})

	loginForm := url.Values{}
	loginForm.Set("username", "admin")
	loginForm.Set("password", "secret")
	loginRequest := httptest.NewRequest(http.MethodPost, "/ui/login", strings.NewReader(loginForm.Encode()))
	loginRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginResponse := httptest.NewRecorder()
	handler.ServeHTTP(loginResponse, loginRequest)
	if loginResponse.Code != http.StatusFound {
		t.Fatalf("expected login redirect, got %d: %s", loginResponse.Code, loginResponse.Body.String())
	}
	if len(loginResponse.Result().Cookies()) == 0 {
		t.Fatal("expected session cookie")
	}
	sessionCookie := loginResponse.Result().Cookies()[0]
	if !sessionCookie.Secure || !sessionCookie.HttpOnly || sessionCookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("expected secure HttpOnly SameSite=Lax session cookie, got %#v", sessionCookie)
	}

	logoutRequest := httptest.NewRequest(http.MethodPost, "/ui/logout", nil)
	logoutRequest.AddCookie(sessionCookie)
	logoutResponse := httptest.NewRecorder()
	handler.ServeHTTP(logoutResponse, logoutRequest)
	if logoutResponse.Code != http.StatusFound {
		t.Fatalf("expected logout redirect, got %d: %s", logoutResponse.Code, logoutResponse.Body.String())
	}
	if len(logoutResponse.Result().Cookies()) == 0 {
		t.Fatal("expected logout clearing cookie")
	}
	clearedCookie := logoutResponse.Result().Cookies()[0]
	if !clearedCookie.Secure || !clearedCookie.HttpOnly || clearedCookie.SameSite != http.SameSiteLaxMode || clearedCookie.MaxAge != -1 {
		t.Fatalf("expected secure clearing cookie, got %#v", clearedCookie)
	}

	dashboardRequest := httptest.NewRequest(http.MethodGet, "/ui", nil)
	dashboardRequest.AddCookie(sessionCookie)
	dashboardResponse := httptest.NewRecorder()
	handler.ServeHTTP(dashboardResponse, dashboardRequest)
	if dashboardResponse.Code != http.StatusOK {
		t.Fatalf("expected dashboard 200, got %d: %s", dashboardResponse.Code, dashboardResponse.Body.String())
	}
	if !strings.Contains(dashboardResponse.Body.String(), "Dashboard") || !strings.Contains(dashboardResponse.Body.String(), "Repositories") {
		t.Fatalf("expected dashboard html, got %s", dashboardResponse.Body.String())
	}
	if !strings.Contains(dashboardResponse.Body.String(), "No registry traffic yet") {
		t.Fatalf("expected dashboard empty traffic state, got %s", dashboardResponse.Body.String())
	}
	if strings.Contains(dashboardResponse.Body.String(), "Search users, repositories, logs") {
		t.Fatal("expected topbar search to be removed")
	}

	settingsRequest := httptest.NewRequest(http.MethodGet, "/ui/settings", nil)
	settingsRequest.AddCookie(sessionCookie)
	settingsResponse := httptest.NewRecorder()
	handler.ServeHTTP(settingsResponse, settingsRequest)
	if settingsResponse.Code != http.StatusOK {
		t.Fatalf("expected settings page 200, got %d: %s", settingsResponse.Code, settingsResponse.Body.String())
	}
	if !strings.Contains(settingsResponse.Body.String(), "Garbage Collection") || !strings.Contains(settingsResponse.Body.String(), "Delete untagged manifests after") {
		t.Fatalf("expected GC settings form, got %s", settingsResponse.Body.String())
	}
	if !strings.Contains(settingsResponse.Body.String(), "Registry Webhook") || !strings.Contains(settingsResponse.Body.String(), "https://example.com/scr-events") {
		t.Fatalf("expected registry webhook settings form, got %s", settingsResponse.Body.String())
	}
	settingsForm := url.Values{}
	settingsForm.Set("enabled", "on")
	settingsForm.Set("delay", "30m")
	settingsForm.Set("interval", "2h")
	settingsUpdateRequest := httptest.NewRequest(http.MethodPost, "/ui/settings/gc", strings.NewReader(settingsForm.Encode()))
	settingsUpdateRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	settingsUpdateRequest.AddCookie(sessionCookie)
	settingsUpdateResponse := httptest.NewRecorder()
	handler.ServeHTTP(settingsUpdateResponse, settingsUpdateRequest)
	if settingsUpdateResponse.Code != http.StatusFound {
		t.Fatalf("expected settings update redirect, got %d: %s", settingsUpdateResponse.Code, settingsUpdateResponse.Body.String())
	}
	gcSettings, err := store.GCSettings(ctx, domain.GCSettings{})
	if err != nil {
		t.Fatalf("GCSettings() error = %v", err)
	}
	if !gcSettings.Enabled || gcSettings.Delay != 30*time.Minute || gcSettings.Interval != 2*time.Hour {
		t.Fatalf("unexpected persisted gc settings: %#v", gcSettings)
	}
	webhookForm := url.Values{}
	webhookForm.Set("url", "https://example.com/scr-events")
	webhookUpdateRequest := httptest.NewRequest(http.MethodPost, "/ui/settings/webhook", strings.NewReader(webhookForm.Encode()))
	webhookUpdateRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	webhookUpdateRequest.AddCookie(sessionCookie)
	webhookUpdateResponse := httptest.NewRecorder()
	handler.ServeHTTP(webhookUpdateResponse, webhookUpdateRequest)
	if webhookUpdateResponse.Code != http.StatusFound {
		t.Fatalf("expected webhook settings update redirect, got %d: %s", webhookUpdateResponse.Code, webhookUpdateResponse.Body.String())
	}
	webhookSettings, err := store.RegistryWebhookSettings(ctx)
	if err != nil {
		t.Fatalf("RegistryWebhookSettings() error = %v", err)
	}
	if webhookSettings.URL != "https://example.com/scr-events" {
		t.Fatalf("unexpected persisted registry webhook settings: %#v", webhookSettings)
	}
	if err := store.UpdateRegistryWebhookSettings(ctx, domain.RegistryWebhookSettings{}, time.Now().UTC()); err != nil {
		t.Fatalf("UpdateRegistryWebhookSettings(clear) error = %v", err)
	}

	adminRegistryToken := requestToken(t, handler, "admin", "secret", "repository:ui/app:pull,push,delete")
	uiManifest := []byte(`{"schemaVersion":2}`)
	for _, tag := range []string{"latest", "stable"} {
		putManifest := httptest.NewRecorder()
		putRequest := httptest.NewRequest(http.MethodPut, "/v2/ui/app/manifests/"+tag, bytes.NewReader(uiManifest))
		putRequest.Header.Set("Authorization", "Bearer "+adminRegistryToken)
		putRequest.Header.Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
		handler.ServeHTTP(putManifest, putRequest)
		if putManifest.Code != http.StatusCreated {
			t.Fatalf("expected UI fixture manifest push 201, got %d: %s", putManifest.Code, putManifest.Body.String())
		}
	}
	trafficRequest := httptest.NewRequest(http.MethodGet, "/ui?repository="+url.QueryEscape("ui/app"), nil)
	trafficRequest.AddCookie(sessionCookie)
	trafficResponse := httptest.NewRecorder()
	handler.ServeHTTP(trafficResponse, trafficRequest)
	if trafficResponse.Code != http.StatusOK {
		t.Fatalf("expected filtered dashboard 200, got %d: %s", trafficResponse.Code, trafficResponse.Body.String())
	}
	if !strings.Contains(trafficResponse.Body.String(), `<optgroup label="ui">`) || !strings.Contains(trafficResponse.Body.String(), `<option value="ui/app" selected>app</option>`) {
		t.Fatalf("expected traffic repository dropdown grouped by prefix, got %s", trafficResponse.Body.String())
	}
	if !strings.Contains(trafficResponse.Body.String(), "Repository: ui/app") || !strings.Contains(trafficResponse.Body.String(), "2 pushes") {
		t.Fatalf("expected filtered dashboard traffic for ui/app, got %s", trafficResponse.Body.String())
	}
	repositoriesRequest := httptest.NewRequest(http.MethodGet, "/ui/repositories", nil)
	repositoriesRequest.AddCookie(sessionCookie)
	repositoriesResponse := httptest.NewRecorder()
	handler.ServeHTTP(repositoriesResponse, repositoriesRequest)
	if repositoriesResponse.Code != http.StatusOK {
		t.Fatalf("expected repositories UI 200, got %d: %s", repositoriesResponse.Code, repositoriesResponse.Body.String())
	}
	if !strings.Contains(repositoriesResponse.Body.String(), "ui/app") || !strings.Contains(repositoriesResponse.Body.String(), "latest") || !strings.Contains(repositoriesResponse.Body.String(), "stable") {
		t.Fatalf("expected repositories UI to show pushed tags, got %s", repositoriesResponse.Body.String())
	}
	if !strings.Contains(repositoriesResponse.Body.String(), "Search repositories, namespaces, tags, or digests") || !strings.Contains(repositoriesResponse.Body.String(), "Delete image repository") {
		t.Fatalf("expected repositories UI search and clear delete copy, got %s", repositoriesResponse.Body.String())
	}
	if !strings.Contains(repositoriesResponse.Body.String(), "Browse pushed images, inspect tags, and remove stale image references") || !strings.Contains(repositoriesResponse.Body.String(), "This removes all tag references and tagged manifests for this exact image repository only") {
		t.Fatalf("expected repository delete confirmation copy, got %s", repositoriesResponse.Body.String())
	}
	if !strings.Contains(repositoriesResponse.Body.String(), "Digest") || !strings.Contains(repositoriesResponse.Body.String(), "Media Type") || !strings.Contains(repositoriesResponse.Body.String(), "Pushed") {
		t.Fatalf("expected tag metadata table, got %s", repositoriesResponse.Body.String())
	}
	if strings.Index(repositoriesResponse.Body.String(), "stable") > strings.Index(repositoriesResponse.Body.String(), "latest") {
		t.Fatalf("expected newest pushed tag to render before older tag, got %s", repositoriesResponse.Body.String())
	}
	if !strings.Contains(repositoriesResponse.Body.String(), "Deleting a tag removes only that tag reference") || !strings.Contains(repositoriesResponse.Body.String(), "It does not delete the manifest content") {
		t.Fatalf("expected tag delete semantics copy, got %s", repositoriesResponse.Body.String())
	}
	searchRequest := httptest.NewRequest(http.MethodGet, "/ui/repositories?q=stable", nil)
	searchRequest.AddCookie(sessionCookie)
	searchResponse := httptest.NewRecorder()
	handler.ServeHTTP(searchResponse, searchRequest)
	if searchResponse.Code != http.StatusOK {
		t.Fatalf("expected repository search 200, got %d: %s", searchResponse.Code, searchResponse.Body.String())
	}
	if !strings.Contains(searchResponse.Body.String(), `value="stable"`) || !strings.Contains(searchResponse.Body.String(), "ui/app") {
		t.Fatalf("expected repository search to preserve query and return tag match, got %s", searchResponse.Body.String())
	}
	missingSearchRequest := httptest.NewRequest(http.MethodGet, "/ui/repositories?q=no-such-tag", nil)
	missingSearchRequest.AddCookie(sessionCookie)
	missingSearchResponse := httptest.NewRecorder()
	handler.ServeHTTP(missingSearchResponse, missingSearchRequest)
	if missingSearchResponse.Code != http.StatusOK {
		t.Fatalf("expected empty repository search 200, got %d: %s", missingSearchResponse.Code, missingSearchResponse.Body.String())
	}
	if !strings.Contains(missingSearchResponse.Body.String(), "No repositories match this search") {
		t.Fatalf("expected empty repository search state, got %s", missingSearchResponse.Body.String())
	}

	deleteTagForm := url.Values{}
	deleteTagForm.Set("repository", "ui/app")
	deleteTagForm.Set("tag", "latest")
	deleteTagRequest := httptest.NewRequest(http.MethodPost, "/ui/repositories/delete-tag", strings.NewReader(deleteTagForm.Encode()))
	deleteTagRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	deleteTagRequest.AddCookie(sessionCookie)
	deleteTagResponse := httptest.NewRecorder()
	handler.ServeHTTP(deleteTagResponse, deleteTagRequest)
	if deleteTagResponse.Code != http.StatusFound {
		t.Fatalf("expected delete tag redirect, got %d: %s", deleteTagResponse.Code, deleteTagResponse.Body.String())
	}
	latestAfterDelete := authenticatedRequest(handler, http.MethodGet, "/v2/ui/app/manifests/latest", adminRegistryToken, nil)
	if latestAfterDelete.Code != http.StatusNotFound {
		t.Fatalf("expected deleted latest tag to be missing, got %d: %s", latestAfterDelete.Code, latestAfterDelete.Body.String())
	}
	stableAfterDelete := authenticatedRequest(handler, http.MethodGet, "/v2/ui/app/manifests/stable", adminRegistryToken, nil)
	if stableAfterDelete.Code != http.StatusOK {
		t.Fatalf("expected stable tag to remain, got %d: %s", stableAfterDelete.Code, stableAfterDelete.Body.String())
	}

	deleteRepositoryForm := url.Values{}
	deleteRepositoryForm.Set("repository", "ui/app")
	deleteRepositoryRequest := httptest.NewRequest(http.MethodPost, "/ui/repositories/delete", strings.NewReader(deleteRepositoryForm.Encode()))
	deleteRepositoryRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	deleteRepositoryRequest.AddCookie(sessionCookie)
	deleteRepositoryResponse := httptest.NewRecorder()
	handler.ServeHTTP(deleteRepositoryResponse, deleteRepositoryRequest)
	if deleteRepositoryResponse.Code != http.StatusFound {
		t.Fatalf("expected delete repository redirect, got %d: %s", deleteRepositoryResponse.Code, deleteRepositoryResponse.Body.String())
	}
	if _, err := store.GetRepository(ctx, "ui/app"); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("expected deleted repository to be removed, got err=%v", err)
	}

	createUserForm := url.Values{}
	createUserForm.Set("username", "ui-reader")
	createUserForm.Set("displayName", "UI Reader")
	createUserForm.Set("role", "reader")
	createUserForm.Set("notBefore", "2026-08-01")
	createUserForm.Set("expiresAt", "2026-08-02")
	createUserRequest := httptest.NewRequest(http.MethodPost, "/ui/users", strings.NewReader(createUserForm.Encode()))
	createUserRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	createUserRequest.AddCookie(sessionCookie)
	createUserResponse := httptest.NewRecorder()
	handler.ServeHTTP(createUserResponse, createUserRequest)
	if createUserResponse.Code != http.StatusOK {
		t.Fatalf("expected create user response 200, got %d: %s", createUserResponse.Code, createUserResponse.Body.String())
	}
	if !strings.Contains(createUserResponse.Body.String(), "User created: ui-reader") || !strings.Contains(createUserResponse.Body.String(), "Copy this secret now") || !strings.Contains(createUserResponse.Body.String(), "content_copy") || !strings.Contains(createUserResponse.Body.String(), `aria-label="Copy secret"`) || !strings.Contains(createUserResponse.Body.String(), "data-copy-status") {
		t.Fatalf("expected one-time user secret after creating user, got %s", createUserResponse.Body.String())
	}

	usersRequest := httptest.NewRequest(http.MethodGet, "/ui/users", nil)
	usersRequest.AddCookie(sessionCookie)
	usersResponse := httptest.NewRecorder()
	handler.ServeHTTP(usersResponse, usersRequest)
	if usersResponse.Code != http.StatusOK {
		t.Fatalf("expected users page 200, got %d: %s", usersResponse.Code, usersResponse.Body.String())
	}
	if !strings.Contains(usersResponse.Body.String(), "ui-reader") {
		t.Fatalf("expected created user in users page, got %s", usersResponse.Body.String())
	}
	if strings.Contains(usersResponse.Body.String(), "<strong>admin</strong>") || strings.Contains(usersResponse.Body.String(), `<option value="admin">`) {
		t.Fatalf("expected admin account and admin role option to be hidden from users UI, got %s", usersResponse.Body.String())
	}
	createdUser, err := store.GetUserByUsername(ctx, "ui-reader")
	if err != nil {
		t.Fatalf("GetUserByUsername(ui-reader) error = %v", err)
	}
	grants, err := store.ListGrantsByUser(ctx, createdUser.ID)
	if err != nil {
		t.Fatalf("ListGrantsByUser(ui-reader) error = %v", err)
	}
	if len(grants) != 1 || grants[0].RepositoryPrefix != "*" || !slices.Contains(grants[0].Actions, domain.ActionPull) {
		t.Fatalf("expected default wildcard pull grant, got %#v", grants)
	}
	usersWithGrantRequest := httptest.NewRequest(http.MethodGet, "/ui/users", nil)
	usersWithGrantRequest.AddCookie(sessionCookie)
	usersWithGrantResponse := httptest.NewRecorder()
	handler.ServeHTTP(usersWithGrantResponse, usersWithGrantRequest)
	if usersWithGrantResponse.Code != http.StatusOK {
		t.Fatalf("expected users page with grant 200, got %d: %s", usersWithGrantResponse.Code, usersWithGrantResponse.Body.String())
	}
	if !strings.Contains(usersWithGrantResponse.Body.String(), `value="*"`) || !strings.Contains(usersWithGrantResponse.Body.String(), "Use * for all repositories") || strings.Contains(usersWithGrantResponse.Body.String(), "Add Grant") {
		t.Fatalf("expected users page to show single grant editor, got %s", usersWithGrantResponse.Body.String())
	}
	if !strings.Contains(usersWithGrantResponse.Body.String(), "Delete user ui-reader?") || !strings.Contains(usersWithGrantResponse.Body.String(), "their repository access grant") {
		t.Fatalf("expected user delete confirmation copy, got %s", usersWithGrantResponse.Body.String())
	}
	if createdUser.NotBefore == nil || createdUser.NotBefore.Format(time.RFC3339) != "2026-08-01T00:00:00Z" {
		t.Fatalf("expected date-only notBefore at midnight UTC, got %v", createdUser.NotBefore)
	}
	if createdUser.ExpiresAt == nil || createdUser.ExpiresAt.Format(time.RFC3339) != "2026-08-02T00:00:00Z" {
		t.Fatalf("expected date-only expiresAt at midnight UTC, got %v", createdUser.ExpiresAt)
	}
	validityForm := url.Values{}
	validityForm.Set("expiresAt", "2026-09-02")
	validityForm.Set("repositoryPrefix", "team/")
	validityForm.Add("actions", "pull")
	validityForm.Add("actions", "push")
	validityRequest := httptest.NewRequest(http.MethodPost, "/ui/users/"+createdUser.ID+"/access", strings.NewReader(validityForm.Encode()))
	validityRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	validityRequest.AddCookie(sessionCookie)
	validityResponse := httptest.NewRecorder()
	handler.ServeHTTP(validityResponse, validityRequest)
	if validityResponse.Code != http.StatusFound {
		t.Fatalf("expected validity update redirect, got %d: %s", validityResponse.Code, validityResponse.Body.String())
	}
	updatedUser, err := store.GetUser(ctx, createdUser.ID)
	if err != nil {
		t.Fatalf("GetUser(updated ui-reader) error = %v", err)
	}
	if updatedUser.ExpiresAt == nil || updatedUser.ExpiresAt.Format(time.RFC3339) != "2026-09-02T00:00:00Z" {
		t.Fatalf("expected updated date-only expiry at midnight UTC, got %v", updatedUser.ExpiresAt)
	}
	grants, err = store.ListGrantsByUser(ctx, createdUser.ID)
	if err != nil {
		t.Fatalf("ListGrantsByUser(after save access) error = %v", err)
	}
	if len(grants) != 1 || grants[0].RepositoryPrefix != "team/" || !slices.Contains(grants[0].Actions, domain.ActionPull) || !slices.Contains(grants[0].Actions, domain.ActionPush) {
		t.Fatalf("expected saved single pull/push grant, got %#v", grants)
	}
	adminUser, err := store.GetUserByUsername(ctx, "admin")
	if err != nil {
		t.Fatalf("GetUserByUsername(admin) error = %v", err)
	}
	adminValidityRequest := httptest.NewRequest(http.MethodPost, "/ui/users/"+adminUser.ID+"/access", strings.NewReader(validityForm.Encode()))
	adminValidityRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	adminValidityRequest.AddCookie(sessionCookie)
	adminValidityResponse := httptest.NewRecorder()
	handler.ServeHTTP(adminValidityResponse, adminValidityRequest)
	if adminValidityResponse.Code != http.StatusOK || !strings.Contains(adminValidityResponse.Body.String(), "Admin users are managed outside this user list") {
		t.Fatalf("expected admin user validity edit to be blocked, got %d: %s", adminValidityResponse.Code, adminValidityResponse.Body.String())
	}

	deleteUser := createHTTPTestUser(t, ctx, store, "delete-me", "Delete Me", domain.RoleReader, "delete-secret", time.Now().UTC())
	deleteRequest := httptest.NewRequest(http.MethodPost, "/ui/users/"+deleteUser.ID+"/delete", nil)
	deleteRequest.AddCookie(sessionCookie)
	deleteResponse := httptest.NewRecorder()
	handler.ServeHTTP(deleteResponse, deleteRequest)
	if deleteResponse.Code != http.StatusFound {
		t.Fatalf("expected delete redirect, got %d: %s", deleteResponse.Code, deleteResponse.Body.String())
	}
	if _, err := store.GetUser(ctx, deleteUser.ID); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("expected deleted user to be removed, got err=%v", err)
	}

	auditRequest := httptest.NewRequest(http.MethodGet, "/ui/audit", nil)
	auditRequest.AddCookie(sessionCookie)
	auditResponse := httptest.NewRecorder()
	handler.ServeHTTP(auditResponse, auditRequest)
	if auditResponse.Code != http.StatusOK {
		t.Fatalf("expected audit page 200, got %d: %s", auditResponse.Code, auditResponse.Body.String())
	}
	if !strings.Contains(auditResponse.Body.String(), "ui-reader") {
		t.Fatalf("expected audit page to resolve user id to username, got %s", auditResponse.Body.String())
	}
	if !strings.Contains(auditResponse.Body.String(), "Filter by action, user, target, result, IP, or user agent") {
		t.Fatalf("expected real audit filter controls, got %s", auditResponse.Body.String())
	}

	auditSearchRequest := httptest.NewRequest(http.MethodGet, "/ui/audit?q=ui-reader", nil)
	auditSearchRequest.AddCookie(sessionCookie)
	auditSearchResponse := httptest.NewRecorder()
	handler.ServeHTTP(auditSearchResponse, auditSearchRequest)
	if auditSearchResponse.Code != http.StatusOK {
		t.Fatalf("expected audit search 200, got %d: %s", auditSearchResponse.Code, auditSearchResponse.Body.String())
	}
	if !strings.Contains(auditSearchResponse.Body.String(), `value="ui-reader"`) || !strings.Contains(auditSearchResponse.Body.String(), "ui-reader") {
		t.Fatalf("expected audit search to preserve query and match user, got %s", auditSearchResponse.Body.String())
	}

	authFilterRequest := httptest.NewRequest(http.MethodGet, "/ui/audit?action=authentication", nil)
	authFilterRequest.AddCookie(sessionCookie)
	authFilterResponse := httptest.NewRecorder()
	handler.ServeHTTP(authFilterResponse, authFilterRequest)
	if authFilterResponse.Code != http.StatusOK {
		t.Fatalf("expected audit auth filter 200, got %d: %s", authFilterResponse.Code, authFilterResponse.Body.String())
	}
	if !strings.Contains(authFilterResponse.Body.String(), "selected>Authentication") || !strings.Contains(authFilterResponse.Body.String(), "ui.login") {
		t.Fatalf("expected authentication audit filter to be selected and include login events, got %s", authFilterResponse.Body.String())
	}

	emptyAuditRequest := httptest.NewRequest(http.MethodGet, "/ui/audit?q=no-such-audit-event", nil)
	emptyAuditRequest.AddCookie(sessionCookie)
	emptyAuditResponse := httptest.NewRecorder()
	handler.ServeHTTP(emptyAuditResponse, emptyAuditRequest)
	if emptyAuditResponse.Code != http.StatusOK {
		t.Fatalf("expected empty audit search 200, got %d: %s", emptyAuditResponse.Code, emptyAuditResponse.Body.String())
	}
	if !strings.Contains(emptyAuditResponse.Body.String(), "No audit events match this filter") {
		t.Fatalf("expected empty audit filter state, got %s", emptyAuditResponse.Body.String())
	}
}

func TestRegistryWebhookReceivesRegistryAndUIDeleteEvents(t *testing.T) {
	ctx := context.Background()
	cfg := config.Default()
	cfg.Storage.RootDirectory = filepath.Join(t.TempDir(), "registry")
	cfg.Database.DSN = filepath.Join(t.TempDir(), "test.db")
	store, err := db.Open(ctx, cfg.Database.DSN)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.InitSchema(ctx); err != nil {
		t.Fatalf("InitSchema() error = %v", err)
	}
	if err := store.EnsureActiveSigningKey(ctx); err != nil {
		t.Fatalf("EnsureActiveSigningKey() error = %v", err)
	}
	if err := auth.BootstrapAdmin(ctx, store, "admin", "secret", time.Now().UTC()); err != nil {
		t.Fatalf("BootstrapAdmin() error = %v", err)
	}

	webhookEvents := make(chan registryWebhookPayload, 10)
	webhookServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected webhook POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("expected webhook json content type, got %q", r.Header.Get("Content-Type"))
		}
		var payload registryWebhookPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("Decode webhook payload error = %v", err)
		}
		webhookEvents <- payload
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(webhookServer.Close)
	if err := store.UpdateRegistryWebhookSettings(ctx, domain.RegistryWebhookSettings{URL: webhookServer.URL}, time.Now().UTC()); err != nil {
		t.Fatalf("UpdateRegistryWebhookSettings() error = %v", err)
	}

	handler := New(Options{Config: cfg, Store: store})
	token := requestToken(t, handler, "admin", "secret", "repository:webhook/app:pull,push,delete")
	manifest := []byte(`{"schemaVersion":2}`)
	putManifest := httptest.NewRecorder()
	putRequest := httptest.NewRequest(http.MethodPut, "/v2/webhook/app/manifests/latest", bytes.NewReader(manifest))
	putRequest.Header.Set("Authorization", "Bearer "+token)
	putRequest.Header.Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
	handler.ServeHTTP(putManifest, putRequest)
	if putManifest.Code != http.StatusCreated {
		t.Fatalf("expected manifest push 201, got %d: %s", putManifest.Code, putManifest.Body.String())
	}
	pushEvent := waitForWebhookEvent(t, webhookEvents, "registry.manifest.pushed")
	if pushEvent.Group != "registry.push" || pushEvent.TargetID != "webhook/app" || pushEvent.ID == "" {
		t.Fatalf("unexpected push webhook payload: %#v", pushEvent)
	}

	getManifest := authenticatedRequest(handler, http.MethodGet, "/v2/webhook/app/manifests/latest", token, nil)
	if getManifest.Code != http.StatusOK {
		t.Fatalf("expected manifest pull 200, got %d: %s", getManifest.Code, getManifest.Body.String())
	}
	pullEvent := waitForWebhookEvent(t, webhookEvents, "registry.manifest.pulled")
	if pullEvent.Group != "registry.pull" || pullEvent.TargetID != "webhook/app" {
		t.Fatalf("unexpected pull webhook payload: %#v", pullEvent)
	}

	loginForm := url.Values{}
	loginForm.Set("username", "admin")
	loginForm.Set("password", "secret")
	loginRequest := httptest.NewRequest(http.MethodPost, "/ui/login", strings.NewReader(loginForm.Encode()))
	loginRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginResponse := httptest.NewRecorder()
	handler.ServeHTTP(loginResponse, loginRequest)
	if loginResponse.Code != http.StatusFound || len(loginResponse.Result().Cookies()) == 0 {
		t.Fatalf("expected UI login redirect with cookie, got %d: %s", loginResponse.Code, loginResponse.Body.String())
	}
	deleteForm := url.Values{}
	deleteForm.Set("repository", "webhook/app")
	deleteRequest := httptest.NewRequest(http.MethodPost, "/ui/repositories/delete", strings.NewReader(deleteForm.Encode()))
	deleteRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	deleteRequest.AddCookie(loginResponse.Result().Cookies()[0])
	deleteResponse := httptest.NewRecorder()
	handler.ServeHTTP(deleteResponse, deleteRequest)
	if deleteResponse.Code != http.StatusFound {
		t.Fatalf("expected UI repository delete redirect, got %d: %s", deleteResponse.Code, deleteResponse.Body.String())
	}
	deleteEvent := waitForWebhookEvent(t, webhookEvents, "repository.deleted")
	if deleteEvent.Group != "registry.delete" || deleteEvent.TargetID != "webhook/app" {
		t.Fatalf("unexpected repository delete webhook payload: %#v", deleteEvent)
	}
}

func TestRegistryWebhookFailureDoesNotFailRegistryRequest(t *testing.T) {
	ctx := context.Background()
	cfg := config.Default()
	cfg.Storage.RootDirectory = filepath.Join(t.TempDir(), "registry")
	cfg.Database.DSN = filepath.Join(t.TempDir(), "test.db")
	store, err := db.Open(ctx, cfg.Database.DSN)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.InitSchema(ctx); err != nil {
		t.Fatalf("InitSchema() error = %v", err)
	}
	if err := store.EnsureActiveSigningKey(ctx); err != nil {
		t.Fatalf("EnsureActiveSigningKey() error = %v", err)
	}
	createHTTPTestUser(t, ctx, store, "admin", "Admin", domain.RoleAdmin, "secret", time.Now().UTC())

	var attempts atomic.Int32
	failingWebhookServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		writeError(w, http.StatusInternalServerError, "webhook down")
	}))
	t.Cleanup(failingWebhookServer.Close)
	if err := store.UpdateRegistryWebhookSettings(ctx, domain.RegistryWebhookSettings{URL: failingWebhookServer.URL}, time.Now().UTC()); err != nil {
		t.Fatalf("UpdateRegistryWebhookSettings() error = %v", err)
	}

	handler := New(Options{Config: cfg, Store: store})
	token := requestToken(t, handler, "admin", "secret", "repository:webhook-failure/app:push")
	putManifest := httptest.NewRecorder()
	putRequest := httptest.NewRequest(http.MethodPut, "/v2/webhook-failure/app/manifests/latest", bytes.NewReader([]byte(`{"schemaVersion":2}`)))
	putRequest.Header.Set("Authorization", "Bearer "+token)
	putRequest.Header.Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
	handler.ServeHTTP(putManifest, putRequest)
	if putManifest.Code != http.StatusCreated {
		t.Fatalf("expected manifest push to ignore webhook failure, got %d: %s", putManifest.Code, putManifest.Body.String())
	}
	waitForWebhookAttempt(t, &attempts)
}

func TestUILoginCanDisableSecureCookieForDirectHTTP(t *testing.T) {
	ctx := context.Background()
	cfg := config.Default()
	cfg.HTTP.SecureCookies = false
	cfg.Storage.RootDirectory = filepath.Join(t.TempDir(), "registry")
	cfg.Database.DSN = filepath.Join(t.TempDir(), "test.db")
	store, err := db.Open(ctx, cfg.Database.DSN)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.InitSchema(ctx); err != nil {
		t.Fatalf("InitSchema() error = %v", err)
	}
	if err := store.EnsureActiveSigningKey(ctx); err != nil {
		t.Fatalf("EnsureActiveSigningKey() error = %v", err)
	}
	if err := auth.BootstrapAdmin(ctx, store, "admin", "secret", time.Now().UTC()); err != nil {
		t.Fatalf("BootstrapAdmin() error = %v", err)
	}
	handler := New(Options{Config: cfg, Store: store})

	loginForm := url.Values{}
	loginForm.Set("username", "admin")
	loginForm.Set("password", "secret")
	loginRequest := httptest.NewRequest(http.MethodPost, "/ui/login", strings.NewReader(loginForm.Encode()))
	loginRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginResponse := httptest.NewRecorder()
	handler.ServeHTTP(loginResponse, loginRequest)
	if loginResponse.Code != http.StatusFound {
		t.Fatalf("expected login redirect, got %d: %s", loginResponse.Code, loginResponse.Body.String())
	}
	if len(loginResponse.Result().Cookies()) == 0 {
		t.Fatal("expected session cookie")
	}
	sessionCookie := loginResponse.Result().Cookies()[0]
	if sessionCookie.Secure || !sessionCookie.HttpOnly || sessionCookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("expected insecure opt-out to affect only Secure flag, got %#v", sessionCookie)
	}
}

func TestRootRedirectsToRegistryAPI(t *testing.T) {
	ctx := context.Background()
	cfg := config.Default()
	cfg.Storage.RootDirectory = filepath.Join(t.TempDir(), "registry")
	cfg.Database.DSN = filepath.Join(t.TempDir(), "test.db")
	store, err := db.Open(ctx, cfg.Database.DSN)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.InitSchema(ctx); err != nil {
		t.Fatalf("InitSchema() error = %v", err)
	}
	if err := store.EnsureActiveSigningKey(ctx); err != nil {
		t.Fatalf("EnsureActiveSigningKey() error = %v", err)
	}
	handler := New(Options{Config: cfg, Store: store})

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	if response.Code != http.StatusFound {
		t.Fatalf("expected root redirect, got %d", response.Code)
	}
	if response.Header().Get("Location") != "/v2/" {
		t.Fatalf("expected root to redirect to /v2/, got %q", response.Header().Get("Location"))
	}
}

func TestUIRoutesRedirectWithoutSession(t *testing.T) {
	ctx := context.Background()
	cfg := config.Default()
	cfg.Storage.RootDirectory = filepath.Join(t.TempDir(), "registry")
	cfg.Database.DSN = filepath.Join(t.TempDir(), "test.db")
	store, err := db.Open(ctx, cfg.Database.DSN)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.InitSchema(ctx); err != nil {
		t.Fatalf("InitSchema() error = %v", err)
	}
	if err := store.EnsureActiveSigningKey(ctx); err != nil {
		t.Fatalf("EnsureActiveSigningKey() error = %v", err)
	}
	handler := New(Options{Config: cfg, Store: store})

	uiResponse := httptest.NewRecorder()
	handler.ServeHTTP(uiResponse, httptest.NewRequest(http.MethodGet, "/ui", nil))
	if uiResponse.Code != http.StatusFound || uiResponse.Header().Get("Location") != "/ui/login" {
		t.Fatalf("expected /ui to redirect to login, got status=%d location=%q", uiResponse.Code, uiResponse.Header().Get("Location"))
	}

	trailingSlashResponse := httptest.NewRecorder()
	handler.ServeHTTP(trailingSlashResponse, httptest.NewRequest(http.MethodGet, "/ui/", nil))
	if trailingSlashResponse.Code != http.StatusFound || trailingSlashResponse.Header().Get("Location") != "/ui" {
		t.Fatalf("expected /ui/ to redirect to /ui, got status=%d location=%q", trailingSlashResponse.Code, trailingSlashResponse.Header().Get("Location"))
	}
}

func requestToken(t *testing.T, handler http.Handler, username, secret, scope string) string {
	t.Helper()
	path := "/token?service=scr"
	if scope != "" {
		path += "&scope=" + scope
	}
	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.SetBasicAuth(username, secret)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("expected token response 200, got %d: %s", response.Code, response.Body.String())
	}
	var payload struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("Decode token response error = %v", err)
	}
	if payload.Token == "" {
		t.Fatal("expected token")
	}
	return payload.Token
}

func createHTTPTestUser(t *testing.T, ctx context.Context, store *db.Store, username, displayName string, role domain.Role, secret string, now time.Time) domain.User {
	t.Helper()
	secretHash, err := auth.HashSecret(secret)
	if err != nil {
		t.Fatalf("HashSecret(%s) error = %v", username, err)
	}
	user, err := store.CreateUser(ctx, db.CreateUserParams{
		Username:    username,
		DisplayName: displayName,
		Role:        role,
		SecretHash:  secretHash,
	}, now)
	if err != nil {
		t.Fatalf("CreateUser(%s) error = %v", username, err)
	}
	return user
}

func authenticatedRequest(handler http.Handler, method, path, token string, body io.Reader) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, body)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func waitForWebhookEvent(t *testing.T, events <-chan registryWebhookPayload, event string) registryWebhookPayload {
	t.Helper()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	for {
		select {
		case payload := <-events:
			if payload.Event == event {
				return payload
			}
		case <-timer.C:
			t.Fatalf("timed out waiting for webhook event %q", event)
		}
	}
}

func waitForWebhookAttempt(t *testing.T, attempts *atomic.Int32) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if attempts.Load() > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for webhook attempt")
}

func sha256Digest(content []byte) string {
	sum := sha256.Sum256(content)
	return fmt.Sprintf("sha256:%x", sum[:])
}

func sha512Digest(content []byte) string {
	sum := sha512.Sum512(content)
	return fmt.Sprintf("sha512:%x", sum[:])
}
