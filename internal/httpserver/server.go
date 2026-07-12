package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"simplecontainerregistry/internal/auth"
	"simplecontainerregistry/internal/config"
	"simplecontainerregistry/internal/db"
	"simplecontainerregistry/internal/domain"
	"simplecontainerregistry/internal/ids"
	"simplecontainerregistry/internal/storage"
)

type Options struct {
	Config config.Config
	Store  *db.Store
	Logger *slog.Logger
}

type Server struct {
	cfg        config.Config
	store      *db.Store
	logger     *slog.Logger
	users      auth.UserService
	tokens     auth.TokenService
	registryFS storage.Filesystem
	webhooks   *registryWebhookDispatcher
	mux        *http.ServeMux
}

func New(opts Options) http.Handler {
	registryFS, err := storage.NewFilesystem(opts.Config.Storage.RootDirectory)
	if err != nil {
		panic(err)
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	server := &Server{
		cfg:        opts.Config,
		store:      opts.Store,
		logger:     logger,
		users:      auth.NewUserService(opts.Store),
		tokens:     auth.NewTokenService(opts.Store, opts.Config.Auth),
		registryFS: registryFS,
		webhooks:   newRegistryWebhookDispatcher(opts.Store, logger),
		mux:        http.NewServeMux(),
	}
	server.routes()
	return server
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /{$}", s.handleUIRoot)
	s.mux.HandleFunc("GET /ui/login", s.handleUILogin)
	s.mux.HandleFunc("POST /ui/login", s.handleUILoginPost)
	s.mux.HandleFunc("POST /ui/logout", s.handleUILogout)
	s.mux.HandleFunc("GET /ui/{$}", s.handleUITrailingSlash)
	s.mux.HandleFunc("GET /ui", s.requireUIAdmin(s.handleUIDashboard))
	s.mux.HandleFunc("GET /ui/repositories", s.requireUIAdmin(s.handleUIRepositories))
	s.mux.HandleFunc("POST /ui/repositories/delete", s.requireUIAdmin(s.handleUIRepositoryDelete))
	s.mux.HandleFunc("POST /ui/repositories/delete-tag", s.requireUIAdmin(s.handleUIRepositoryTagDelete))
	s.mux.HandleFunc("GET /ui/users", s.requireUIAdmin(s.handleUIUsers))
	s.mux.HandleFunc("POST /ui/users", s.requireUIAdmin(s.handleUIUsersCreate))
	s.mux.HandleFunc("POST /ui/users/{id}/access", s.requireUIAdmin(s.handleUIUserAccessUpdate))
	s.mux.HandleFunc("POST /ui/users/{id}/delete", s.requireUIAdmin(s.handleUIUserDelete))
	s.mux.HandleFunc("GET /ui/audit", s.requireUIAdmin(s.handleUIAudit))
	s.mux.HandleFunc("GET /ui/settings", s.requireUIAdmin(s.handleUISettings))
	s.mux.HandleFunc("POST /ui/settings/gc", s.requireUIAdmin(s.handleUIGCSettingsUpdate))
	s.mux.HandleFunc("POST /ui/settings/webhook", s.requireUIAdmin(s.handleUIRegistryWebhookSettingsUpdate))

	s.mux.HandleFunc("GET /healthz", s.handleHealth)
	s.mux.HandleFunc("GET /token", s.handleToken)

	s.mux.HandleFunc("GET /api/users", s.requireAdmin(s.handleListUsers))
	s.mux.HandleFunc("POST /api/users", s.requireAdmin(s.handleCreateUser))
	s.mux.HandleFunc("GET /api/users/{id}", s.requireAdmin(s.handleGetUser))
	s.mux.HandleFunc("DELETE /api/users/{id}", s.requireAdmin(s.handleDeleteUser))
	s.mux.HandleFunc("POST /api/users/{id}/disable", s.requireAdmin(s.handleDisableUser))
	s.mux.HandleFunc("POST /api/users/{id}/enable", s.requireAdmin(s.handleEnableUser))
	s.mux.HandleFunc("GET /api/grants", s.requireAdmin(s.handleListGrants))
	s.mux.HandleFunc("POST /api/grants", s.requireAdmin(s.handleCreateGrant))
	s.mux.HandleFunc("DELETE /api/grants/{id}", s.requireAdmin(s.handleDeleteGrant))
	s.mux.HandleFunc("GET /api/dashboard/summary", s.requireAdmin(s.handleDashboardSummary))
	s.mux.HandleFunc("GET /api/repositories", s.requireAdmin(s.handleListRepositories))
	s.mux.HandleFunc("GET /api/repositories/{name...}", s.requireAdmin(s.handleRepositoryRoute))
	s.mux.HandleFunc("GET /api/audit-events", s.requireAdmin(s.handleListAuditEvents))

	s.mux.HandleFunc("GET /v2/{$}", s.handleV2Base)
	s.mux.HandleFunc("/v2/{rest...}", s.handleRegistry)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	username, secret, ok := r.BasicAuth()
	if !ok {
		if err := s.auditAnonymous(r, "token.denied", "user", "", "missing_basic_auth"); err != nil {
			s.logger.Error("failed to write audit event", "error", err)
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="scr token service"`)
		writeError(w, http.StatusUnauthorized, "basic authentication is required")
		return
	}

	requested, err := parseRequestedScopes(r.URL.Query()["scope"])
	if err != nil {
		if auditErr := s.auditAnonymous(r, "token.denied", "username", username, "invalid_scope"); auditErr != nil {
			s.logger.Error("failed to write audit event", "error", auditErr)
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	authenticated, err := s.users.Authenticate(r.Context(), username, secret, now)
	if err != nil {
		status := http.StatusInternalServerError
		result := "error"
		if errors.Is(err, auth.ErrInvalidCredentials) {
			status = http.StatusUnauthorized
			result = "invalid_credentials"
		}
		if auditErr := s.auditAnonymous(r, "token.denied", "username", username, result); auditErr != nil {
			s.logger.Error("failed to write audit event", "error", auditErr)
		}
		writeError(w, status, "invalid credentials")
		return
	}

	grants, err := s.store.ListGrantsByUser(r.Context(), authenticated.User.ID)
	if err != nil {
		if auditErr := s.auditAnonymous(r, "token.denied", "user", authenticated.User.ID, "grant_load_failed"); auditErr != nil {
			s.logger.Error("failed to write audit event", "error", auditErr)
		}
		writeError(w, http.StatusInternalServerError, "failed to load grants")
		return
	}
	access := auth.IntersectAccess(authenticated.User.Role, grants, requested)
	token, issuedUntil, err := s.tokens.Mint(r.Context(), authenticated.User, access, now)
	if err != nil {
		if auditErr := s.auditAnonymous(r, "token.denied", "user", authenticated.User.ID, "mint_failed"); auditErr != nil {
			s.logger.Error("failed to write audit event", "error", auditErr)
		}
		writeError(w, http.StatusInternalServerError, "failed to mint token")
		return
	}
	if err := s.auditWithActor(r, auth.Principal{
		UserID:   authenticated.User.ID,
		Username: authenticated.User.Username,
		Role:     authenticated.User.Role,
		Access:   access,
	}, "token.issued", "user", authenticated.User.ID, "success"); err != nil {
		s.logger.Error("failed to write audit event", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to audit token issuance")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"token":        token,
		"access_token": token,
		"expires_in":   s.tokens.TTLSeconds(),
		"issued_at":    now.Format(time.RFC3339),
		"expires_at":   issuedUntil.Format(time.RFC3339),
	})
}

func (s *Server) handleV2Base(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.principalFromBearer(r); !ok {
		s.challenge(w, r, "")
		return
	}
	w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleRegistry(w http.ResponseWriter, r *http.Request) {
	route, ok := parseRegistryRoute(r)
	if !ok {
		writeError(w, http.StatusNotFound, "unknown registry endpoint")
		return
	}

	principal, authenticated := s.principalFromBearer(r)
	if route.kind == registryRouteCatalog {
		if !authenticated || principal.Role != domain.RoleAdmin {
			s.challenge(w, r, "")
			return
		}
		w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
		s.handleCatalog(w, r)
		return
	}

	if !authenticated || !auth.HasAccess(principal.Access, route.repository, route.action) {
		s.challenge(w, r, fmt.Sprintf("repository:%s:%s", route.repository, route.action))
		return
	}

	w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
	s.serveRegistryRoute(w, r.WithContext(contextWithPrincipal(r.Context(), principal)), route)
}

func (s *Server) serveRegistryRoute(w http.ResponseWriter, r *http.Request, route registryRoute) {
	switch route.kind {
	case registryRouteBlob:
		s.handleBlob(w, r, route)
	case registryRouteUploadStart:
		s.handleUploadStart(w, r, route)
	case registryRouteUpload:
		s.handleUpload(w, r, route)
	case registryRouteManifest:
		s.handleManifest(w, r, route)
	case registryRouteTags:
		s.handleTags(w, r, route)
	case registryRouteReferrers:
		s.handleReferrers(w, r, route)
	case registryRouteCatalog:
		s.handleCatalog(w, r)
	default:
		writeError(w, http.StatusNotFound, "unknown registry endpoint")
	}
}

func (s *Server) handleBlob(w http.ResponseWriter, r *http.Request, route registryRoute) {
	exists, _, err := s.registryFS.HasBlob(route.reference)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !exists {
		writeError(w, http.StatusNotFound, "blob not found")
		return
	}
	if r.Method == http.MethodDelete {
		if err := s.registryFS.DeleteBlob(route.reference); err != nil {
			writeStorageError(w, err)
			return
		}
		if err := s.audit(r, "registry.blob.deleted", "repository", route.repository, "success"); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to write audit event")
			return
		}
		w.WriteHeader(http.StatusAccepted)
		return
	}
	w.Header().Set("Docker-Content-Digest", route.reference)
	w.Header().Set("Content-Type", "application/octet-stream")
	if r.Method != http.MethodHead {
		if err := s.store.MarkRepositoryPulled(r.Context(), route.repository, "", time.Now().UTC()); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to update repository metadata")
			return
		}
		if err := s.store.IncrementUsageCounter(r.Context(), route.repository, domain.ActionPull, time.Now().UTC()); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to update usage counters")
			return
		}
		if err := s.audit(r, "registry.blob.pulled", "repository", route.repository, "success"); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to write audit event")
			return
		}
	}
	file, _, err := s.registryFS.OpenBlob(route.reference)
	if err != nil {
		writeStorageError(w, err)
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to inspect blob")
		return
	}
	http.ServeContent(w, r, route.reference, info.ModTime(), file)
}

func (s *Server) handleUploadStart(w http.ResponseWriter, r *http.Request, route registryRoute) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	digest := r.URL.Query().Get("digest")
	uploadID, err := ids.New("upl")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create upload")
		return
	}
	uploadPath, err := s.registryFS.UploadPath(uploadID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create upload")
		return
	}
	if err := os.MkdirAll(filepath.Dir(uploadPath), 0o750); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create upload")
		return
	}
	file, err := os.OpenFile(uploadPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create upload")
		return
	}
	if digest != "" {
		if _, err := io.Copy(file, r.Body); err != nil {
			_ = file.Close()
			writeError(w, http.StatusInternalServerError, "failed to write upload")
			return
		}
		_ = file.Close()
		s.commitBlobUpload(w, r, route.repository, uploadPath, digest)
		return
	}
	_ = file.Close()
	writeUploadAccepted(w, uploadLocation(route.repository, uploadID), uploadID, 0)
}

func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request, route registryRoute) {
	uploadPath, err := s.registryFS.UploadPath(route.uploadID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	switch r.Method {
	case http.MethodPatch:
		currentSize, err := uploadSize(uploadPath)
		if err != nil {
			writeError(w, http.StatusNotFound, "upload not found")
			return
		}
		if err := validateContentRange(r.Header.Get("Content-Range"), currentSize); err != nil {
			w.Header().Set("Range", uploadRange(currentSize))
			writeError(w, http.StatusRequestedRangeNotSatisfiable, err.Error())
			return
		}
		size, err := appendUpload(uploadPath, r.Body)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to append upload")
			return
		}
		writeUploadAccepted(w, uploadLocation(route.repository, route.uploadID), route.uploadID, size)
	case http.MethodPut:
		currentSize, err := uploadSize(uploadPath)
		if err != nil {
			writeError(w, http.StatusNotFound, "upload not found")
			return
		}
		if err := validateContentRange(r.Header.Get("Content-Range"), currentSize); err != nil {
			w.Header().Set("Range", uploadRange(currentSize))
			writeError(w, http.StatusRequestedRangeNotSatisfiable, err.Error())
			return
		}
		if _, err := appendUpload(uploadPath, r.Body); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to append upload")
			return
		}
		digest := r.URL.Query().Get("digest")
		if digest == "" {
			writeError(w, http.StatusBadRequest, "digest query parameter is required")
			return
		}
		s.commitBlobUpload(w, r, route.repository, uploadPath, digest)
	case http.MethodGet:
		size, err := uploadSize(uploadPath)
		if err != nil {
			writeError(w, http.StatusNotFound, "upload not found")
			return
		}
		w.Header().Set("Docker-Upload-UUID", route.uploadID)
		w.Header().Set("Range", uploadRange(size))
		w.WriteHeader(http.StatusNoContent)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) commitBlobUpload(w http.ResponseWriter, r *http.Request, repository, uploadPath, digest string) {
	if _, err := s.registryFS.CommitBlobFromUpload(uploadPath, digest); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.IncrementUsageCounter(r.Context(), repository, domain.ActionPush, time.Now().UTC()); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update usage counters")
		return
	}
	if err := s.audit(r, "registry.blob.pushed", "repository", repository, "success"); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to write audit event")
		return
	}
	w.Header().Set("Docker-Content-Digest", digest)
	w.Header().Set("Location", "/v2/"+repository+"/blobs/"+digest)
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) handleManifest(w http.ResponseWriter, r *http.Request, route registryRoute) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		content, mediaType, digest, err := s.registryFS.GetManifest(route.repository, route.reference)
		if err != nil {
			writeStorageError(w, err)
			return
		}
		w.Header().Set("Content-Type", mediaType)
		w.Header().Set("Docker-Content-Digest", digest)
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(content)))
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		if err := s.store.MarkRepositoryPulled(r.Context(), route.repository, route.reference, time.Now().UTC()); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to update repository metadata")
			return
		}
		if err := s.store.IncrementUsageCounter(r.Context(), route.repository, domain.ActionPull, time.Now().UTC()); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to update usage counters")
			return
		}
		if err := s.audit(r, "registry.manifest.pulled", "repository", route.repository, "success"); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to write audit event")
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(content)
	case http.MethodPut:
		content, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<20))
		if err != nil {
			writeError(w, http.StatusBadRequest, "failed to read manifest")
			return
		}
		mediaType := r.Header.Get("Content-Type")
		if mediaType == "" {
			mediaType = "application/vnd.oci.image.manifest.v1+json"
		}
		digest, _, err := s.registryFS.PutManifest(route.repository, route.reference, mediaType, content)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		tags := manifestTags(route.reference, r.URL.Query()["tag"])
		for _, tag := range tags {
			w.Header().Add("OCI-Tag", tag)
			if strings.Contains(route.reference, ":") {
				if err := s.registryFS.LinkManifestTag(route.repository, tag, digest); err != nil {
					writeStorageError(w, err)
					return
				}
			}
			if err := s.store.UpsertRepositoryTag(r.Context(), db.UpsertRepositoryTagParams{
				RepositoryName: route.repository,
				Tag:            tag,
				Digest:         digest,
				MediaType:      mediaType,
				SizeBytes:      estimateManifestArtifactSize(content),
			}, time.Now().UTC()); err != nil {
				writeError(w, http.StatusInternalServerError, "failed to update repository metadata")
				return
			}
		}
		if err := s.store.IncrementUsageCounter(r.Context(), route.repository, domain.ActionPush, time.Now().UTC()); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to update usage counters")
			return
		}
		if err := s.audit(r, "registry.manifest.pushed", "repository", route.repository, "success"); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to write audit event")
			return
		}
		w.Header().Set("Docker-Content-Digest", digest)
		if subjectDigest := storage.SubjectDigest(content); subjectDigest != "" {
			w.Header().Set("OCI-Subject", subjectDigest)
		}
		w.Header().Set("Location", "/v2/"+route.repository+"/manifests/"+route.reference)
		w.WriteHeader(http.StatusCreated)
	case http.MethodDelete:
		if err := s.deleteManifestReference(r.Context(), route.repository, route.reference); err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				writeStorageError(w, err)
				return
			}
			writeError(w, http.StatusInternalServerError, "failed to update repository metadata")
			return
		}
		if err := s.audit(r, "registry.manifest.deleted", "repository", route.repository, "success"); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to write audit event")
			return
		}
		w.WriteHeader(http.StatusAccepted)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) deleteManifestReference(ctx context.Context, repository, reference string) error {
	digest, err := s.registryFS.DeleteManifest(repository, reference)
	if err != nil {
		return err
	}
	return s.store.DeleteRepositoryManifestReference(ctx, repository, reference, digest)
}

func (s *Server) handleTags(w http.ResponseWriter, r *http.Request, route registryRoute) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	tags, err := s.registryFS.ListTags(route.repository)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	limit, err := parseNonNegativeInt(r.URL.Query().Get("n"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid tags limit")
		return
	}
	tags = pageStrings(tags, r.URL.Query().Get("last"), limit)
	if limit > 0 && len(tags) > limit {
		nextLast := tags[limit-1]
		tags = tags[:limit]
		query := url.Values{}
		query.Set("last", nextLast)
		query.Set("n", strconv.Itoa(limit))
		w.Header().Set("Link", "</v2/"+route.repository+"/tags/list?"+query.Encode()+">; rel=\"next\"")
	}
	writeJSON(w, http.StatusOK, map[string]any{"name": route.repository, "tags": tags})
}

func (s *Server) handleReferrers(w http.ResponseWriter, r *http.Request, route registryRoute) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	artifactType := r.URL.Query().Get("artifactType")
	descriptors, err := s.registryFS.ListReferrers(route.repository, route.reference, artifactType)
	if err != nil {
		writeStorageError(w, err)
		return
	}
	if artifactType != "" {
		w.Header().Set("OCI-Filters-Applied", "artifactType")
	}
	w.Header().Set("Content-Type", "application/vnd.oci.image.index.v1+json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.index.v1+json",
		"manifests":     descriptors,
	})
}

func (s *Server) handleCatalog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	limit := 0
	if raw := r.URL.Query().Get("n"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 {
			writeError(w, http.StatusBadRequest, "invalid catalog limit")
			return
		}
		limit = parsed
	}
	last := r.URL.Query().Get("last")
	repositories, err := s.store.ListRepositories(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list repositories")
		return
	}

	names := make([]string, 0, len(repositories))
	for _, repository := range repositories {
		if last != "" && repository.Name <= last {
			continue
		}
		names = append(names, repository.Name)
	}
	if limit > 0 && len(names) > limit {
		nextLast := names[limit-1]
		names = names[:limit]
		query := url.Values{}
		query.Set("last", nextLast)
		query.Set("n", strconv.Itoa(limit))
		w.Header().Set("Link", "</v2/_catalog?"+query.Encode()+">; rel=\"next\"")
	}
	writeJSON(w, http.StatusOK, map[string]any{"repositories": names})
}

func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := s.principalFromBearer(r)
		if !ok || principal.Role != domain.RoleAdmin {
			writeError(w, http.StatusUnauthorized, "admin bearer token is required")
			return
		}
		next(w, r.WithContext(contextWithPrincipal(r.Context(), principal)))
	}
}

func (s *Server) principalFromBearer(r *http.Request) (auth.Principal, bool) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return auth.Principal{}, false
	}
	scheme, token, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" {
		return auth.Principal{}, false
	}
	principal, err := s.tokens.Validate(r.Context(), token)
	if err != nil {
		return auth.Principal{}, false
	}
	return principal, true
}

func (s *Server) challenge(w http.ResponseWriter, r *http.Request, scope string) {
	value := fmt.Sprintf(`Bearer realm="%s",service="%s"`, s.realm(r), s.cfg.Auth.Service)
	if scope != "" {
		value += fmt.Sprintf(`,scope="%s"`, scope)
	}
	w.Header().Set("WWW-Authenticate", value)
	w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
	writeError(w, http.StatusUnauthorized, "authentication required")
}

func (s *Server) realm(r *http.Request) string {
	proto := r.Header.Get("X-Forwarded-Proto")
	if proto == "" {
		proto = "http"
	}
	host := r.Host
	if host == "" {
		host = s.cfg.HTTP.ListenAddress()
	}
	return proto + "://" + host + "/token"
}

func parseRequestedScopes(rawScopes []string) ([]auth.RequestedScope, error) {
	requested := make([]auth.RequestedScope, 0, len(rawScopes))
	for _, raw := range rawScopes {
		if raw == "" {
			continue
		}
		scope, err := auth.ParseScope(raw)
		if err != nil {
			return nil, err
		}
		requested = append(requested, scope)
	}
	return requested, nil
}

type registryRouteKind string

const (
	registryRouteBlob        registryRouteKind = "blob"
	registryRouteUploadStart registryRouteKind = "upload-start"
	registryRouteUpload      registryRouteKind = "upload"
	registryRouteManifest    registryRouteKind = "manifest"
	registryRouteTags        registryRouteKind = "tags"
	registryRouteReferrers   registryRouteKind = "referrers"
	registryRouteCatalog     registryRouteKind = "catalog"
)

type registryRoute struct {
	repository string
	kind       registryRouteKind
	reference  string
	uploadID   string
	action     domain.Action
}

func parseRegistryRoute(r *http.Request) (registryRoute, bool) {
	rest := strings.TrimPrefix(r.URL.Path, "/v2/")
	if rest == "" {
		return registryRoute{}, false
	}
	if rest == "_catalog" {
		return registryRoute{kind: registryRouteCatalog, action: domain.ActionAdmin}, true
	}
	if repository, _, ok := strings.Cut(rest, "/tags/list"); ok && repository != "" {
		return registryRoute{repository: repository, kind: registryRouteTags, action: domain.ActionPull}, true
	}
	if repository, digest, ok := cutMarker(rest, "/referrers/"); ok && repository != "" && digest != "" {
		if r.Method != http.MethodGet {
			return registryRoute{}, false
		}
		return registryRoute{repository: repository, kind: registryRouteReferrers, reference: digest, action: domain.ActionPull}, true
	}
	if repository, reference, ok := cutMarker(rest, "/manifests/"); ok {
		action := actionForManifestMethod(r.Method)
		if action == "" || reference == "" {
			return registryRoute{}, false
		}
		return registryRoute{repository: repository, kind: registryRouteManifest, reference: reference, action: action}, true
	}
	if repository, digest, ok := cutMarker(rest, "/blobs/"); ok && digest != "" && !strings.HasPrefix(digest, "uploads/") {
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodDelete {
			return registryRoute{}, false
		}
		action := domain.ActionPull
		if r.Method == http.MethodDelete {
			action = domain.ActionDelete
		}
		return registryRoute{repository: repository, kind: registryRouteBlob, reference: digest, action: action}, true
	}
	if repository, uploadID, ok := cutMarker(rest, "/blobs/uploads/"); ok {
		if uploadID == "" {
			if r.Method != http.MethodPost {
				return registryRoute{}, false
			}
			return registryRoute{repository: repository, kind: registryRouteUploadStart, action: domain.ActionPush}, true
		}
		if r.Method != http.MethodPatch && r.Method != http.MethodPut && r.Method != http.MethodGet {
			return registryRoute{}, false
		}
		return registryRoute{repository: repository, kind: registryRouteUpload, uploadID: uploadID, action: domain.ActionPush}, true
	}
	return registryRoute{}, false
}

func cutMarker(value, marker string) (string, string, bool) {
	idx := strings.Index(value, marker)
	if idx <= 0 {
		return "", "", false
	}
	return value[:idx], value[idx+len(marker):], true
}

func actionForManifestMethod(method string) domain.Action {
	switch method {
	case http.MethodGet, http.MethodHead:
		return domain.ActionPull
	case http.MethodPut:
		return domain.ActionPush
	case http.MethodDelete:
		return domain.ActionDelete
	default:
		return ""
	}
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{"error": message})
}

func writeStorageError(w http.ResponseWriter, err error) {
	if errors.Is(err, storage.ErrInvalidDigest) {
		writeError(w, http.StatusBadRequest, "invalid digest")
		return
	}
	if errors.Is(err, storage.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	writeError(w, http.StatusInternalServerError, "storage error")
}

func parseNonNegativeInt(raw string) (int, error) {
	if raw == "" {
		return 0, nil
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil || parsed < 0 {
		return 0, fmt.Errorf("invalid non-negative integer")
	}
	return parsed, nil
}

func pageStrings(values []string, last string, limit int) []string {
	paged := make([]string, 0, len(values))
	for _, value := range values {
		if last != "" && value <= last {
			continue
		}
		paged = append(paged, value)
	}
	if limit > 0 && len(paged) > limit {
		return paged[:limit+1]
	}
	return paged
}

func manifestTags(reference string, queryTags []string) []string {
	if !strings.Contains(reference, ":") {
		return []string{reference}
	}
	tags := make([]string, 0, len(queryTags))
	seen := make(map[string]bool, len(queryTags))
	for _, tag := range queryTags {
		if tag == "" || seen[tag] {
			continue
		}
		seen[tag] = true
		tags = append(tags, tag)
	}
	return tags
}

func uploadSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

func validateContentRange(raw string, currentSize int64) error {
	if raw == "" {
		return nil
	}
	startRaw, endRaw, ok := strings.Cut(raw, "-")
	if !ok || startRaw == "" || endRaw == "" {
		return fmt.Errorf("invalid content range")
	}
	start, err := strconv.ParseInt(startRaw, 10, 64)
	if err != nil || start < 0 {
		return fmt.Errorf("invalid content range")
	}
	end, err := strconv.ParseInt(endRaw, 10, 64)
	if err != nil || end < start {
		return fmt.Errorf("invalid content range")
	}
	if start != currentSize {
		return fmt.Errorf("out-of-order upload chunk")
	}
	return nil
}

func appendUpload(path string, body io.Reader) (int64, error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	if _, err := io.Copy(file, body); err != nil {
		return 0, err
	}
	info, err := file.Stat()
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

func writeUploadAccepted(w http.ResponseWriter, location, uploadID string, size int64) {
	w.Header().Set("Location", location)
	w.Header().Set("Docker-Upload-UUID", uploadID)
	w.Header().Set("Range", uploadRange(size))
	w.WriteHeader(http.StatusAccepted)
}

func uploadLocation(repository, uploadID string) string {
	return "/v2/" + repository + "/blobs/uploads/" + uploadID
}

func uploadRange(size int64) string {
	if size <= 0 {
		return "0-0"
	}
	return fmt.Sprintf("0-%d", size-1)
}

func estimateManifestArtifactSize(content []byte) int64 {
	var manifest struct {
		Config *struct {
			Size int64 `json:"size"`
		} `json:"config"`
		Layers []struct {
			Size int64 `json:"size"`
		} `json:"layers"`
		Manifests []struct {
			Size int64 `json:"size"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal(content, &manifest); err != nil {
		return int64(len(content))
	}
	total := int64(len(content))
	if manifest.Config != nil && manifest.Config.Size > 0 {
		total += manifest.Config.Size
	}
	for _, layer := range manifest.Layers {
		if layer.Size > 0 {
			total += layer.Size
		}
	}
	for _, child := range manifest.Manifests {
		if child.Size > 0 {
			total += child.Size
		}
	}
	return total
}
