package httpserver

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"simplecontainerregistry/internal/db"
	"simplecontainerregistry/internal/domain"
)

type createUserRequest struct {
	Username    string               `json:"username"`
	DisplayName string               `json:"displayName"`
	Role        domain.Role          `json:"role"`
	NotBefore   *time.Time           `json:"notBefore"`
	ExpiresAt   *time.Time           `json:"expiresAt"`
	Grants      []createGrantRequest `json:"grants"`
}

type createUserResponse struct {
	User      domain.User `json:"user"`
	Secret    string      `json:"secret"`
	NotBefore *time.Time  `json:"notBefore,omitempty"`
	ExpiresAt *time.Time  `json:"expiresAt,omitempty"`
}

type createGrantRequest struct {
	SubjectType      string          `json:"subjectType"`
	SubjectID        string          `json:"subjectId"`
	RepositoryPrefix string          `json:"repositoryPrefix"`
	Actions          []domain.Action `json:"actions"`
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var request createUserRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	now := time.Now().UTC()
	if request.NotBefore != nil && request.ExpiresAt != nil && !request.ExpiresAt.After(*request.NotBefore) {
		writeError(w, http.StatusBadRequest, "expires at must be after valid from")
		return
	}
	user, secret, err := s.users.CreateUser(r.Context(), db.CreateUserParams{
		Username:    request.Username,
		DisplayName: request.DisplayName,
		Role:        request.Role,
		NotBefore:   request.NotBefore,
		ExpiresAt:   request.ExpiresAt,
	}, now)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.audit(r, "user.created", "user", user.ID, "success"); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to write audit event")
		return
	}
	for _, grantRequest := range request.Grants {
		grant, err := s.store.CreateGrant(r.Context(), db.CreateGrantParams{
			SubjectType:      "user",
			SubjectID:        user.ID,
			RepositoryPrefix: grantRequest.RepositoryPrefix,
			Actions:          grantRequest.Actions,
		}, now)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := s.audit(r, "grant.created", "grant", grant.ID, "success"); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to write audit event")
			return
		}
	}
	writeJSON(w, http.StatusCreated, createUserResponse{
		User:      user,
		Secret:    secret,
		NotBefore: user.NotBefore,
		ExpiresAt: user.ExpiresAt,
	})
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list users")
		return
	}
	writeJSON(w, http.StatusOK, users)
}

func (s *Server) handleGetUser(w http.ResponseWriter, r *http.Request) {
	user, err := s.store.GetUser(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, user)
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	principal, ok := principalFromContext(r.Context())
	if ok && principal.UserID == userID {
		writeError(w, http.StatusBadRequest, "cannot delete the current admin user")
		return
	}
	if err := s.store.DeleteUser(r.Context(), userID); err != nil {
		writeStoreError(w, err)
		return
	}
	if err := s.audit(r, "user.deleted", "user", userID, "success"); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to write audit event")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDisableUser(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	if err := s.store.SetUserStatus(r.Context(), userID, domain.UserStatusDisabled, time.Now().UTC()); err != nil {
		writeStoreError(w, err)
		return
	}
	if err := s.audit(r, "user.disabled", "user", userID, "success"); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to write audit event")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleEnableUser(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	if err := s.store.SetUserStatus(r.Context(), userID, domain.UserStatusActive, time.Now().UTC()); err != nil {
		writeStoreError(w, err)
		return
	}
	if err := s.audit(r, "user.enabled", "user", userID, "success"); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to write audit event")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleCreateGrant(w http.ResponseWriter, r *http.Request) {
	var request createGrantRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	grant, err := s.store.CreateGrant(r.Context(), db.CreateGrantParams{
		SubjectType:      request.SubjectType,
		SubjectID:        request.SubjectID,
		RepositoryPrefix: request.RepositoryPrefix,
		Actions:          request.Actions,
	}, time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.audit(r, "grant.created", "grant", grant.ID, "success"); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to write audit event")
		return
	}
	writeJSON(w, http.StatusCreated, grant)
}

func (s *Server) handleListGrants(w http.ResponseWriter, r *http.Request) {
	grants, err := s.store.ListGrants(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list grants")
		return
	}
	writeJSON(w, http.StatusOK, grants)
}

func (s *Server) handleDeleteGrant(w http.ResponseWriter, r *http.Request) {
	grantID := r.PathValue("id")
	if err := s.store.DeleteGrant(r.Context(), grantID); err != nil {
		writeStoreError(w, err)
		return
	}
	if err := s.audit(r, "grant.deleted", "grant", grantID, "success"); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to write audit event")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDashboardSummary(w http.ResponseWriter, r *http.Request) {
	summary, err := s.store.DashboardSummary(r.Context(), time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load dashboard summary")
		return
	}
	writeJSON(w, http.StatusOK, summary)
}

func (s *Server) handleListRepositories(w http.ResponseWriter, r *http.Request) {
	repositories, err := s.store.ListRepositories(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list repositories")
		return
	}
	writeJSON(w, http.StatusOK, repositories)
}

func (s *Server) handleRepositoryRoute(w http.ResponseWriter, r *http.Request) {
	name := strings.Trim(r.PathValue("name"), "/")
	if name == "" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if strings.HasSuffix(name, "/tags") {
		s.handleListRepositoryTags(w, r, strings.TrimSuffix(name, "/tags"))
		return
	}
	s.handleGetRepository(w, r, name)
}

func (s *Server) handleGetRepository(w http.ResponseWriter, r *http.Request, name string) {
	repository, err := s.store.GetRepository(r.Context(), name)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, repository)
}

func (s *Server) handleListRepositoryTags(w http.ResponseWriter, r *http.Request, repositoryName string) {
	if repositoryName == "" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if _, err := s.store.GetRepository(r.Context(), repositoryName); err != nil {
		writeStoreError(w, err)
		return
	}
	tags, err := s.store.ListRepositoryTags(r.Context(), repositoryName)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list repository tags")
		return
	}
	writeJSON(w, http.StatusOK, tags)
}

func (s *Server) handleListAuditEvents(w http.ResponseWriter, r *http.Request) {
	events, err := s.store.ListAuditEvents(r.Context(), 100)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list audit events")
		return
	}
	writeJSON(w, http.StatusOK, events)
}

func writeStoreError(w http.ResponseWriter, err error) {
	if errors.Is(err, db.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	writeError(w, http.StatusInternalServerError, "internal server error")
}
