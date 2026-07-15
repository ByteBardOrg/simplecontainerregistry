package httpserver

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"simplecontainerregistry/internal/auth"
	"simplecontainerregistry/internal/domain"
	"simplecontainerregistry/internal/ids"
)

type principalContextKey struct{}

func contextWithPrincipal(ctx context.Context, principal auth.Principal) context.Context {
	return context.WithValue(ctx, principalContextKey{}, principal)
}

func principalFromContext(ctx context.Context) (auth.Principal, bool) {
	principal, ok := ctx.Value(principalContextKey{}).(auth.Principal)
	return principal, ok
}

func (s *Server) audit(r *http.Request, action, targetType, targetID, result string) error {
	principal, ok := principalFromContext(r.Context())
	var actorUserID *string
	if ok {
		actorUserID = stringPtr(principal.UserID)
	}
	return s.insertAuditEvent(r.Context(), domain.AuditEvent{
		ActorUserID: actorUserID,
		Action:      action,
		TargetType:  targetType,
		TargetID:    targetID,
		Result:      result,
		IPAddress:   requestIP(r),
		UserAgent:   r.UserAgent(),
		CreatedAt:   time.Now().UTC(),
	})
}

func (s *Server) auditWithActor(r *http.Request, principal auth.Principal, action, targetType, targetID, result string) error {
	actorUserID := stringPtr(principal.UserID)
	return s.insertAuditEvent(r.Context(), domain.AuditEvent{
		ActorUserID: actorUserID,
		Action:      action,
		TargetType:  targetType,
		TargetID:    targetID,
		Result:      result,
		IPAddress:   requestIP(r),
		UserAgent:   r.UserAgent(),
		CreatedAt:   time.Now().UTC(),
	})
}

func (s *Server) auditAnonymous(r *http.Request, action, targetType, targetID, result string) error {
	return s.insertAuditEvent(r.Context(), domain.AuditEvent{
		Action:     action,
		TargetType: targetType,
		TargetID:   targetID,
		Result:     result,
		IPAddress:  requestIP(r),
		UserAgent:  r.UserAgent(),
		CreatedAt:  time.Now().UTC(),
	})
}

func (s *Server) insertAuditEvent(ctx context.Context, event domain.AuditEvent) error {
	if event.ID == "" {
		id, err := ids.New("aud")
		if err != nil {
			return err
		}
		event.ID = id
	}
	if err := s.store.InsertAuditEvent(ctx, event); err != nil {
		return err
	}
	if s.webhooks != nil {
		s.webhooks.Enqueue(event)
	}
	return nil
}

func (s *Server) auditGrantTarget(ctx context.Context, grant domain.Grant) string {
	subject := grant.SubjectID
	if user, err := s.store.GetUser(ctx, grant.SubjectID); err == nil {
		subject = user.Username
	}
	return fmt.Sprintf("%s | %s | %s", subject, grant.RepositoryPrefix, auditActionsLabel(grant.Actions))
}

func (s *Server) auditGrantTargetByID(ctx context.Context, grantID string) string {
	grants, err := s.store.ListGrants(ctx)
	if err != nil {
		return grantID
	}
	for _, grant := range grants {
		if grant.ID == grantID {
			return s.auditGrantTarget(ctx, grant)
		}
	}
	return grantID
}

func auditActionsLabel(actions []domain.Action) string {
	parts := make([]string, 0, len(actions))
	for _, action := range actions {
		parts = append(parts, string(action))
	}
	return strings.Join(parts, ", ")
}

func requestIP(r *http.Request) string {
	if forwardedFor := r.Header.Get("X-Forwarded-For"); forwardedFor != "" {
		first, _, _ := strings.Cut(forwardedFor, ",")
		return strings.TrimSpace(first)
	}
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return realIP
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func stringPtr(value string) *string {
	return &value
}
