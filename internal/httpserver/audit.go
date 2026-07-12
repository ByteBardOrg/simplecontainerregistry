package httpserver

import (
	"context"
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
