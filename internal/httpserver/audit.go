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
		IPAddress:   s.requestIP(r),
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
		IPAddress:   s.requestIP(r),
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
		IPAddress:  s.requestIP(r),
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

func (s *Server) requestIP(r *http.Request) string {
	if s.isTrustedProxy(r.RemoteAddr) {
		if forwardedFor := r.Header.Get("X-Forwarded-For"); forwardedFor != "" {
			if clientIP, ok := s.forwardedClientIP(forwardedFor); ok {
				return clientIP
			}
			return remoteHost(r.RemoteAddr)
		}
		if realIP := net.ParseIP(strings.TrimSpace(r.Header.Get("X-Real-IP"))); realIP != nil && !s.isTrustedProxyIP(realIP) {
			return realIP.String()
		}
	}
	return remoteHost(r.RemoteAddr)
}

func remoteHost(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

func (s *Server) forwardedClientIP(forwardedFor string) (string, bool) {
	parts := strings.Split(forwardedFor, ",")
	for index := len(parts) - 1; index >= 0; index-- {
		ip := net.ParseIP(strings.TrimSpace(parts[index]))
		if ip != nil && !s.isTrustedProxyIP(ip) {
			return ip.String(), true
		}
	}
	return "", false
}

func (s *Server) isTrustedProxy(remoteAddr string) bool {
	if !s.cfg.HTTP.TrustForwardedHeaders {
		return false
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return false
	}
	peer := net.ParseIP(host)
	if peer == nil {
		return false
	}
	return s.isTrustedProxyIP(peer)
}

func (s *Server) isTrustedProxyIP(peer net.IP) bool {
	for _, rawCIDR := range s.cfg.HTTP.TrustedProxyCIDRs {
		_, cidr, err := net.ParseCIDR(rawCIDR)
		if err == nil && cidr.Contains(peer) {
			return true
		}
	}
	return false
}

func stringPtr(value string) *string {
	return &value
}
