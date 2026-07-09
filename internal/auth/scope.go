package auth

import (
	"fmt"
	"strings"

	"simplecontainerregistry/internal/domain"
)

type RequestedScope struct {
	Type    string
	Name    string
	Actions []domain.Action
}

type AccessClaim struct {
	Type    string          `json:"type"`
	Name    string          `json:"name"`
	Actions []domain.Action `json:"actions"`
}

func ParseScope(raw string) (RequestedScope, error) {
	parts := strings.Split(raw, ":")
	if len(parts) != 3 {
		return RequestedScope{}, fmt.Errorf("invalid scope %q", raw)
	}
	if parts[0] != "repository" {
		return RequestedScope{}, fmt.Errorf("unsupported scope type %q", parts[0])
	}
	if parts[1] == "" {
		return RequestedScope{}, fmt.Errorf("repository scope name is required")
	}
	actionParts := strings.Split(parts[2], ",")
	actions := make([]domain.Action, 0, len(actionParts))
	for _, action := range actionParts {
		if action == "" {
			continue
		}
		actions = append(actions, domain.Action(action))
	}
	if !domain.ValidActions(actions) {
		return RequestedScope{}, fmt.Errorf("invalid scope actions")
	}
	return RequestedScope{Type: parts[0], Name: parts[1], Actions: actions}, nil
}

func IntersectAccess(role domain.Role, grants []domain.Grant, requested []RequestedScope) []AccessClaim {
	access := make([]AccessClaim, 0, len(requested))
	for _, scope := range requested {
		allowed := allowedActions(role, grants, scope)
		if len(allowed) == 0 {
			continue
		}
		access = append(access, AccessClaim{Type: scope.Type, Name: scope.Name, Actions: allowed})
	}
	return access
}

func HasAccess(access []AccessClaim, repository string, action domain.Action) bool {
	for _, claim := range access {
		if claim.Type != "repository" || claim.Name != repository {
			continue
		}
		for _, allowed := range claim.Actions {
			if allowed == action || allowed == domain.ActionAdmin {
				return true
			}
		}
	}
	return false
}

func allowedActions(role domain.Role, grants []domain.Grant, scope RequestedScope) []domain.Action {
	if role == domain.RoleAdmin {
		return uniqueActions(scope.Actions)
	}

	allowed := make(map[domain.Action]bool)
	for _, grant := range grants {
		if grant.SubjectType != "user" || !repositoryMatches(scope.Name, grant.RepositoryPrefix) {
			continue
		}
		for _, granted := range grant.Actions {
			allowed[granted] = true
		}
	}

	var intersected []domain.Action
	seen := make(map[domain.Action]bool)
	for _, requested := range scope.Actions {
		if allowed[requested] && !seen[requested] {
			intersected = append(intersected, requested)
			seen[requested] = true
		}
	}
	return intersected
}

func repositoryMatches(repository, prefix string) bool {
	prefix = strings.TrimPrefix(prefix, "/")
	if prefix == "*" {
		return true
	}
	if prefix == "" {
		return false
	}
	return repository == strings.TrimSuffix(prefix, "/") || strings.HasPrefix(repository, prefix)
}

func uniqueActions(actions []domain.Action) []domain.Action {
	seen := make(map[domain.Action]bool, len(actions))
	result := make([]domain.Action, 0, len(actions))
	for _, action := range actions {
		if seen[action] {
			continue
		}
		seen[action] = true
		result = append(result, action)
	}
	return result
}
