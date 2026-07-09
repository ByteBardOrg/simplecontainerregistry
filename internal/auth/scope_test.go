package auth

import (
	"testing"

	"simplecontainerregistry/internal/domain"
)

func TestParseScope(t *testing.T) {
	scope, err := ParseScope("repository:customers/acme/app:pull,push")
	if err != nil {
		t.Fatalf("ParseScope() error = %v", err)
	}
	if scope.Name != "customers/acme/app" || len(scope.Actions) != 2 {
		t.Fatalf("unexpected scope: %#v", scope)
	}
}

func TestIntersectAccessForReaderUsesPrefixGrants(t *testing.T) {
	grants := []domain.Grant{{
		SubjectType:      "user",
		RepositoryPrefix: "customers/acme/",
		Actions:          []domain.Action{domain.ActionPull},
	}}
	requested := []RequestedScope{{
		Type:    "repository",
		Name:    "customers/acme/app",
		Actions: []domain.Action{domain.ActionPull, domain.ActionPush},
	}}

	access := IntersectAccess(domain.RoleReader, grants, requested)
	if len(access) != 1 {
		t.Fatalf("expected one access claim, got %d", len(access))
	}
	if len(access[0].Actions) != 1 || access[0].Actions[0] != domain.ActionPull {
		t.Fatalf("expected only pull access, got %#v", access[0].Actions)
	}
}

func TestIntersectAccessSupportsWildcardGrant(t *testing.T) {
	grants := []domain.Grant{{
		SubjectType:      "user",
		RepositoryPrefix: "*",
		Actions:          []domain.Action{domain.ActionPull},
	}}
	requested := []RequestedScope{{
		Type:    "repository",
		Name:    "any/repo",
		Actions: []domain.Action{domain.ActionPull, domain.ActionPush},
	}}

	access := IntersectAccess(domain.RoleReader, grants, requested)
	if len(access) != 1 || len(access[0].Actions) != 1 || access[0].Actions[0] != domain.ActionPull {
		t.Fatalf("expected wildcard pull access, got %#v", access)
	}
}

func TestIntersectAccessForAdminAllowsRequestedActions(t *testing.T) {
	requested := []RequestedScope{{
		Type:    "repository",
		Name:    "any/repo",
		Actions: []domain.Action{domain.ActionPull, domain.ActionPush},
	}}
	access := IntersectAccess(domain.RoleAdmin, nil, requested)
	if len(access) != 1 || len(access[0].Actions) != 2 {
		t.Fatalf("expected admin to get requested access, got %#v", access)
	}
}
