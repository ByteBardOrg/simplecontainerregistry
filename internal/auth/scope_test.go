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

func TestRepositoryMatches(t *testing.T) {
	tests := []struct {
		name       string
		repository string
		prefix     string
		want       bool
	}{
		{name: "exact repository", repository: "team/app", prefix: "team/app", want: true},
		{name: "child namespace", repository: "team/app/api", prefix: "team/app", want: true},
		{name: "trailing slash namespace", repository: "team/api", prefix: "team/", want: true},
		{name: "same-string sibling", repository: "team/application", prefix: "team/app", want: false},
		{name: "hyphenated sibling", repository: "team/app-prod", prefix: "team/app", want: false},
		{name: "wildcard", repository: "any/repository", prefix: "*", want: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := repositoryMatches(test.repository, test.prefix); got != test.want {
				t.Errorf("repositoryMatches(%q, %q) = %v, want %v", test.repository, test.prefix, got, test.want)
			}
		})
	}
}

func TestIntersectAccessForReaderPreservesActionSemantics(t *testing.T) {
	grants := []domain.Grant{{
		SubjectType:      "user",
		RepositoryPrefix: "customers/acme/",
		Actions:          []domain.Action{domain.ActionPull, domain.ActionPush, domain.ActionDelete},
	}}
	requested := []RequestedScope{{
		Type:    "repository",
		Name:    "customers/acme/app",
		Actions: []domain.Action{domain.ActionPull, domain.ActionPush, domain.ActionDelete},
	}}

	access := IntersectAccess(domain.RoleReader, grants, requested)
	if len(access) != 1 {
		t.Fatalf("expected one access claim, got %d", len(access))
	}
	if len(access[0].Actions) != 3 || access[0].Actions[0] != domain.ActionPull || access[0].Actions[1] != domain.ActionPush || access[0].Actions[2] != domain.ActionDelete {
		t.Fatalf("expected pull, push, and delete access, got %#v", access[0].Actions)
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
