package auth

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"simplecontainerregistry/internal/config"
	"simplecontainerregistry/internal/db"
	"simplecontainerregistry/internal/domain"
)

func TestTokenMintAndValidate(t *testing.T) {
	ctx := context.Background()
	store := openAuthTestStore(t, ctx)
	if err := store.EnsureActiveSigningKey(ctx); err != nil {
		t.Fatalf("EnsureActiveSigningKey() error = %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	user, err := createTokenTestUser(t, ctx, store, "admin", domain.RoleAdmin, now, nil, nil)
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}

	cfg := config.Default().Auth
	service := NewTokenService(store, cfg)
	token, _, err := service.Mint(ctx, user, []AccessClaim{{Type: "repository", Name: "repo", Actions: []domain.Action{domain.ActionPull}}}, now)
	if err != nil {
		t.Fatalf("Mint() error = %v", err)
	}
	principal, err := service.Validate(ctx, token)
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if principal.UserID != user.ID || principal.Role != domain.RoleAdmin {
		t.Fatalf("unexpected principal: %#v", principal)
	}
}

func TestTokenValidateRejectsDisabledUser(t *testing.T) {
	ctx := context.Background()
	store := openAuthTestStore(t, ctx)
	if err := store.EnsureActiveSigningKey(ctx); err != nil {
		t.Fatalf("EnsureActiveSigningKey() error = %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	user, err := createTokenTestUser(t, ctx, store, "disabled", domain.RoleReader, now, nil, nil)
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}

	service := NewTokenService(store, config.Default().Auth)
	token, _, err := service.Mint(ctx, user, nil, now)
	if err != nil {
		t.Fatalf("Mint() error = %v", err)
	}
	if err := store.SetUserStatus(ctx, user.ID, domain.UserStatusDisabled, now.Add(time.Second)); err != nil {
		t.Fatalf("SetUserStatus() error = %v", err)
	}
	if _, err := service.Validate(ctx, token); err == nil {
		t.Fatal("expected disabled user token to be rejected")
	}
}

func TestTokenValidateRejectsExpiredUser(t *testing.T) {
	ctx := context.Background()
	store := openAuthTestStore(t, ctx)
	if err := store.EnsureActiveSigningKey(ctx); err != nil {
		t.Fatalf("EnsureActiveSigningKey() error = %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	expiresAt := now.Add(-time.Minute)
	user, err := createTokenTestUser(t, ctx, store, "expired", domain.RoleReader, now, nil, &expiresAt)
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}

	service := NewTokenService(store, config.Default().Auth)
	token, _, err := service.Mint(ctx, user, nil, now)
	if err != nil {
		t.Fatalf("Mint() error = %v", err)
	}
	if _, err := service.Validate(ctx, token); err == nil {
		t.Fatal("expected expired user token to be rejected")
	}
}

func TestTokenValidateRejectsFutureUser(t *testing.T) {
	ctx := context.Background()
	store := openAuthTestStore(t, ctx)
	if err := store.EnsureActiveSigningKey(ctx); err != nil {
		t.Fatalf("EnsureActiveSigningKey() error = %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	notBefore := now.Add(time.Hour)
	user, err := createTokenTestUser(t, ctx, store, "future", domain.RoleReader, now, &notBefore, nil)
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}

	service := NewTokenService(store, config.Default().Auth)
	token, _, err := service.Mint(ctx, user, nil, now)
	if err != nil {
		t.Fatalf("Mint() error = %v", err)
	}
	if _, err := service.Validate(ctx, token); err == nil {
		t.Fatal("expected future user token to be rejected")
	}
}

func createTokenTestUser(t *testing.T, ctx context.Context, store *db.Store, username string, role domain.Role, now time.Time, notBefore, expiresAt *time.Time) (domain.User, error) {
	t.Helper()
	return store.CreateUser(ctx, db.CreateUserParams{
		Username:    username,
		DisplayName: username,
		Role:        role,
		SecretHash:  "hash",
		NotBefore:   notBefore,
		ExpiresAt:   expiresAt,
	}, now)
}

func openAuthTestStore(t *testing.T, ctx context.Context) *db.Store {
	t.Helper()
	store, err := db.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.InitSchema(ctx); err != nil {
		t.Fatalf("InitSchema() error = %v", err)
	}
	return store
}
