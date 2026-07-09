package auth

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"simplecontainerregistry/internal/db"
	"simplecontainerregistry/internal/domain"
)

func TestAuthenticateRejectsUserBeforeNotBefore(t *testing.T) {
	ctx := context.Background()
	store, err := db.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.InitSchema(ctx); err != nil {
		t.Fatalf("InitSchema() error = %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	hash, err := HashSecret("secret")
	if err != nil {
		t.Fatalf("HashSecret() error = %v", err)
	}
	notBefore := now.Add(time.Hour)
	if _, err := store.CreateUser(ctx, db.CreateUserParams{
		Username:    "future",
		DisplayName: "Future",
		Role:        domain.RoleReader,
		SecretHash:  hash,
		NotBefore:   &notBefore,
	}, now); err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}

	service := NewUserService(store)
	if _, err := service.Authenticate(ctx, "future", "secret", now); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials before notBefore, got %v", err)
	}
	if _, err := service.Authenticate(ctx, "future", "secret", notBefore.Add(time.Second)); err != nil {
		t.Fatalf("expected user to work after notBefore, got %v", err)
	}
}

func TestCreateUserIssuesSecret(t *testing.T) {
	ctx := context.Background()
	store, err := db.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.InitSchema(ctx); err != nil {
		t.Fatalf("InitSchema() error = %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	service := NewUserService(store)
	user, secret, err := service.CreateUser(ctx, db.CreateUserParams{Username: "customer-a", DisplayName: "Customer A", Role: domain.RoleReader}, now)
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	if secret == "" || user.SecretHash == "" {
		t.Fatalf("expected issued secret and stored hash, got user=%#v secret=%q", user, secret)
	}
	if _, err := service.Authenticate(ctx, "customer-a", secret, now); err != nil {
		t.Fatalf("Authenticate() with issued secret error = %v", err)
	}
}
