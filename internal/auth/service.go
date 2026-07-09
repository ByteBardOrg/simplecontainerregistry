package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"simplecontainerregistry/internal/db"
	"simplecontainerregistry/internal/domain"
)

var ErrInvalidCredentials = errors.New("invalid credentials")

type UserService struct {
	store *db.Store
}

type AuthenticatedUser struct {
	User domain.User
}

func NewUserService(store *db.Store) UserService {
	return UserService{store: store}
}

func (s UserService) Authenticate(ctx context.Context, username, secret string, now time.Time) (AuthenticatedUser, error) {
	user, err := s.store.GetUserByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return AuthenticatedUser{}, ErrInvalidCredentials
		}
		return AuthenticatedUser{}, err
	}
	if user.Status != domain.UserStatusActive {
		return AuthenticatedUser{}, ErrInvalidCredentials
	}
	if user.NotBefore != nil && user.NotBefore.After(now) {
		return AuthenticatedUser{}, ErrInvalidCredentials
	}
	if user.ExpiresAt != nil && !user.ExpiresAt.After(now) {
		return AuthenticatedUser{}, ErrInvalidCredentials
	}
	matches, err := VerifySecret(secret, user.SecretHash)
	if err != nil {
		return AuthenticatedUser{}, err
	}
	if !matches {
		return AuthenticatedUser{}, ErrInvalidCredentials
	}
	if err := s.store.UpdateUserLastUsed(ctx, user.ID, now); err != nil {
		return AuthenticatedUser{}, err
	}
	return AuthenticatedUser{User: user}, nil
}

func (s UserService) CreateUser(ctx context.Context, params db.CreateUserParams, now time.Time) (domain.User, string, error) {
	if params.NotBefore != nil && params.ExpiresAt != nil && !params.ExpiresAt.After(*params.NotBefore) {
		return domain.User{}, "", fmt.Errorf("expires at must be after valid from")
	}
	secret, err := GenerateSecret()
	if err != nil {
		return domain.User{}, "", err
	}
	hash, err := HashSecret(secret)
	if err != nil {
		return domain.User{}, "", err
	}
	params.SecretHash = hash
	user, err := s.store.CreateUser(ctx, params, now)
	if err != nil {
		return domain.User{}, "", err
	}
	return user, secret, nil
}

func BootstrapAdmin(ctx context.Context, store *db.Store, username, password string, now time.Time) error {
	if username == "" || password == "" {
		return fmt.Errorf("bootstrap admin username and password are required")
	}
	if _, err := store.GetUserByUsername(ctx, username); err == nil {
		return nil
	} else if !errors.Is(err, db.ErrNotFound) {
		return err
	}

	hash, err := HashSecret(password)
	if err != nil {
		return err
	}
	_, err = store.CreateUser(ctx, db.CreateUserParams{
		Username:    username,
		DisplayName: username,
		Role:        domain.RoleAdmin,
		SecretHash:  hash,
	}, now)
	return err
}
