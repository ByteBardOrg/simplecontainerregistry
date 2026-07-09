package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"simplecontainerregistry/internal/config"
	"simplecontainerregistry/internal/db"
	"simplecontainerregistry/internal/domain"
	"simplecontainerregistry/internal/ids"
)

type Claims struct {
	Username string        `json:"username"`
	Role     domain.Role   `json:"role"`
	Access   []AccessClaim `json:"access"`
	jwt.RegisteredClaims
}

type Principal struct {
	UserID   string
	Username string
	Role     domain.Role
	Access   []AccessClaim
}

type TokenService struct {
	store   *db.Store
	issuer  string
	service string
	ttl     time.Duration
}

func NewTokenService(store *db.Store, cfg config.AuthConfig) TokenService {
	return TokenService{
		store:   store,
		issuer:  cfg.Issuer,
		service: cfg.Service,
		ttl:     cfg.TokenTTL.Std(),
	}
}

func (s TokenService) Mint(ctx context.Context, user domain.User, access []AccessClaim, now time.Time) (string, time.Time, error) {
	key, err := s.store.ActiveSigningKey(ctx)
	if err != nil {
		return "", time.Time{}, err
	}
	jti, err := ids.New("tok")
	if err != nil {
		return "", time.Time{}, err
	}
	expiresAt := now.Add(s.ttl)
	claims := Claims{
		Username: user.Username,
		Role:     user.Role,
		Access:   access,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   user.ID,
			Audience:  jwt.ClaimStrings{s.service},
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(now.Add(-5 * time.Second)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        jti,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["kid"] = key.ID
	signed, err := token.SignedString(key.Secret)
	if err != nil {
		return "", time.Time{}, err
	}
	return signed, expiresAt, nil
}

func (s TokenService) Validate(ctx context.Context, raw string) (Principal, error) {
	key, err := s.store.ActiveSigningKey(ctx)
	if err != nil {
		return Principal{}, err
	}

	claims := Claims{}
	token, err := jwt.ParseWithClaims(raw, &claims, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method %s", token.Method.Alg())
		}
		return key.Secret, nil
	}, jwt.WithAudience(s.service), jwt.WithIssuer(s.issuer))
	if err != nil {
		return Principal{}, err
	}
	if !token.Valid {
		return Principal{}, fmt.Errorf("invalid token")
	}
	user, err := s.store.GetUser(ctx, claims.Subject)
	if err != nil {
		return Principal{}, err
	}
	if user.Status != domain.UserStatusActive {
		return Principal{}, fmt.Errorf("user is not active")
	}
	now := time.Now().UTC()
	if user.NotBefore != nil && user.NotBefore.After(now) {
		return Principal{}, fmt.Errorf("user is not valid yet")
	}
	if user.ExpiresAt != nil && !user.ExpiresAt.After(now) {
		return Principal{}, fmt.Errorf("user is expired")
	}
	return Principal{
		UserID:   user.ID,
		Username: user.Username,
		Role:     user.Role,
		Access:   claims.Access,
	}, nil
}

func (s TokenService) TTLSeconds() int {
	return int(s.ttl.Seconds())
}
