package auth

import "testing"

func TestHashAndVerifySecret(t *testing.T) {
	hash, err := HashSecret("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashSecret() error = %v", err)
	}
	matches, err := VerifySecret("correct horse battery staple", hash)
	if err != nil {
		t.Fatalf("VerifySecret() error = %v", err)
	}
	if !matches {
		t.Fatal("expected secret to match")
	}
	matches, err = VerifySecret("wrong", hash)
	if err != nil {
		t.Fatalf("VerifySecret() wrong secret error = %v", err)
	}
	if matches {
		t.Fatal("expected wrong secret not to match")
	}
}

func TestGenerateSecretReturnsOpaqueValue(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret() error = %v", err)
	}
	if len(secret) < 32 {
		t.Fatalf("generated secret too short: %d", len(secret))
	}
}
