package httpserver

import (
	"testing"
	"time"
)

func TestAuthAttemptLimiterLimitsAccountsAndResets(t *testing.T) {
	limiter := newAuthAttemptLimiter()
	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	limiter.now = func() time.Time { return now }

	for range authAccountAttempts {
		if _, allowed := limiter.allow("192.0.2.1", "admin"); !allowed {
			t.Fatal("expected authentication attempt within account limit")
		}
	}
	retryAfter, allowed := limiter.allow("192.0.2.1", "ADMIN")
	if allowed || retryAfter != authAttemptWindow {
		t.Fatalf("expected normalized account to be limited for %s, allowed=%v", authAttemptWindow, allowed)
	}

	now = now.Add(authAttemptWindow)
	if _, allowed := limiter.allow("192.0.2.1", "admin"); !allowed {
		t.Fatal("expected authentication limit to reset")
	}
}

func TestAuthAttemptLimiterBoundsConcurrentVerification(t *testing.T) {
	limiter := newAuthAttemptLimiter()
	releases := make([]func(), 0, authVerifyWorkers)
	for range authVerifyWorkers {
		release, acquired := limiter.acquireVerification()
		if !acquired {
			t.Fatal("expected verification worker slot")
		}
		releases = append(releases, release)
	}
	if _, acquired := limiter.acquireVerification(); acquired {
		t.Fatal("expected verification beyond worker limit to be rejected")
	}
	for _, release := range releases {
		release()
	}
	if release, acquired := limiter.acquireVerification(); !acquired {
		t.Fatal("expected released verification slot to be reusable")
	} else {
		release()
	}
}
