package httpserver

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	authIPAttempts      = 60
	authAccountAttempts = 20
	authAttemptWindow   = time.Minute
	authVerifyWorkers   = 4
)

type authAttemptWindowState struct {
	count int
	reset time.Time
}

type authAttemptLimiter struct {
	mu      sync.Mutex
	windows map[string]authAttemptWindowState
	verify  chan struct{}
	now     func() time.Time
	nextGC  time.Time
}

func newAuthAttemptLimiter() *authAttemptLimiter {
	return &authAttemptLimiter{
		windows: make(map[string]authAttemptWindowState),
		verify:  make(chan struct{}, authVerifyWorkers),
		now:     time.Now,
	}
}

func (l *authAttemptLimiter) allow(ipAddress, username string) (time.Duration, bool) {
	now := l.now()
	keys := []struct {
		value string
		limit int
	}{{value: "ip:" + ipAddress, limit: authIPAttempts}}
	if username = strings.ToLower(strings.TrimSpace(username)); username != "" {
		keys = append(keys, struct {
			value string
			limit int
		}{value: "account:" + username, limit: authAccountAttempts})
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.nextGC.After(now) {
		for key, window := range l.windows {
			if !window.reset.After(now) {
				delete(l.windows, key)
			}
		}
		l.nextGC = now.Add(authAttemptWindow)
	}
	for _, key := range keys {
		window := l.windows[key.value]
		if !window.reset.After(now) {
			continue
		}
		if window.count >= key.limit {
			return window.reset.Sub(now), false
		}
	}
	for _, key := range keys {
		window := l.windows[key.value]
		if !window.reset.After(now) {
			window = authAttemptWindowState{reset: now.Add(authAttemptWindow)}
		}
		window.count++
		l.windows[key.value] = window
	}
	return 0, true
}

func (l *authAttemptLimiter) acquireVerification() (func(), bool) {
	select {
	case l.verify <- struct{}{}:
		return func() { <-l.verify }, true
	default:
		return nil, false
	}
}

func writeAuthRateLimited(w http.ResponseWriter, retryAfter time.Duration) {
	seconds := int(retryAfter.Round(time.Second).Seconds())
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	writeError(w, http.StatusTooManyRequests, "too many authentication attempts")
}
