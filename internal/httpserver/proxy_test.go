package httpserver

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"simplecontainerregistry/internal/config"
)

func TestTrustedProxyForwardedClientAddress(t *testing.T) {
	cfg := config.Default()
	cfg.HTTP.TrustForwardedHeaders = true
	cfg.HTTP.TrustedProxyCIDRs = []string{"10.0.0.0/8"}
	cfg.HTTP.PublicURL = "https://registry.example.test"
	server := &Server{cfg: cfg}

	trusted := httptest.NewRequest(http.MethodGet, "/", nil)
	trusted.RemoteAddr = "10.1.2.3:443"
	trusted.Header.Set("X-Forwarded-For", "198.51.100.7, 10.1.2.3")
	if got := server.requestIP(trusted); got != "198.51.100.7" {
		t.Fatalf("trusted proxy client IP = %q, want %q", got, "198.51.100.7")
	}

	untrusted := httptest.NewRequest(http.MethodGet, "/", nil)
	untrusted.RemoteAddr = "203.0.113.10:443"
	untrusted.Header.Set("X-Forwarded-For", "198.51.100.7")
	if got := server.requestIP(untrusted); got != "203.0.113.10" {
		t.Fatalf("untrusted proxy client IP = %q, want peer IP", got)
	}

	malformed := httptest.NewRequest(http.MethodGet, "/", nil)
	malformed.RemoteAddr = "not-a-remote-address"
	malformed.Header.Set("X-Real-IP", "198.51.100.7")
	if got := server.requestIP(malformed); got != "not-a-remote-address" {
		t.Fatalf("malformed remote client IP = %q, want remote address", got)
	}
}

func TestTrustedProxyForwardedClientAddressSkipsAttackerAndProxyAddresses(t *testing.T) {
	cfg := config.Default()
	cfg.HTTP.TrustForwardedHeaders = true
	cfg.HTTP.TrustedProxyCIDRs = []string{"10.0.0.0/8", "fd00::/8"}
	server := &Server{cfg: cfg}

	tests := []struct {
		name string
		xff  string
		want string
	}{
		{"trusted proxy appends client after attacker value", "203.0.113.200, 198.51.100.7", "198.51.100.7"},
		{"multiple proxies", "203.0.113.200, 198.51.100.7, 10.2.3.4, fd00::4", "198.51.100.7"},
		{"only trusted or malformed values falls back to peer", "malformed, 10.2.3.4, fd00::4", "10.1.2.3"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			request.RemoteAddr = "10.1.2.3:443"
			request.Header.Set("X-Forwarded-For", test.xff)
			if got := server.requestIP(request); got != test.want {
				t.Fatalf("client IP = %q, want %q", got, test.want)
			}
		})
	}
}

func TestChallengeRealmUsesCanonicalURLAndDirectFallback(t *testing.T) {
	cfg := config.Default()
	cfg.HTTP.PublicURL = "https://registry.example.test"
	cfg.HTTP.TrustForwardedHeaders = true
	cfg.HTTP.TrustedProxyCIDRs = []string{"10.0.0.0/8"}
	server := &Server{cfg: cfg}
	request := httptest.NewRequest(http.MethodGet, "http://internal.example/v2/", nil)
	request.RemoteAddr = "10.1.2.3:443"
	request.Header.Set("X-Forwarded-Host", "attacker.example")
	request.Header.Set("X-Forwarded-Proto", "http")
	response := httptest.NewRecorder()
	server.challenge(response, request, "")
	if got := response.Header().Get("WWW-Authenticate"); got != `Bearer realm="https://registry.example.test/token",service="scr"` {
		t.Fatalf("canonical challenge = %q", got)
	}

	directCfg := config.Default()
	direct := &Server{cfg: directCfg}
	directRequest := httptest.NewRequest(http.MethodGet, "http://registry.local/v2/", nil)
	directRequest.Host = "registry.local"
	directRequest.Header.Set("X-Forwarded-Host", "attacker.example")
	directRequest.Header.Set("X-Forwarded-Proto", "https")
	if got := direct.realm(directRequest); got != "http://registry.local/token" {
		t.Fatalf("direct fallback realm = %q", got)
	}
}
