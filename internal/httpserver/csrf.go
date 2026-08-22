package httpserver

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
)

const csrfFormField = "_csrf"

func csrfToken(sessionToken string) string {
	digest := sha256.Sum256([]byte("scr-csrf:" + sessionToken))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func (s *Server) requireUIAdminMutation(next http.HandlerFunc) http.HandlerFunc {
	return s.requireUIAdmin(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			writeError(w, http.StatusBadRequest, "invalid form submission")
			return
		}
		cookie, err := r.Cookie(adminCookieName)
		if err != nil {
			writeError(w, http.StatusForbidden, "invalid CSRF token")
			return
		}
		expected := csrfToken(cookie.Value)
		provided := r.Header.Get("X-CSRF-Token")
		if provided == "" {
			provided = r.FormValue(csrfFormField)
		}
		if len(provided) != len(expected) || subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) != 1 {
			writeError(w, http.StatusForbidden, "invalid CSRF token")
			return
		}
		next(w, r)
	})
}
