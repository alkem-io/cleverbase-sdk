package httpapi

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// authMiddleware enforces a bearer API key on /v1/sign/* when auth is enabled (the default). Health
// endpoints are always open for orchestration probes. Rejection happens before any signing work.
func (s *Service) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.Profile.AuthEnabled || r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			next.ServeHTTP(w, r)
			return
		}
		const prefix = "Bearer "
		auth := r.Header.Get("Authorization")
		token := strings.TrimPrefix(auth, prefix)
		// Fail closed: a misconfigured empty APIKey must never authenticate, or the constant-time
		// compare of ""=="" would accept "Authorization: Bearer " (an empty token) and turn the
		// default-on gate into a bypass. config.Load already requires a key in live mode; this is
		// defense in depth at the gate itself.
		if s.Profile.APIKey == "" ||
			!strings.HasPrefix(auth, prefix) ||
			subtle.ConstantTimeCompare([]byte(token), []byte(s.Profile.APIKey)) != 1 {
			writeErr(w, http.StatusUnauthorized, "unauthorized", "missing or invalid API key")
			return
		}
		next.ServeHTTP(w, r)
	})
}
