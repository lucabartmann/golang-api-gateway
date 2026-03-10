package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

const (
	headerUserID     = "X-User-ID"
	headerUserScopes = "X-User-Scopes"
	headerRequestID  = "X-Request-Id"
)

// Middleware extracts the identity headers injected by the gateway and stores
// them in the request context. It must be the first middleware in the chain of
// every upstream service.
//
// IMPORTANT: only trust these headers when the service is reachable exclusively
// through the gateway (enforced via Kubernetes NetworkPolicy). Any caller with
// direct access to the service can forge these headers.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := &Identity{
			UserID:    r.Header.Get(headerUserID),
			Scopes:    parseScopes(r.Header.Get(headerUserScopes)),
			RequestID: r.Header.Get(headerRequestID),
		}
		ctx := context.WithValue(r.Context(), contextKey{}, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Require returns a middleware that enforces the presence of every listed scope
// on the request identity. Responds 401 if unauthenticated, 403 if a scope is
// missing. Must be used after Middleware in the chain.
//
//	r.With(gateway.Require("read:users")).Get("/users", listUsers)
func Require(scopes ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, ok := FromContext(r.Context())
			if !ok || !id.IsAuthenticated() {
				writeJSON(w, http.StatusUnauthorized, "unauthenticated")
				return
			}
			for _, scope := range scopes {
				if !id.HasScope(scope) {
					writeJSON(w, http.StatusForbidden, "missing scope: "+scope)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAuthenticated returns a middleware that enforces the presence of any
// authenticated identity, without checking specific scopes. Use when a route
// just needs a logged-in user, not a particular permission.
//
//	r.With(gateway.RequireAuthenticated()).Get("/profile", getProfile)
func RequireAuthenticated() func(http.Handler) http.Handler {
	return Require() // no scopes = only checks authentication
}

func parseScopes(raw string) []string {
	if raw == "" {
		return nil
	}
	return strings.Fields(raw)
}

func writeJSON(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
