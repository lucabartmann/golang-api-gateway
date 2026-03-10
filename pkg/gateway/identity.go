// Package gateway provides a client library for services running behind the
// golang-api-gateway. It extracts the identity headers the gateway injects
// after successful JWT validation and exposes them via a typed context value.
//
// Typical usage in an upstream service:
//
//	r.Use(gateway.Middleware)
//	r.With(gateway.Require("write:orders")).Post("/orders", createOrder)
//
//	func createOrder(w http.ResponseWriter, r *http.Request) {
//	    id := gateway.MustFromContext(r.Context())
//	    // id.UserID, id.Scopes, id.RequestID are all populated
//	}
package gateway

import (
	"context"
	"errors"
)

type contextKey struct{}

// Identity holds the caller information forwarded by the gateway after a
// successful JWT validation. All fields are empty strings / nil slices if the
// request did not pass through the gateway auth middleware (e.g. public routes).
type Identity struct {
	// UserID is the JWT subject claim (Auth0: "auth0|<id>").
	UserID string

	// Scopes is the list of OAuth2 scopes granted to the token.
	Scopes []string

	// RequestID is the X-Request-Id set by the gateway for log correlation.
	RequestID string
}

// HasScope reports whether the identity holds the given scope.
func (id *Identity) HasScope(scope string) bool {
	for _, s := range id.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// HasAllScopes reports whether the identity holds every one of the given scopes.
func (id *Identity) HasAllScopes(scopes ...string) bool {
	for _, s := range scopes {
		if !id.HasScope(s) {
			return false
		}
	}
	return true
}

// IsAuthenticated reports whether the identity carries a non-empty user ID,
// i.e. the request passed through the gateway auth middleware.
func (id *Identity) IsAuthenticated() bool {
	return id.UserID != ""
}

// FromContext retrieves the Identity stored by Middleware.
// Returns (nil, false) if the context carries no identity.
func FromContext(ctx context.Context) (*Identity, bool) {
	id, ok := ctx.Value(contextKey{}).(*Identity)
	return id, ok
}

// MustFromContext retrieves the Identity stored by Middleware.
// Panics if no identity is present — use only in handlers guarded by Middleware.
func MustFromContext(ctx context.Context) *Identity {
	id, ok := FromContext(ctx)
	if !ok {
		panic("gateway: identity not found in context — is gateway.Middleware installed?")
	}
	return id
}

// ErrUnauthenticated is returned by operations that require an authenticated identity.
var ErrUnauthenticated = errors.New("gateway: request is not authenticated")

// ErrForbidden is returned when the identity lacks a required scope.
var ErrForbidden = errors.New("gateway: insufficient scopes")
