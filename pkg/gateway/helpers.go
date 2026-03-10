package gateway

import "context"

// UserID returns the authenticated user's ID from context, or "" if absent.
// Convenience wrapper to avoid the two-value FromContext call in service code.
func UserID(ctx context.Context) string {
	id, ok := FromContext(ctx)
	if !ok {
		return ""
	}
	return id.UserID
}

// RequestID returns the gateway-assigned request ID from context, or "".
// Use this when propagating the correlation ID to outbound calls or log lines.
func RequestID(ctx context.Context) string {
	id, ok := FromContext(ctx)
	if !ok {
		return ""
	}
	return id.RequestID
}

// CheckScope returns ErrUnauthenticated or ErrForbidden if the context identity
// does not satisfy the required scope. Returns nil if the check passes.
// Use in service-layer code that cannot depend on http.Handler middleware.
//
//	func (s *OrderService) Cancel(ctx context.Context, orderID string) error {
//	    if err := gateway.CheckScope(ctx, "write:orders"); err != nil {
//	        return err
//	    }
//	    ...
//	}
func CheckScope(ctx context.Context, scope string) error {
	id, ok := FromContext(ctx)
	if !ok || !id.IsAuthenticated() {
		return ErrUnauthenticated
	}
	if !id.HasScope(scope) {
		return ErrForbidden
	}
	return nil
}
