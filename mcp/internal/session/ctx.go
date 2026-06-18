package session

import "context"

type ctxKey struct{}

// WithID attaches a session id to ctx so downstream code (the dispatcher, tool
// logging) can attribute work to a client session.
func WithID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// IDFrom returns the session id stored in ctx, or "" if absent.
func IDFrom(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKey{}).(string); ok {
		return v
	}
	return ""
}
