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

type remoteKey struct{}

// WithRemoteAddr attaches the caller's remote IP to ctx. Only the connection's own
// address is used: forwarding headers are never trusted.
func WithRemoteAddr(ctx context.Context, addr string) context.Context {
	return context.WithValue(ctx, remoteKey{}, addr)
}

// RemoteAddrFrom returns the remote IP stored in ctx, or "" if absent.
func RemoteAddrFrom(ctx context.Context) string {
	if v, ok := ctx.Value(remoteKey{}).(string); ok {
		return v
	}
	return ""
}

// Label is the audit/log label of the caller: the session id when there is one,
// "http:<ip>" for a stateless HTTP call with a known remote address, otherwise "stdio".
func Label(ctx context.Context) string {
	if id := IDFrom(ctx); id != "" {
		return id
	}
	if ra := RemoteAddrFrom(ctx); ra != "" {
		return "http:" + ra
	}
	return "stdio"
}
