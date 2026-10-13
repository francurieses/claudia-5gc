package transport

import (
	"io"
	"log/slog"
	"testing"

	"github.com/francurieses/claudia-5gc/mcp/internal/config"
	"github.com/francurieses/claudia-5gc/mcp/internal/guard"
)

func newAuthSSE(auth config.Auth) *SSE {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return &SSE{cfg: &config.Config{Auth: auth}, logger: logger}
}

func TestResolveRoleAuthDisabledIsOperator(t *testing.T) {
	s := newAuthSSE(config.Auth{})
	role, ok := s.resolveRole("")
	if !ok || role != guard.RoleOperator {
		t.Errorf("auth disabled: got (%q,%v), want (operator,true)", role, ok)
	}
}

func TestResolveRoleMapsTokens(t *testing.T) {
	s := newAuthSSE(config.Auth{
		BearerToken: "op",
		Tokens: []config.AuthToken{
			{Token: "view", Role: "viewer"},
			{Token: "root", Role: "admin"},
		},
	})
	cases := map[string]guard.Role{
		"Bearer op":   guard.RoleOperator,
		"Bearer view": guard.RoleViewer,
		"Bearer root": guard.RoleAdmin,
	}
	for header, want := range cases {
		got, ok := s.resolveRole(header)
		if !ok || got != want {
			t.Errorf("%q: got (%q,%v), want %q", header, got, ok, want)
		}
	}
}

func TestResolveRoleRejectsMissingOrWrongToken(t *testing.T) {
	s := newAuthSSE(config.Auth{BearerToken: "op"})
	for _, header := range []string{"", "op", "Bearer", "Bearer nope", "Basic op"} {
		if _, ok := s.resolveRole(header); ok {
			t.Errorf("%q must be rejected", header)
		}
	}
}
