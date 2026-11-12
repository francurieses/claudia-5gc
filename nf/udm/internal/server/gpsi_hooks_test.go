package server

import (
	"io"
	"log/slog"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/capability"
)

// newSDMGoldenUDMWith builds a UDM over an arbitrary UDR client.
func newSDMGoldenUDMWith(t *testing.T, p *capability.Profile, udr UDRClient) *Server {
	t.Helper()
	s, err := New("127.0.0.1:0", "5G:mnc001.mcc001.3gppnetwork.org", TLSConfig{}, udr,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if p != nil {
		s.SetProfile(p)
	}
	return s
}
