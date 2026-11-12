package main

import (
	"io"
	"log/slog"
	"testing"

	"github.com/francurieses/claudia-5gc/nf/sepp/internal/config"
	"github.com/francurieses/claudia-5gc/nf/sepp/internal/server"
	"github.com/francurieses/claudia-5gc/shared/nrf"
)

func TestMountForwarderFailFast(t *testing.T) {
	lg := slog.New(slog.NewJSONHandler(io.Discard, nil))
	missing := func(cfg *config.Config) {
		cfg.SBI.TLS.CertFile, cfg.SBI.TLS.KeyFile, cfg.SBI.TLS.CAFile = "/nonexistent/c", "/nonexistent/k", "/nonexistent/ca"
	}
	tests := []struct {
		name    string
		mutate  func(*config.Config)
		nrf     bool
		wantErr bool
	}{
		{"no roaming, no NRF: warn only", func(c *config.Config) { missing(c) }, false, false},
		{"no roaming, no certs: warn only", func(c *config.Config) { missing(c) }, true, false},
		{"partners, no NRF: error", func(c *config.Config) {
			c.N32.RoamingPartners = []config.PLMN{{MCC: "001", MNC: "02"}}
		}, false, true},
		{"peers, no certs: error", func(c *config.Config) {
			missing(c)
			c.N32.Peers = []config.N32Peer{{PLMN: config.PLMN{MCC: "001", MNC: "02"}, FQDN: "p.example", Address: "p:8443"}}
		}, true, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CONFIG_PATH", t.TempDir()+"/absent.yaml")
			cfg, err := config.Load()
			if err != nil {
				t.Fatal(err)
			}
			tc.mutate(cfg)
			var nc *nrf.Client
			if tc.nrf {
				nc = nrf.New("https://nrf:8000", nil, lg)
			}
			err = mountForwarder(cfg, server.New(cfg, lg), nc, lg)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tc.wantErr)
			}
		})
	}
}
