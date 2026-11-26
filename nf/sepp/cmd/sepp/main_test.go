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
	partner := func(cfg *config.Config) {
		cfg.N32.Partners = []config.Partner{{PLMN: config.PLMN{MCC: "001", MNC: "02"},
			N32: config.PartnerN32{CAFile: "/x", Address: "p:8443"}}}
	}
	tests := []struct {
		name    string
		mutate  func(*config.Config)
		nrf     bool
		n32tls  *server.N32TLS
		wantErr bool
	}{
		{"no partners, no N32 TLS: nothing mounted", func(c *config.Config) { missing(c) }, true, nil, false},
		{"no partners, N32 TLS, no NRF: info only", func(c *config.Config) {}, false, &server.N32TLS{}, false},
		{"no partners, N32 TLS, forwarder unbuildable: info only", func(c *config.Config) { missing(c) }, true, &server.N32TLS{}, false},
		{"partners, no NRF: error", partner, false, &server.N32TLS{}, true},
		{"partners, forwarder unbuildable: error", func(c *config.Config) { missing(c); partner(c) }, true, &server.N32TLS{}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CONFIG_PATH", t.TempDir()+"/absent.yaml")
			t.Setenv(config.PartnersFileEnv, t.TempDir()+"/absent-partners.yaml")
			cfg, err := config.Load()
			if err != nil {
				t.Fatal(err)
			}
			tc.mutate(cfg)
			var nc *nrf.Client
			if tc.nrf {
				nc = nrf.New("https://nrf:8000", nil, lg)
			}
			err = mountForwarder(cfg, server.New(cfg, lg), nc, tc.n32tls, lg)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tc.wantErr)
			}
		})
	}
}
