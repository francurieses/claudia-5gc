package server

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"

	"github.com/francurieses/claudia-5gc/nf/sepp/internal/config"
	"github.com/francurieses/claudia-5gc/nf/sepp/internal/n32trust"
)

// N32TLS is the local N32 certificate and the per-PLMN peer verifier shared by
// the N32 listener, the N32-c initiator and the N32-f outbound transport.
type N32TLS struct {
	Cert     tls.Certificate
	Verifier *n32trust.Verifier
}

// ClientTLSConfig is the outbound N32 TLS config (per-PLMN server verification).
func (t *N32TLS) ClientTLSConfig() *tls.Config {
	return t.Verifier.ClientTLSConfig(t.Cert, n32MinTLSVersion, nil)
}

// LoadN32TLS builds the N32 trust material from the configuration: the
// partner anchors (never the SBI CA) and the local N32 certificate, whose SAN
// must name the local SEPP FQDN. With no partners and no local certificate it
// returns (nil, nil): the N32 listener is simply not started. Partners without
// a local certificate, an unreadable anchor or a wrong SAN are errors (fatal at
// startup). Ref: TS 33.501 §13.1, docs/procedures/N32InteropReadiness.md §6 E12.
func LoadN32TLS(cfg *config.Config, logger *slog.Logger) (*N32TLS, error) {
	partners := cfg.N32Partners()
	v, err := n32trust.NewVerifier(partners, logger, cfg.SBI.TLS.CAFile)
	if err != nil {
		return nil, fmt.Errorf("sepp: n32 trust: %w", err)
	}
	cert, err := n32trust.LoadLocalCert(cfg.N32.TLS.CertFile, cfg.N32.TLS.KeyFile, cfg.SBI.FQDN)
	if errors.Is(err, n32trust.ErrNoLocalCert) {
		if len(partners) > 0 {
			return nil, fmt.Errorf("sepp: n32 trust: partners are configured but n32.tls.cert_file/n32.tls.key_file are missing (no fallback to sbi.tls): %w", err)
		}
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("sepp: n32 trust: %w", err)
	}
	return &N32TLS{Cert: cert, Verifier: v}, nil
}
