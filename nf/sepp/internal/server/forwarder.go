package server

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/francurieses/claudia-5gc/nf/sepp/internal/config"
	"github.com/francurieses/claudia-5gc/nf/sepp/internal/n32c"
	"github.com/francurieses/claudia-5gc/nf/sepp/internal/n32f"
	"github.com/francurieses/claudia-5gc/shared/sbi"
)

// NewForwarder builds the N32-f forwarder from the SEPP configuration:
// SEPPFQDN = sbi.fqdn, topology hiding per n32.topology_hiding (default on), mTLS towards the peer SEPP with the
// local N32 certificate and the per-PLMN verifier of trust (never the SBI CA) and mTLS towards local
// NFs with sbi.tls; local NFs are resolved through the NRF.
// Ref: TS 29.573 §5.3, TS 23.003 §28.5.2, TS 33.501 §13.1.
func NewForwarder(cfg *config.Config, store *n32c.Store, disc n32f.Discoverer, trust *N32TLS, logger *slog.Logger) (*n32f.Forwarder, error) {
	if trust == nil {
		return nil, errors.New("sepp: new forwarder: no N32 TLS material")
	}
	tc := trust.Verifier.ClientTLSConfig(trust.Cert, n32MinTLSVersion,
		// No-op unless SSLKEYLOGFILE is set (opt-in pcap decryption, as in the other NFs).
		sbi.OpenKeyLogWriter())
	n32t, err := n32f.NewN32Transport(tc)
	if err != nil {
		return nil, fmt.Errorf("sepp: new forwarder: %w", err)
	}
	local, err := sbi.NewMTLSClient(cfg.SBI.TLS.CAFile, cfg.SBI.TLS.CertFile, cfg.SBI.TLS.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("sepp: new forwarder: local SBI client: %w", err)
	}
	fwd, err := n32f.New(n32f.Config{
		LocalPLMN:              n32c.PlmnId{Mcc: cfg.PLMN.MCC, Mnc: cfg.PLMN.MNC},
		SEPPFQDN:               cfg.SBI.FQDN,
		Store:                  store,
		TargetAPIRootSupported: cfg.N32.TargetAPIRootSupported,
		TopologyHiding:         cfg.TopologyHidingEnabled(),
		Transport:              n32t,
		LocalTransport:         local.Transport,
		Resolver:               n32f.NewNRFResolver(disc),
		Logger:                 logger,
	})
	if err != nil {
		return nil, fmt.Errorf("sepp: new forwarder: %w", err)
	}
	return fwd, nil
}
