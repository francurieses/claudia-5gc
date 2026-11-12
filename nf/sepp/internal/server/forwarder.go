package server

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"

	"github.com/francurieses/claudia-5gc/nf/sepp/internal/config"
	"github.com/francurieses/claudia-5gc/nf/sepp/internal/n32c"
	"github.com/francurieses/claudia-5gc/nf/sepp/internal/n32f"
	"github.com/francurieses/claudia-5gc/shared/sbi"
)

// NewForwarder builds the N32-f forwarder from the SEPP configuration:
// SEPPFQDN = sbi.fqdn, topology hiding per n32.topology_hiding (default on), mTLS towards the peer SEPP with the
// N32 trust material (n32.tls, falling back to sbi.tls) and mTLS towards local
// NFs with sbi.tls; local NFs are resolved through the NRF.
// Ref: TS 29.573 §5.3, TS 23.003 §28.5.2, TS 33.501 §13.1.
func NewForwarder(cfg *config.Config, store *n32c.Store, disc n32f.Discoverer, logger *slog.Logger) (*n32f.Forwarder, error) {
	f := cfg.N32TLS()
	cert, err := tls.LoadX509KeyPair(f.CertFile, f.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("sepp: new forwarder: load N32 cert: %w", err)
	}
	caPEM, err := os.ReadFile(f.CAFile)
	if err != nil {
		return nil, fmt.Errorf("sepp: new forwarder: load N32 CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("sepp: new forwarder: N32 CA file %q has no valid certificate", f.CAFile)
	}
	n32t, err := n32f.NewN32Transport(&tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool, MinVersion: n32MinTLSVersion,
		// No-op unless SSLKEYLOGFILE is set (opt-in pcap decryption, as in the other NFs).
		KeyLogWriter: sbi.OpenKeyLogWriter()})
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
