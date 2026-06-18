// Package sbi provides shared utilities for the Service Based Interface (SBA).
package sbi

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"golang.org/x/net/http2"
)

// NewHTTP2Client returns an *http.Client configured for HTTP/2 over TLS.
// caFile is the path to the PEM-encoded CA certificate used to verify server
// certificates. If caFile is empty, it falls back to H2C (cleartext HTTP/2 for dev).
// Returns error if caFile is non-empty but unreadable or contains no valid certs.
func NewHTTP2Client(caFile string) (*http.Client, error) {
	// If no CA cert provided, use H2C for local dev
	if caFile == "" {
		slog.Default().Warn("NewHTTP2Client: no ca_file provided, using H2C cleartext (DEV ONLY)")
		return NewH2CClient(), nil
	}

	// Load CA certificate
	caData, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read ca cert: %w", err)
	}

	// Build CA cert pool
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caData) {
		return nil, fmt.Errorf("parse ca cert: no certificates found in %s", caFile)
	}

	// Configure TLS
	tlsCfg := &tls.Config{
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS13,
		KeyLogWriter: OpenKeyLogWriter(),
	}

	// Configure HTTP/2 transport with TLS
	transport := &http2.Transport{
		TLSClientConfig: tlsCfg,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}, nil
}

// NewMTLSClient returns an *http.Client configured for mutual TLS (mTLS).
// caFile is the CA cert used to verify the server certificate.
// certFile and keyFile are the client certificate and key for mTLS.
// Ref: TS 33.501 §13 — SBA security (TLS with client authentication).
func NewMTLSClient(caFile, certFile, keyFile string) (*http.Client, error) {
	caData, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read ca cert: %w", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caData) {
		return nil, fmt.Errorf("parse ca cert: no certificates found in %s", caFile)
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load client cert: %w", err)
	}
	tlsCfg := &tls.Config{
		RootCAs:      caPool,
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		KeyLogWriter: OpenKeyLogWriter(),
	}
	return &http.Client{
		Transport: &http2.Transport{TLSClientConfig: tlsCfg},
		Timeout:   10 * time.Second,
	}, nil
}

// NewH2CClient returns an *http.Client using cleartext HTTP/2 (H2C).
// This should only be used in local development when TLS certificates are not available.
// The returned client is not suitable for production use.
func NewH2CClient() *http.Client {
	slog.Default().Warn("NewH2CClient: using cleartext HTTP/2 (DEV ONLY, not for production)")
	transport := &http2.Transport{
		AllowHTTP: true,
		DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
			return net.Dial(network, addr)
		},
	}
	return &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}
}
