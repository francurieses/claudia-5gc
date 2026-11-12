// Package server — construction of the NEF outbound SBI HTTP client.
//
// Kept out of cmd/nef so the ES3XX redirect policy installation is covered by
// a test (removing it must fail a test).
//
// Ref: TS 29.500 §4.4.1 (mTLS), §6.10.9.1 (307/308 redirection)
package server

import (
	"log/slog"
	"net/http"

	"github.com/francurieses/claudia-5gc/shared/sbi"
)

// NewOutboundClient builds the HTTP/2 client used for outbound NRF, BSF and PCF
// calls: mTLS when certFile and keyFile are set, else TLS-with-CA / h2c (dev
// and functional-test mode). On a build error it returns a copy of
// http.DefaultClient together with the error so callers may log and continue.
// In every case the TS 29.500 §6.10.9.1 redirect policy (follow 307/308 only;
// ES3XX consumer behaviour, not profile-gated) is installed before the client
// is shared.
func NewOutboundClient(caFile, certFile, keyFile string, logger *slog.Logger) (*http.Client, error) {
	var (
		c   *http.Client
		err error
	)
	if certFile != "" && keyFile != "" {
		c, err = sbi.NewMTLSClient(caFile, certFile, keyFile)
	} else {
		c, err = sbi.NewHTTP2Client(caFile)
	}
	if err != nil {
		// Copy, never mutate the process-wide http.DefaultClient.
		dc := *http.DefaultClient
		c = &dc
	}
	sbi.ApplyRedirectPolicy(c, logger, sbi.WithNF("NEF"))
	return c, err
}
