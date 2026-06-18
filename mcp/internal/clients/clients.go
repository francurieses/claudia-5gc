// Package clients holds thin HTTP wrappers the MCP tools use to reach upstream
// 5G core services: the NRF SBI (mTLS HTTP/2), the AMF management API and the
// Jaeger/Prometheus query APIs (plain HTTP). Network logic lives here so the
// tool packages stay focused on shaping MCP input/output.
package clients

import (
	"net/http"
	"time"

	"github.com/francurieses/claudia-5gc/shared/sbi"
)

// NewSBIClient builds the HTTP client used to reach the NRF SBI. It selects
// mTLS when a client certificate is configured, server-auth TLS when only a CA
// is set, and H2C cleartext otherwise (dev). Mirrors the NF→NF posture.
func NewSBIClient(caFile, certFile, keyFile string) (*http.Client, error) {
	switch {
	case certFile != "" && keyFile != "":
		return sbi.NewMTLSClient(caFile, certFile, keyFile)
	default:
		return sbi.NewHTTP2Client(caFile)
	}
}

// NewPlainClient returns a standard HTTP client for plain-HTTP upstreams (the
// AMF management API, Jaeger and Prometheus query APIs).
func NewPlainClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Second}
}
