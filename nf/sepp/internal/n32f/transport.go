package n32f

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/http2"
)

const (
	// DialTimeout bounds the TCP+TLS connect to the peer SEPP (implementation limit).
	DialTimeout = 5 * time.Second
	// transportIdleConnTimeout closes idle N32-f connections (implementation limit).
	transportIdleConnTimeout = 90 * time.Second
	// transportMaxConnsPerHost bounds parallel N32-f connections per peer.
	transportMaxConnsPerHost = 16
)

// peerDial tells the N32 transport where to connect and which name to verify.
// Without it the transport refuses to dial, so a request can never reach an
// address that did not come from an N32 context.
type peerDial struct {
	addr       string // host:port of the peer SEPP N32 listener
	serverName string // peer SEPP FQDN verified against its certificate
}

type peerKey struct{}

// NewN32Transport returns the outbound N32-f transport: HTTP/2 over mutual
// TLS. tlsCfg must carry a client certificate (TS 33.501 §13.1.2: N32 is
// always mutually authenticated); NextProtos is forced to h2.
func NewN32Transport(tlsCfg *tls.Config) (*http.Transport, error) {
	if tlsCfg == nil || (len(tlsCfg.Certificates) == 0 && tlsCfg.GetClientCertificate == nil) {
		return nil, errors.New("n32f: new transport: a client certificate is required (mTLS)")
	}
	if tlsCfg.InsecureSkipVerify {
		return nil, errors.New("n32f: new transport: InsecureSkipVerify is not allowed")
	}
	if tlsCfg.RootCAs == nil {
		return nil, errors.New("n32f: new transport: RootCAs (N32 trust anchors) are required")
	}
	base := tlsCfg.Clone()
	base.NextProtos = []string{"h2"}
	if base.MinVersion == 0 {
		base.MinVersion = tls.VersionTLS12 // TS 33.210 §6.2 (TLS 1.2 and 1.3)
	}
	t := &http.Transport{
		IdleConnTimeout:     transportIdleConnTimeout,
		MaxConnsPerHost:     transportMaxConnsPerHost,
		TLSHandshakeTimeout: DialTimeout,
		ForceAttemptHTTP2:   true,
		DialTLSContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			p, ok := ctx.Value(peerKey{}).(peerDial)
			if !ok {
				return nil, errors.New("n32f: dial: no N32 context for this request")
			}
			cfg := base.Clone()
			cfg.ServerName = p.serverName
			d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: DialTimeout}, Config: cfg}
			return d.DialContext(ctx, network, p.addr)
		},
	}
	if _, err := http2.ConfigureTransports(t); err != nil {
		return nil, err
	}
	return t, nil
}
