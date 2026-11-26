package server

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"

	"golang.org/x/net/http2"

	"github.com/francurieses/claudia-5gc/nf/sepp/internal/config"
	"github.com/francurieses/claudia-5gc/nf/sepp/internal/n32trust"
)

// peerIdentityTransport routes each partner n32.address to a dedicated HTTP/2
// transport whose TLS ServerName is the partner SEPP FQDN, so the peer
// certificate is verified (per-PLMN anchor, SAN, dialled PLMN: n32trust)
// against that FQDN while the connection is dialled to the address. Other hosts use the base transport.
// Ref: TS 33.501 §13.1.2 (mutual authentication of SEPPs), RFC 6125.
type peerIdentityTransport struct {
	base  http.RoundTripper
	peers map[string]*http2.Transport // keyed by URL host (host:port)
}

// NewPeerIdentityClient returns a copy of base whose transport verifies every
// partner address against the partner SEPP FQDN. base.Transport must be an
// *http2.Transport (as returned by sbi.NewMTLSClient).
func NewPeerIdentityClient(base *http.Client, peers []config.Partner) (*http.Client, error) {
	bt, ok := base.Transport.(*http2.Transport)
	if !ok || bt.TLSClientConfig == nil {
		return nil, errors.New("sepp: peer identity client: base transport must be *http2.Transport with TLS config")
	}
	pt := &peerIdentityTransport{base: bt, peers: make(map[string]*http2.Transport, len(peers))}
	for _, p := range peers {
		if p.N32.Address == "" {
			return nil, fmt.Errorf("sepp: peer identity client: partner %s has no address", p.PLMN)
		}
		tc := bt.TLSClientConfig.Clone()
		tc.ServerName = p.FQDN()
		pt.peers[p.N32.Address] = &http2.Transport{
			TLSClientConfig: tc,
			ReadIdleTimeout: bt.ReadIdleTimeout,
			PingTimeout:     bt.PingTimeout,
		}
	}
	c := *base
	c.Transport = pt
	return &c, nil
}

// RoundTrip implements http.RoundTripper.
func (t *peerIdentityTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if pt, ok := t.peers[r.URL.Host]; ok {
		return pt.RoundTrip(r)
	}
	return t.base.RoundTrip(r)
}

// CloseIdleConnections closes idle connections of every transport.
func (t *peerIdentityTransport) CloseIdleConnections() {
	for _, pt := range t.peers {
		pt.CloseIdleConnections()
	}
	if c, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}

// isCertIdentityError reports a TLS certificate verification failure
// (hostname/SAN mismatch, unknown authority, invalid chain, n32trust reject): not retryable.
func isCertIdentityError(err error) bool {
	var cv *tls.CertificateVerificationError
	var rj *n32trust.RejectError
	return errors.As(err, &cv) || errors.As(err, &rj)
}
