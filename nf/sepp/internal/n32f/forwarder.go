package n32f

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/francurieses/claudia-5gc/nf/sepp/internal/n32c"
	"github.com/francurieses/claudia-5gc/shared/logging"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

const (
	// procedureName is the canonical log/metric procedure for N32-f forwarding.
	procedureName = "N32fMessageForwarding"
	// interfaceN32f is the canonical log interface value.
	interfaceN32f = "N32f"

	// HeaderTargetAPIRoot carries the apiRoot of the target NF.
	// Ref: TS 29.500 §5.2.3.2.4, §6.1.4.3.3.
	HeaderTargetAPIRoot = "3gpp-Sbi-Target-apiRoot"
	// HeaderCorrelationID is the project correlation header (CLAUDE.md logging).
	HeaderCorrelationID = "X-Correlation-Id"
	// viaPseudonymPrefix prefixes the SEPP FQDN in the Via header.
	// Ref: TS 29.500 §6.10.10.3 and Table 5.2.2.2-2 ("SEPP-<FQDN>").
	viaPseudonymPrefix = "SEPP-"
	// serverHeaderPrefix: Server header of SEPP-originated errors, "SEPP-<FQDN>".
	// Ref: TS 29.500 §6.10.8.2.
	serverHeaderPrefix = "SEPP-"
	// viaReceivedProtocol is the received-protocol of the Via header for HTTP/2.
	// Ref: IETF RFC 9110 §7.6.3; TS 29.500 §5.2.2.2 example "Via: 2.0 SCP-...".
	viaReceivedProtocol = "2.0"

	// DefaultRequestTimeout bounds one forwarded exchange, including the
	// peer round trip (implementation limit; TS 29.500 leaves it to the operator).
	DefaultRequestTimeout = 10 * time.Second
	// DefaultMaxInflight bounds concurrent forwarded exchanges (implementation limit).
	DefaultMaxInflight = 1024
	// DefaultMaxBodyBytes bounds request bodies and rewritten response bodies.
	DefaultMaxBodyBytes = 1 << 20
	// DefaultN32Port is the peer N32 listener port (docs: N32 8443).
	DefaultN32Port = 8443
	// retryAfterOverloaded is the Retry-After (seconds) of an overload reply.
	// Ref: TS 29.500 §5.2.7.2 / §6.9 (503 with Retry-After).
	retryAfterOverloaded = "1"

	// Causes. TS 29.573 Table 5.3.3.4-1, TS 29.500 Table 5.2.7.2-1 and §6.10.10.3, §5.2.7.4.
	causeContextNotFound   = "CONTEXT_NOT_FOUND"
	causeInvalidMsgFormat  = "INVALID_MSG_FORMAT"
	causeMsgLoopDetected   = "MSG_LOOP_DETECTED"
	causeTargetUnreachable = "TARGET_NF_NOT_REACHABLE"
	causeSystemFailure     = "SYSTEM_FAILURE" // TS 29.500 Table 5.2.7.4-1 (500 only)
	causeOverload          = "NF_CONGESTION"  // TS 29.500 Table 5.2.7.4-1 (503)
)

// Spec references used in logs.
const (
	specForward   = "TS 29.573 §5.3.3.1; TS 29.500 §6.1.4.3.4"
	specCorrelate = "TS 29.573 §5.3.3.2.1, §5.3.3.4; TS 33.501 §13.1.2"
	specTelescope = "TS 23.003 §28.5.2; TS 29.500 §6.1.4.3.2; TS 33.501 §13.1.1.1"
	specHeader    = "TS 29.500 §6.1.4.3.3, §6.1.4.3.4"
	specLoop      = "TS 29.500 §6.10.10.3"
)

// Config configures a Forwarder.
type Config struct {
	// LocalPLMN is the PLMN of this SEPP.
	LocalPLMN n32c.PlmnId
	// SEPPFQDN is this SEPP's FQDN: the telescopic suffix (TS 23.003 §28.5.2)
	// and the Via pseudonym (TS 29.500 §6.10.10.3).
	SEPPFQDN string
	// Store is the N32 context store filled by n32c.
	Store *n32c.Store
	// TargetAPIRootSupported is the local support of the 3gpp-Sbi-Target-apiRoot
	// header; the header model applies only if the context also negotiated it.
	TargetAPIRootSupported bool
	// TopologyHiding enables telescopic-FQDN rewriting of Location headers,
	// discovery results and callback URIs (TS 33.501 §13.1.1.1). It never
	// applies to a request that used the header model (TS 29.500 §6.1.4.3.1).
	TopologyHiding bool

	// Transport sends to the peer SEPP (use NewN32Transport).
	Transport http.RoundTripper
	// LocalTransport sends to the local NF (mTLS client of the SBI).
	LocalTransport http.RoundTripper
	// Resolver finds the local NF for inbound requests (NRF discovery).
	Resolver Resolver
	// PeerIdentity authenticates the N32 peer (default n32c.CertPeerIdentity).
	PeerIdentity func(*http.Request) (n32c.PeerIdentity, error)
	// PeerAddr overrides the peer N32 address host:port (default PeerFQDN:N32Port).
	PeerAddr func(n32c.Context) string

	N32Port        int
	RequestTimeout time.Duration
	MaxInflight    int
	MaxBodyBytes   int64
	Logger         *slog.Logger
}

// Forwarder is the SEPP N32-f TLS-mode forwarding path.
type Forwarder struct {
	cfg      Config
	tele     *Telescopic
	sem      chan struct{}
	outProxy *httputil.ReverseProxy
	inProxy  *httputil.ReverseProxy
}

// New validates cfg, applies defaults and builds the Forwarder.
func New(cfg Config) (*Forwarder, error) {
	switch {
	case cfg.SEPPFQDN == "" || !cfg.LocalPLMN.Valid():
		return nil, errors.New("n32f: new: SEPP FQDN and valid local PLMN are required")
	case cfg.Store == nil:
		return nil, errors.New("n32f: new: N32 context store is required")
	case cfg.Transport == nil || cfg.LocalTransport == nil:
		return nil, errors.New("n32f: new: transports are required")
	case cfg.Resolver == nil:
		return nil, errors.New("n32f: new: resolver is required")
	}
	if cfg.PeerIdentity == nil {
		cfg.PeerIdentity = n32c.CertPeerIdentity
	}
	if cfg.N32Port == 0 {
		cfg.N32Port = DefaultN32Port
	}
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = DefaultRequestTimeout
	}
	if cfg.MaxInflight <= 0 {
		cfg.MaxInflight = DefaultMaxInflight
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	cfg.SEPPFQDN = strings.ToLower(cfg.SEPPFQDN)
	f := &Forwarder{cfg: cfg, tele: NewTelescopic(cfg.SEPPFQDN), sem: make(chan struct{}, cfg.MaxInflight)}
	f.outProxy = f.newProxy(cfg.Transport, true)
	f.inProxy = f.newProxy(cfg.LocalTransport, false)
	return f, nil
}

// Outbound is the handler of the SEPP SBI listener: local NF -> cSEPP -> pSEPP.
func (f *Forwarder) Outbound() http.Handler { return f.serve(true) }

// Inbound is the handler of the N32 listener: pSEPP -> local NF.
func (f *Forwarder) Inbound() http.Handler { return f.serve(false) }

// Terminate closes the idle N32-f connections after N32-c teardown or context
// replacement; it matches n32c.Config.Terminator. Requests in flight finish
// ("once all the ongoing message exchanges are completed", TS 29.573 §5.2.4).
func (f *Forwarder) Terminate(ctx context.Context, remote n32c.PlmnId, reason string) {
	if c, ok := f.cfg.Transport.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
	f.plog(ctx, "OUT").InfoContext(ctx, "n32-f connections closed",
		"result", "OK", "reason", reason, "remote_plmn", remote.String(),
		"spec_ref", "TS 29.573 §5.2.2")
}

// ---- request routing ----------------------------------------------------

type rejection struct {
	status int
	cause  string
	detail string
	param  string
	logWhy string
	spec   string
}

type route struct {
	outbound  bool
	remote    n32c.PlmnId
	targetURL url.URL // inbound: local NF base; outbound: scheme+authority of the Out URL
	out       struct {
		host      string
		setHeader string // header model: value of 3gpp-Sbi-Target-apiRoot to send
	}
	hide      bool
	headerReq bool
	failed    bool
	log       *slog.Logger
	cid       string
}

type routeKey struct{}

func (f *Forwarder) plog(ctx context.Context, direction string) *slog.Logger {
	return logging.NewProcedureLogger(ctx, f.cfg.Logger, procedureName).With(
		"nf", "SEPP", "interface", interfaceN32f, "direction", direction)
}

func (f *Forwarder) headerModel(c n32c.Context) bool {
	return c.TargetAPIRootHeader && f.cfg.TargetAPIRootSupported
}

func (f *Forwarder) peerAddr(c n32c.Context) string {
	if f.cfg.PeerAddr != nil {
		return f.cfg.PeerAddr(c)
	}
	return net.JoinHostPort(c.PeerFQDN, strconv.Itoa(f.cfg.N32Port))
}

// parseAPIRoot validates a 3gpp-Sbi-Target-apiRoot value and returns its authority.
func parseAPIRoot(v string) (string, error) {
	u, err := url.Parse(v)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return "", fmt.Errorf("n32f: invalid apiRoot %q", v)
	}
	return strings.ToLower(u.Host), nil
}

func hostOnly(authority string) string {
	h, _ := splitHostPort(authority)
	return strings.ToLower(h)
}

func (f *Forwarder) routeOutbound(r *http.Request) (*route, *rejection) {
	rt := &route{outbound: true}
	host, port := splitHostPort(r.Host)
	host = strings.ToLower(host)
	hdr := r.Header.Get(HeaderTargetAPIRoot)
	var targetAuthority string
	switch {
	case f.tele.Is(host):
		// TS 29.500 §6.1.4.3.3 NOTE 1: telescopic FQDN wins, header ignored.
		orig, err := f.tele.Decode(host)
		if err != nil {
			return nil, &rejection{status: 400, cause: causeInvalidMsgFormat, param: ":authority",
				detail: "unknown telescopic FQDN", logWhy: "telescopic_unknown", spec: specTelescope}
		}
		targetAuthority = orig + port
	case hdr != "":
		a, err := parseAPIRoot(hdr)
		if err != nil {
			return nil, &rejection{status: 400, cause: causeInvalidMsgFormat, param: HeaderTargetAPIRoot,
				detail: "invalid apiRoot", logWhy: "bad_target_apiroot", spec: specHeader}
		}
		targetAuthority, rt.headerReq = a, true
	default:
		targetAuthority = host + port
	}
	thost := hostOnly(targetAuthority)
	plmn, err := n32c.ParsePLMNFromFQDN(thost)
	if err != nil {
		param := ":authority"
		if rt.headerReq { // the offending target came from the apiRoot header
			param = HeaderTargetAPIRoot
		}
		return nil, &rejection{status: 400, cause: causeInvalidMsgFormat, param: param,
			detail: "target FQDN has no PLMN (TS 23.003 §28.5.1)", logWhy: "target_without_plmn", spec: "TS 23.003 §28.5.1"}
	}
	if plmn.Key() == f.cfg.LocalPLMN.Key() {
		return nil, &rejection{status: 400, cause: causeInvalidMsgFormat, param: ":authority",
			detail: "target is in the local PLMN", logWhy: "target_is_local", spec: specForward}
	}
	nctx, rej := f.context(plmn)
	if rej != nil {
		return nil, rej
	}
	rt.remote = plmn
	peer := f.peerAddr(nctx)
	if f.headerModel(nctx) {
		// Both SEPPs signalled the header: authority := receiving SEPP; header
		// forwarded unmodified or inserted from the target. TS 29.500 §6.1.4.3.4.
		rt.out.host = peer
		rt.out.setHeader = hdr
		if hdr == "" || !rt.headerReq {
			rt.out.setHeader = "https://" + targetAuthority
		}
	} else {
		// Header removed; request authority := target NF apiRoot, forwarded as is.
		rt.out.host = targetAuthority
	}
	rt.targetURL = url.URL{Scheme: "https", Host: rt.out.host}
	rt.hide = f.cfg.TopologyHiding && !rt.headerReq
	return rt, nil
}

func (f *Forwarder) routeInbound(ctx context.Context, r *http.Request) (*route, *rejection) {
	rt := &route{}
	id, err := f.cfg.PeerIdentity(r)
	if err != nil {
		return nil, &rejection{status: 403, cause: causeContextNotFound, detail: "no N32 context for this peer",
			logWhy: "peer_identity", spec: specCorrelate}
	}
	nctx, rej := f.context(id.PLMN)
	if rej != nil {
		return nil, rej
	}
	rt.remote = id.PLMN
	authority := strings.ToLower(r.Host)
	if hdr := r.Header.Get(HeaderTargetAPIRoot); hdr != "" {
		a, perr := parseAPIRoot(hdr)
		if !f.headerModel(nctx) || perr != nil {
			return nil, &rejection{status: 400, cause: causeInvalidMsgFormat, param: HeaderTargetAPIRoot,
				detail: "header not negotiated or invalid", logWhy: "bad_target_apiroot", spec: specHeader}
		}
		authority, rt.headerReq = a, true
	}
	thost := hostOnly(authority)
	plmn, perr := n32c.ParsePLMNFromFQDN(thost)
	if perr != nil || plmn.Key() != f.cfg.LocalPLMN.Key() {
		param := ":authority"
		if rt.headerReq {
			param = HeaderTargetAPIRoot
		}
		return nil, &rejection{status: 400, cause: causeInvalidMsgFormat, param: param,
			detail: "target is not an NF of this PLMN", logWhy: "target_not_local", spec: specForward}
	}
	base, rerr := f.cfg.Resolver.Resolve(ctx, thost, r.URL.Path)
	if rerr != nil {
		return nil, &rejection{status: 504, cause: causeTargetUnreachable, detail: "target NF not found via NRF",
			logWhy: "nrf_discovery: " + rerr.Error(), spec: "TS 29.510 §5.3.2.2"}
	}
	rt.targetURL = *base
	rt.hide = f.cfg.TopologyHiding && !rt.headerReq
	return rt, nil
}

// context returns the TLS-mode N32 context of the remote PLMN.
func (f *Forwarder) context(p n32c.PlmnId) (n32c.Context, *rejection) {
	c, ok := f.cfg.Store.Get(p)
	if !ok {
		return c, &rejection{status: 403, cause: causeContextNotFound,
			detail: "no N32 context for the PLMN", logWhy: "context_not_found", spec: specCorrelate}
	}
	if c.SecCapability != n32c.CapTLS {
		return c, &rejection{status: 403, cause: causeContextNotFound,
			detail: "N32 context is not in TLS security mode", logWhy: "context_not_tls", spec: specCorrelate}
	}
	return c, nil
}

// ---- serving ------------------------------------------------------------

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (f *Forwarder) serve(outbound bool) http.Handler {
	dir := "IN"
	if outbound {
		dir = "OUT"
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ctx := logging.WithCorrelationID(r.Context(), r.Header.Get(HeaderCorrelationID))
		cid := logging.CorrelationID(ctx)
		r.Header.Set(HeaderCorrelationID, cid)
		w.Header().Set(HeaderCorrelationID, cid)
		ctx, cancel := context.WithTimeout(ctx, f.cfg.RequestTimeout)
		defer cancel()
		sw := &statusWriter{ResponseWriter: w}
		lg := f.plog(ctx, dir)

		select {
		case f.sem <- struct{}{}:
			defer func() { <-f.sem }()
		default:
			w.Header().Set("Retry-After", retryAfterOverloaded)
			f.reject(ctx, sw, lg, &rejection{status: http.StatusServiceUnavailable, cause: causeOverload,
				detail: "too many forwarded exchanges", logWhy: "overload", spec: specForward}, "FAILURE")
			return
		}
		if f.loops(r) {
			f.reject(ctx, sw, lg, &rejection{status: 400, cause: causeMsgLoopDetected,
				detail: "request already traversed this SEPP", logWhy: "loop", spec: specLoop}, "REJECT")
			return
		}
		var (
			rt  *route
			rej *rejection
		)
		if outbound {
			rt, rej = f.routeOutbound(r)
		} else {
			rt, rej = f.routeInbound(ctx, r)
		}
		if rej != nil {
			f.reject(ctx, sw, lg, rej, "REJECT")
			return
		}
		rt.log, rt.cid = lg, cid
		if rej := f.prepareBody(sw, r, rt); rej != nil {
			f.reject(ctx, sw, lg, rej, "REJECT")
			return
		}
		ctx = context.WithValue(ctx, routeKey{}, rt)
		if outbound {
			ctx = context.WithValue(ctx, peerKey{}, peerDial{addr: f.peerAddrFor(rt), serverName: f.peerNameFor(rt)})
		}
		proxy := f.inProxy
		if outbound {
			proxy = f.outProxy
		}
		proxy.ServeHTTP(sw, r.WithContext(ctx))

		result := "OK"
		if rt.failed {
			result = "FAILURE"
		}
		metrics.ProcedureTotal.WithLabelValues("SEPP", procedureName, result).Inc()
		lg.InfoContext(ctx, "n32-f message forwarded",
			"result", result, "remote_plmn", rt.remote.String(), "status", sw.status,
			"topology_hiding", rt.hide, "header_model", rt.headerReq,
			"duration_ms", time.Since(start).Milliseconds(), "spec_ref", specForward)
	})
}

// peerAddrFor / peerNameFor read the context again so the dial target always
// comes from the N32 context, never from the request.
func (f *Forwarder) peerAddrFor(rt *route) string {
	c, _ := f.cfg.Store.Get(rt.remote)
	return f.peerAddr(c)
}

func (f *Forwarder) peerNameFor(rt *route) string {
	c, _ := f.cfg.Store.Get(rt.remote)
	return c.PeerFQDN
}

// loops reports whether this SEPP already appears in the Via header.
// Ref: TS 29.500 §6.10.10.3 (loop detection through Via).
func (f *Forwarder) loops(r *http.Request) bool {
	self := strings.ToLower(viaPseudonymPrefix + f.cfg.SEPPFQDN)
	for _, v := range r.Header.Values("Via") {
		for _, hop := range strings.Split(v, ",") {
			if fs := strings.Fields(hop); len(fs) >= 2 && strings.ToLower(fs[1]) == self {
				return true
			}
		}
	}
	return false
}

func (f *Forwarder) via() string {
	return viaReceivedProtocol + " " + viaPseudonymPrefix + f.cfg.SEPPFQDN
}

// prepareBody bounds the request body and, only when topology hiding applies,
// rewrites the callback URIs of a JSON request body (TS 33.501 §13.1.1.1 b, c).
// Otherwise the body is streamed untouched (TS 29.500 §6.1.4.3.4 "as is").
func (f *Forwarder) prepareBody(w http.ResponseWriter, r *http.Request, rt *route) *rejection {
	if r.Body == nil || r.Body == http.NoBody {
		return nil
	}
	r.Body = http.MaxBytesReader(w, r.Body, f.cfg.MaxBodyBytes)
	if rt.outbound || !rt.hide || !isJSON(r.Header.Get("Content-Type")) {
		return nil
	}
	b, err := io.ReadAll(r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return &rejection{status: http.StatusRequestEntityTooLarge,
				detail: "body too large", logWhy: "body_too_large", spec: specForward}
		}
		return &rejection{status: 400, cause: causeInvalidMsgFormat, detail: "cannot read body", logWhy: "body_read", spec: specForward}
	}
	nb, changed, err := rewriteJSON(b, f.hideHost)
	if err != nil {
		return &rejection{status: 400, cause: causeInvalidMsgFormat, detail: "invalid JSON body", logWhy: "body_json", spec: specTelescope}
	}
	if changed {
		b = nb
	}
	r.Body = io.NopCloser(bytes.NewReader(b))
	r.ContentLength = int64(len(b))
	r.Header.Del("Content-Length")
	return nil
}

// hideHost maps a foreign-PLMN host to its telescopic FQDN; hosts of the local
// PLMN, IP literals and non-PLMN names are left alone.
// Ref: TS 23.003 §28.5.2; TS 33.501 §13.1.1.1.
func (f *Forwarder) hideHost(host string) (string, error) {
	p, err := n32c.ParsePLMNFromFQDN(host)
	if err != nil || p.Key() == f.cfg.LocalPLMN.Key() {
		return host, nil
	}
	return f.tele.Encode(host)
}

func (f *Forwarder) newProxy(rtp http.RoundTripper, outbound bool) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Transport: rtp,
		// Rewrite (not Director) so hop-by-hop headers are removed before we
		// run and no X-Forwarded-* is added (RFC 9110 §7.6.1).
		Rewrite: func(pr *httputil.ProxyRequest) {
			rt, _ := pr.In.Context().Value(routeKey{}).(*route)
			if rt == nil {
				return
			}
			pr.Out.URL.Scheme = rt.targetURL.Scheme
			pr.Out.URL.Host = rt.targetURL.Host
			pr.Out.Host = rt.targetURL.Host
			if outbound {
				pr.Out.Header.Del(HeaderTargetAPIRoot)
				if rt.out.setHeader != "" {
					pr.Out.Header.Set(HeaderTargetAPIRoot, rt.out.setHeader)
				}
			} else {
				pr.Out.Header.Del(HeaderTargetAPIRoot)
			}
			pr.Out.Header.Add("Via", f.via())
		},
		ModifyResponse: func(resp *http.Response) error {
			rt, _ := resp.Request.Context().Value(routeKey{}).(*route)
			// serve() already set the correlation id on the client response and ReverseProxy
			// appends the upstream headers to it: drop the upstream NF's echo so the client
			// sees exactly one value (it was duplicated in the N32-f pcap).
			resp.Header.Del(HeaderCorrelationID)
			if resp.StatusCode >= http.StatusBadRequest {
				resp.Header.Add("Via", f.via())
			}
			if rt == nil || !rt.outbound || !rt.hide {
				return nil
			}
			return f.hideResponse(resp)
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			rt, _ := r.Context().Value(routeKey{}).(*route)
			if rt != nil {
				rt.failed = true
			}
			rej := &rejection{status: http.StatusInternalServerError, cause: causeSystemFailure, detail: "forwarding failed",
				logWhy: err.Error(), spec: specForward}
			var mbe *http.MaxBytesError
			switch {
			case errors.Is(err, context.DeadlineExceeded), errors.Is(r.Context().Err(), context.DeadlineExceeded):
				rej.status, rej.cause, rej.detail = http.StatusGatewayTimeout, causeTargetUnreachable, "peer did not answer in time"
			case errors.As(err, &mbe):
				rej.status, rej.cause, rej.detail = http.StatusRequestEntityTooLarge, "", "body too large" // TS 29.500 §5.2.7.4: no cause
			case errors.Is(err, context.Canceled):
				rej.status, rej.cause, rej.detail = http.StatusGatewayTimeout, causeTargetUnreachable, "request cancelled"
			default:
				if isDialError(err) {
					rej.status, rej.cause, rej.detail = http.StatusGatewayTimeout, causeTargetUnreachable, "peer SEPP not reachable"
				}
			}
			f.writeProblem(w, rej)
			f.plog(r.Context(), dirOf(outbound)).WarnContext(r.Context(), "n32-f forwarding failed",
				"result", "FAILURE", "cause", rej.logWhy, "status", rej.status, "spec_ref", rej.spec)
		},
	}
}

func dirOf(outbound bool) string {
	if outbound {
		return "OUT"
	}
	return "IN"
}

func isDialError(err error) bool {
	var op *net.OpError
	return errors.As(err, &op)
}

// hideResponse applies topology hiding to a response received from the peer
// SEPP: Location header and JSON body (e.g. NFDiscover result) get telescopic
// FQDNs of this (cSEPP) domain. A body that cannot be rewritten fails the
// exchange instead of leaking the foreign topology.
// Ref: TS 29.500 §6.1.4.3.2 (link relation URI), TS 33.501 §13.1.1.1 a.
func (f *Forwarder) hideResponse(resp *http.Response) error {
	if loc := resp.Header.Get("Location"); loc != "" {
		if nl, ok, err := rewriteURI(loc, f.hideHost); err != nil {
			return fmt.Errorf("n32f: rewrite location: %w", err)
		} else if ok {
			resp.Header.Set("Location", nl)
		}
	}
	if resp.Body == nil || !isJSON(resp.Header.Get("Content-Type")) {
		return nil
	}
	if ce := resp.Header.Get("Content-Encoding"); ce != "" && !strings.EqualFold(ce, "identity") {
		return fmt.Errorf("n32f: cannot rewrite %s-encoded body", ce)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, f.cfg.MaxBodyBytes+1))
	_ = resp.Body.Close()
	if err != nil {
		return fmt.Errorf("n32f: read response body: %w", err)
	}
	if int64(len(b)) > f.cfg.MaxBodyBytes {
		return errors.New("n32f: response body too large to rewrite")
	}
	if len(bytes.TrimSpace(b)) > 0 {
		nb, changed, err := rewriteJSON(b, f.hideHost)
		if err != nil {
			return fmt.Errorf("n32f: rewrite response body: %w", err)
		}
		if changed {
			b = nb
		}
	}
	resp.Body = io.NopCloser(bytes.NewReader(b))
	resp.ContentLength = int64(len(b))
	resp.Header.Set("Content-Length", strconv.Itoa(len(b)))
	return nil
}

// ---- errors -------------------------------------------------------------

func (f *Forwarder) reject(ctx context.Context, w http.ResponseWriter, lg *slog.Logger, rej *rejection, result string) {
	f.writeProblem(w, rej)
	metrics.ProcedureTotal.WithLabelValues("SEPP", procedureName, result).Inc()
	lg.WarnContext(ctx, "n32-f request rejected",
		"result", result, "cause", rej.logWhy, "status", rej.status, "spec_ref", rej.spec)
}

// writeProblem writes an application/problem+json body (TS 29.500 §5.2.7).
func (f *Forwarder) writeProblem(w http.ResponseWriter, rej *rejection) {
	pd := n32c.ProblemDetails{Title: http.StatusText(rej.status), Status: rej.status, Detail: rej.detail, Cause: rej.cause}
	if rej.param != "" {
		pd.InvalidParams = []n32c.InvalidParam{{Param: rej.param, Reason: rej.detail}}
	}
	// Originator of the error: Server header, no Via (TS 29.500 §6.10.8.2).
	w.Header().Del("Via")
	w.Header().Set("Server", serverHeaderPrefix+f.cfg.SEPPFQDN)
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(rej.status)
	_ = json.NewEncoder(w).Encode(pd)
}
