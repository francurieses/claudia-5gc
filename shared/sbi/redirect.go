// Package sbi: consumer-side HTTP 307/308 redirection handling (ES3XX).
//
// ApplyRedirectPolicy replaces the net/http default redirect policy (which also
// follows 301/302/303 and rewrites POST to GET) with the policy of
// TS 29.500 §6.10.9.1: only 307 Temporary Redirect and 308 Permanent Redirect
// are followed, with the same method, body and headers; SCP_REDIRECTION /
// SEPP_REDIRECTION bodies (TS 29.571 RedirectResponse) re-target the apiRoot;
// the chain is bounded (TS 29.500 §6.4.2.4). The policy is not profile-gated:
// ES3XX is mandatory for consumers already in Rel-17 (TS 29.502 §6.1.8 Table
// 6.1.8-1 feature 8, TS 29.518 §6.1.8 Table 6.1.8-1 feature 7).
//
// net/http calls CheckRedirect with req.Response set; the response body is
// closed only after CheckRedirect returns (client.go: checkRedirect is invoked
// before resp.Body.Close), so it can be read here.
package sbi

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/francurieses/claudia-5gc/shared/logging"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

const (
	// MaxRedirects is the maximum number of consecutive 307/308 redirects a
	// consumer follows for one request. Exceeding it is treated as an
	// infinite redirection loop: "the client shall be responsible of the
	// detection of infinite redirection loops" (TS 29.500 §6.4.2.4). The
	// value 5 is an implementation choice; the TS defines no number.
	MaxRedirects = 5

	// CauseSCPRedirection is the RedirectResponse cause asking the client to
	// retransmit to another SCP. Ref: TS 29.500 §6.10.9.1, Table 5.2.7.4-2.
	CauseSCPRedirection = "SCP_REDIRECTION"
	// CauseSEPPRedirection is the RedirectResponse cause asking the client to
	// retransmit to another SEPP. Ref: TS 29.500 §6.10.9.1, Table 5.2.7.4-2.
	CauseSEPPRedirection = "SEPP_REDIRECTION"

	// HeaderTargetNfID carries the target NF (service) instance ID of a
	// redirection. Ref: TS 29.500 §5.2.3.2.13, §6.10.9.1.
	HeaderTargetNfID = "3gpp-Sbi-Target-Nf-Id"

	// RedirectSpecRef is the spec_ref of followed-redirect records and of
	// SCP/SEPP/Location refusals (TS 29.500 §6.10.9.1).
	RedirectSpecRef = "TS 29.500 §6.10.9.1"
	// RedirectLoopSpecRef is the spec_ref of the redirect-loop-limit record:
	// the client detects infinite redirection loops (TS 29.500 §6.4.2.4).
	RedirectLoopSpecRef = "TS 29.500 §6.4.2.4"
	// RedirectNotFollowedSpecRef is the spec_ref of the record for a 3xx other
	// than 307/308, which is not followed (TS 29.500 §5.2.7.3).
	RedirectNotFollowedSpecRef = "TS 29.500 §5.2.7.3"

	// redirectBodyLimit bounds the RedirectResponse body read (64 KiB).
	redirectBodyLimit = 64 << 10
)

// ErrTooManyRedirects is returned (wrapped in a *url.Error by net/http) when
// more than MaxRedirects consecutive redirects are received.
var ErrTooManyRedirects = errors.New("sbi: redirect: too many redirects")

// RedirectResponse is the body of a 307/308 response. Ref: TS 29.571
// RedirectResponse (TS29571_CommonData.yaml).
type RedirectResponse struct {
	// Cause is SCP_REDIRECTION or SEPP_REDIRECTION.
	Cause string `json:"cause,omitempty"`
	// TargetScp is the apiRoot of the target SCP (cause SCP_REDIRECTION).
	TargetScp string `json:"targetScp,omitempty"`
	// TargetSepp is the apiRoot of the target SEPP (cause SEPP_REDIRECTION).
	TargetSepp string `json:"targetSepp,omitempty"`
}

// RedirectOption customises the redirect policy.
type RedirectOption func(*redirectConfig)

type redirectConfig struct{ nf string }

// WithNF sets the nf label (e.g. "AMF", "SMF") of the
// fivegc_procedure_total{procedure="HttpRedirection"} counter incremented for
// every redirect record. Without it the label is "UNKNOWN".
func WithNF(nf string) RedirectOption {
	return func(c *redirectConfig) { c.nf = nf }
}

// ApplyRedirectPolicy installs the TS 29.500 §6.10.9.1 redirect policy on c.
// A nil logger selects slog.Default(). Call it before wrapping the client
// (oauth2.NewBearerClient copies CheckRedirect).
func ApplyRedirectPolicy(c *http.Client, logger *slog.Logger, opts ...RedirectOption) {
	c.CheckRedirect = RedirectPolicy(logger, opts...)
}

// RedirectPolicy returns the http.Client.CheckRedirect function implementing
// the ES3XX consumer behaviour.
func RedirectPolicy(logger *slog.Logger, opts ...RedirectOption) func(req *http.Request, via []*http.Request) error {
	if logger == nil {
		logger = slog.Default()
	}
	cfg := redirectConfig{nf: "UNKNOWN"}
	for _, o := range opts {
		o(&cfg)
	}
	return func(req *http.Request, via []*http.Request) error {
		return checkRedirect(logger, cfg.nf, req, via)
	}
}

// redirectInterface derives the log interface (Namf, Nsmf, Nausf, ...) from
// the service-name prefix of the first path segment (TS 29.501 §4.4: the
// apiName "<nf>-<service>"). The NRF token endpoint "oauth2" (TS 29.510
// §6.3) maps to Nnrf. Anything else falls back to "SBI".
func redirectInterface(u *url.URL) string {
	seg := strings.SplitN(strings.TrimPrefix(u.Path, "/"), "/", 2)[0]
	if seg == "oauth2" {
		return "Nnrf"
	}
	prefix, _, found := strings.Cut(seg, "-")
	if !found || len(prefix) < 2 || prefix[0] != 'n' {
		return "SBI"
	}
	return "N" + prefix[1:]
}

func checkRedirect(logger *slog.Logger, nf string, req *http.Request, via []*http.Request) error {
	if len(via) == 0 || req.Response == nil {
		return http.ErrUseLastResponse
	}
	resp := req.Response
	prev := via[len(via)-1]
	hop := len(via) // redirect number being followed
	ctx := req.Context()

	attrs := []any{
		"interface", redirectInterface(via[0].URL),
		"direction", "OUT",
		"http_status", resp.StatusCode,
		"redirect_count", hop,
	}
	if id := resp.Header.Get(HeaderTargetNfID); id != "" {
		attrs = append(attrs, "target_nf_id", id)
	}
	emit := func(specRef string, target *url.URL, cause, result, msg string) {
		a := append([]any(nil), attrs...)
		a = append(a, "spec_ref", specRef)
		if target != nil {
			a = append(a, "location", target.Redacted())
		}
		if cause != "" {
			a = append(a, "cause", cause)
		}
		a = append(a, "result", result)
		metrics.ProcedureTotal.WithLabelValues(nf, "HttpRedirection", result).Inc()
		l := logging.NewProcedureLogger(ctx, logger, "HttpRedirection")
		if result == "OK" {
			l.Info(msg, a...)
		} else {
			l.Warn(msg, a...)
		}
	}

	// Only 307 and 308 are followed (same method). Other 3xx are returned.
	if resp.StatusCode != http.StatusTemporaryRedirect && resp.StatusCode != http.StatusPermanentRedirect {
		emit(RedirectNotFollowedSpecRef, req.URL, "", "FAILURE", "3xx other than 307/308 not followed")
		return http.ErrUseLastResponse
	}
	// A body that cannot be replayed would be silently dropped by net/http.
	if prev.Body != nil && prev.Body != http.NoBody && req.Body == nil {
		emit(RedirectSpecRef, req.URL, "", "FAILURE", "redirect not followed: request body not replayable")
		return http.ErrUseLastResponse
	}
	if hop > MaxRedirects {
		emit(RedirectLoopSpecRef, req.URL, "", "FAILURE", "too many redirects")
		return ErrTooManyRedirects
	}

	target, cause := req.URL, ""
	retarget, rcause := redirectResponseTarget(resp, prev.URL)
	if retarget != nil {
		target, cause = retarget, rcause
	}

	// Project rule: never leave TLS; also refuse non-HTTP schemes.
	if (target.Scheme != "https" && target.Scheme != "http") ||
		(prev.URL.Scheme == "https" && target.Scheme != "https") {
		emit(RedirectSpecRef, target, cause, "FAILURE", "redirect refused: scheme downgrade or unsupported scheme")
		return http.ErrUseLastResponse
	}
	if target.Host == "" {
		emit(RedirectSpecRef, target, cause, "FAILURE", "redirect refused: target without host")
		return http.ErrUseLastResponse
	}

	if retarget != nil {
		// SCP/SEPP: Location is ignored (TS 29.500 §6.10.9.1).
		req.URL = retarget
		req.Host = ""
	}
	// net/http adds Referer on redirects; the retransmission must carry the
	// same headers as the original request.
	if via[0].Header.Get("Referer") == "" {
		req.Header.Del("Referer")
	}
	emit(RedirectSpecRef, target, cause, "OK", "following redirect")
	return nil
}

// redirectResponseTarget decodes a RedirectResponse body and, for a usable
// SCP_REDIRECTION / SEPP_REDIRECTION, returns the original path and query on
// the target apiRoot. A malformed or unknown body returns nil (the caller falls
// back to the Location header).
func redirectResponseTarget(resp *http.Response, orig *url.URL) (*url.URL, string) {
	if resp.Body == nil {
		return nil, ""
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, redirectBodyLimit))
	if err != nil || len(raw) == 0 {
		return nil, ""
	}
	var rr RedirectResponse
	if err := json.Unmarshal(raw, &rr); err != nil {
		return nil, ""
	}
	var root string
	switch rr.Cause {
	case CauseSCPRedirection:
		root = rr.TargetScp
	case CauseSEPPRedirection:
		root = rr.TargetSepp
	default:
		return nil, ""
	}
	r, err := url.Parse(root)
	if err != nil || r.Scheme == "" || r.Host == "" {
		return nil, ""
	}
	s := r.Scheme + "://" + r.Host + strings.TrimRight(r.EscapedPath(), "/") + orig.EscapedPath()
	if orig.RawQuery != "" {
		s += "?" + orig.RawQuery
	}
	t, err := url.Parse(s)
	if err != nil {
		return nil, ""
	}
	return t, rr.Cause
}
