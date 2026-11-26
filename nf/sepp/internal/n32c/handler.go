package n32c

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/francurieses/claudia-5gc/shared/logging"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

// Log result values. Ref: CLAUDE.md "Logging — Required Format".
const (
	resultOK      = "OK"
	resultReject  = "REJECT"
	resultFailure = "FAILURE"
)

// Log-only causes (no wire cause is defined for these, TS 29.573 §6.1.6.3).
const (
	logCausePlmnNotAllowed = "plmn_not_allowed"
	logCausePlmnMismatch   = "plmn_mismatch"
	logCauseNoPeerCert     = "peer_identity_unavailable"
	logCauseNoContext      = "no_context_for_teardown"
	logCauseSenderDomain   = "sender_domain_mismatch"
	logCauseTargetPlmn     = "target_plmn_not_served"
	logCausePurpose        = "purpose_not_allowed"
	// logCauseAccepted marks an accepted exchange-capability (result=OK).
	logCauseAccepted = "handshake_accepted"
)

// reject writes a ProblemDetails response and logs the REJECT outcome.
func (s *Service) reject(ctx context.Context, w http.ResponseWriter, status int, wireCause, logCause, detail string, extra ...any) {
	s.rejectParam(ctx, w, status, wireCause, logCause, detail, "", extra...)
}

// rejectParam is reject plus an invalidParams entry naming the offending attribute.
func (s *Service) rejectParam(ctx context.Context, w http.ResponseWriter, status int, wireCause, logCause, detail, param string, extra ...any) {
	pd := ProblemDetails{Title: http.StatusText(status), Status: status, Cause: wireCause, Detail: detail}
	if param != "" {
		pd.InvalidParams = []InvalidParam{{Param: param, Reason: detail}}
	}
	w.Header().Set("Content-Type", "application/problem+json")
	// SEPP-originated error: Server header names the SEPP (same convention as n32f).
	w.Header().Set("Server", serverHeaderPrefix+s.cfg.LocalFQDN)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(pd)
	if logCause == "" {
		logCause = wireCause
	}
	countResult(resultReject)
	if p, ok := peerFrom(ctx); ok {
		s.record(p, RoleResponder, resultReject, logCause)
	} else {
		s.record(PlmnId{}, RoleResponder, resultReject, logCause)
	}
	attrs := append([]any{"result", resultReject, "cause", logCause, "status", status, "spec_ref", specStep2b}, extra...)
	s.plog(ctx, "IN").Warn("exchange-capability rejected", attrs...)
}

// HandleExchangeCapability implements POST .../exchange-capability (responder).
// Ref: TS 29.573 §5.2.2 steps 2a/2b, §6.1.4.2.
func (s *Service) HandleExchangeCapability(w http.ResponseWriter, r *http.Request) {
	ctx := logging.WithCorrelationID(r.Context(), r.Header.Get("X-Correlation-Id"))

	// 415: Content-Type must be application/json (TS 29.500 §5.2.2.2).
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		s.reject(ctx, w, http.StatusUnsupportedMediaType, "", "unsupported_media_type", "Content-Type must be application/json")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			s.reject(ctx, w, http.StatusRequestEntityTooLarge, "", "body_too_large", "request body too large")
			return
		}
		s.reject(ctx, w, http.StatusBadRequest, CauseInvalidMsgFormat, "", "cannot read body")
		return
	}
	var req SecNegotiateReqData
	if err := json.Unmarshal(body, &req); err != nil { // unknown keys are tolerated by encoding/json
		s.reject(ctx, w, http.StatusBadRequest, CauseInvalidMsgFormat, "", "body is not a valid SecNegotiateReqData")
		return
	}
	switch {
	case req.Sender == "":
		s.rejectParam(ctx, w, http.StatusBadRequest, CauseMandatoryIEMissing, "", "sender is missing", "sender")
		return
	case req.SupportedSecCapabilityList == nil:
		s.rejectParam(ctx, w, http.StatusBadRequest, CauseMandatoryIEMissing, "", "supportedSecCapabilityList is missing", "supportedSecCapabilityList")
		return
	case len(req.SupportedSecCapabilityList) == 0:
		s.rejectParam(ctx, w, http.StatusBadRequest, CauseMandatoryIEIncorrect, "", "supportedSecCapabilityList is empty", "supportedSecCapabilityList")
		return
	}
	if req.SupportedFeatures != "" {
		if err := features.Validate(req.SupportedFeatures); err != nil {
			s.reject(ctx, w, http.StatusBadRequest, CauseInvalidMsgFormat, "", "supportedFeatures is not a hex string")
			return
		}
	}

	// Peer identity (verified client certificate). TS 33.501 §13.1.2.
	peer, err := s.cfg.PeerIdentity(r)
	if err != nil {
		s.reject(ctx, w, http.StatusForbidden, "", logCauseNoPeerCert, "peer certificate not usable")
		return
	}
	ctx = withPeer(ctx, peer.PLMN)
	lg := []any{"peer_plmn", peer.PLMN.String(), "peer_fqdn", peer.FQDN}
	// E2: roaming-partner authorisation first (cause plmn_not_allowed).
	if !s.isPartner(peer.PLMN) {
		s.reject(ctx, w, http.StatusForbidden, "", logCausePlmnNotAllowed, "PLMN not allowed", lg...)
		return
	}
	certPLMNs := certPLMNSet(peer)
	// E9 (S4): sender must sit under the Home Network Domain of a certificate
	// PLMN (TS 23.003 §28.5.1); no exact-FQDN match on the responder.
	if !senderUnderCertDomain(req.Sender, certPLMNs) {
		s.reject(ctx, w, http.StatusForbidden, "", logCauseSenderDomain, "sender is not under the certificate PLMN home network domain", lg...)
		return
	}
	// E7 (S5): every plmnIdList entry must be a certificate PLMN (TS 33.501 §13.1.2).
	for _, p := range req.PlmnIDList {
		if !certPLMNs[p.Key()] {
			s.reject(ctx, w, http.StatusForbidden, "", logCausePlmnMismatch, "plmnIdList differs from certificate PLMN", lg...)
			return
		}
	}
	// E8 (S3): the PLMN selected by targetPlmnId must be ours (TS 29.573 §5.2.2).
	if req.TargetPlmnID != nil && req.TargetPlmnID.Key() != s.cfg.LocalPLMN.Key() {
		s.reject(ctx, w, http.StatusForbidden, "", logCauseTargetPlmn, "targetPlmnId is not served by this SEPP",
			append(lg, "target_plmn", req.TargetPlmnID.String())...)
		return
	}

	hasTLS, allNone := false, true
	for _, c := range req.SupportedSecCapabilityList {
		hasTLS = hasTLS || c == CapTLS
		allNone = allNone && c == CapNone
	}
	rspFeatures, negotiated := features.Answer(s.catalog, s.cfg.Profile, req.SupportedFeatures)

	switch {
	case hasTLS:
		// E10 (S2): purposes per Table 6.1.5.2.3-1 / 6.1.6.3-1.
		allowed, rejected := splitPurposes(req.IntendedUsagePurpose)
		if len(req.IntendedUsagePurpose) > 0 && len(allowed) == 0 {
			s.reject(ctx, w, http.StatusForbidden, CausePurposeNotAllowed, logCausePurpose, "all requested usage purposes rejected", lg...)
			return
		}
		s.negotiate(ctx, w, req, peer, rspFeatures, negotiated, lg, allowed, rejected)
	case allNone:
		s.teardown(ctx, w, peer, rspFeatures, lg)
	default:
		// E1: no common capability (PRINS only, unknown only, mixed without TLS).
		s.reject(ctx, w, http.StatusForbidden, CauseNegotiationNotAllowed, "", "no common security capability", lg...)
	}
}

// negotiate selects TLS and stores the context. Ref: TS 29.573 §5.2.2 step 2a/2b.
func (s *Service) negotiate(ctx context.Context, w http.ResponseWriter, req SecNegotiateReqData,
	peer PeerIdentity, rspFeatures string, negotiated features.Set, lg []any, allowed, rejected []IntendedN32Purpose) {
	// Collision (Rel-19 only; Rel-17 has no 409): step 2b.
	if s.specLit {
		if in, ok := s.lookupInflight(peer.PLMN); ok {
			if strings.Compare(in.localFQDN, strings.ToLower(req.Sender)) < 0 {
				s.reject(ctx, w, http.StatusConflict, CauseExchangeOngoing, "",
					"own exchange-capability ongoing", lg...)
				return
			}
			s.abandonInflight(peer.PLMN)
			s.plog(ctx, "IN").Info("own outgoing exchange-capability abandoned", append(lg,
				"spec_ref", specStep2b)...)
		}
	}

	local := s.cfg.TargetAPIRootSupported
	both := local && req.TargetAPIRootSupported
	c := Context{
		RemotePLMN: peer.PLMN, SecCapability: CapTLS, TargetAPIRootHeader: both,
		Features: negotiated, NFTLST: negotiated.Has(featureNFTLST),
		PeerFQDN: strings.ToLower(req.Sender), CertPLMNs: peerCertPLMNs(peer), CreatedAt: s.cfg.Now(),
	}
	// Delete the previous context (and its N32-f connections), then create.
	_, existed := s.store.Replace(c)

	rsp := SecNegotiateRspData{
		Sender:                 s.cfg.LocalFQDN,
		SelectedSecCapability:  CapTLS,
		TargetAPIRootSupported: both,
		PlmnIDList:             []PlmnId{s.cfg.LocalPLMN},
		SupportedFeatures:      rspFeatures,
		AllowedUsagePurpose:    allowed,
		RejectedUsagePurpose:   rejected,
	}
	writeFinalJSON(w, http.StatusOK, rsp)
	countResult(resultOK)
	s.record(peer.PLMN, RoleResponder, resultOK, "")
	s.plog(ctx, "IN").Info("exchange-capability accepted", append(lg,
		"result", resultOK, "cause", logCauseAccepted, "selected", string(CapTLS), "target_api_root_header", both,
		"replaced", existed, "negotiated_features", negotiated.String(),
		"spec_ref", specStep2a)...)
	// The previous context's N32-f connections go after the response is out.
	if existed && s.cfg.Terminator != nil {
		s.cfg.Terminator(ctx, peer.PLMN, reasonReplace)
	}
}

// teardown handles supportedSecCapabilityList ["NONE"]. Ref: TS 29.573 §5.2.2 (NFTLST).
func (s *Service) teardown(ctx context.Context, w http.ResponseWriter, peer PeerIdentity, rspFeatures string, lg []any) {
	cur, ok := s.store.Get(peer.PLMN)
	if !ok || !cur.NFTLST {
		cause := logCauseNoContext
		if ok {
			cause = "nftlst_not_negotiated"
		}
		s.reject(ctx, w, http.StatusForbidden, CauseNegotiationNotAllowed, cause,
			"NONE requires a context with feature NFTLST", lg...)
		return
	}
	s.store.Delete(peer.PLMN)
	writeFinalJSON(w, http.StatusOK, SecNegotiateRspData{
		Sender: s.cfg.LocalFQDN, SelectedSecCapability: CapNone,
		PlmnIDList: []PlmnId{s.cfg.LocalPLMN}, SupportedFeatures: rspFeatures,
	})
	countResult(resultOK)
	s.record(peer.PLMN, RoleResponder, resultOK, "teardown")
	s.plog(ctx, "IN").Info("N32-f TLS teardown accepted", append(lg,
		"result", resultOK, "selected", string(CapNone), "spec_ref", specStep2a)...)
	if s.cfg.Terminator != nil {
		s.cfg.Terminator(ctx, peer.PLMN, reasonTeardown)
	}
}

// writeFinalJSON writes the 200 that ends the N32-c connection and flushes it.
// "Connection: close" makes the net/http HTTP/1 server close the connection
// and the x/net http2 server send GOAWAY and tear the connection down once the
// stream completes: when TLS is selected (or on NONE) the HTTP/2 connection
// used for the handshake is terminated. Ref: TS 29.573 §5.2.2.
func writeFinalJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Connection", "close")
	writeJSON(w, status, v)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// serverHeaderPrefix: Server header of SEPP-originated errors, "SEPP-<FQDN>".
const serverHeaderPrefix = "SEPP-"

// certPLMNSet returns the canonical keys of the PLMNs of the verified peer
// certificate (PeerIdentity.PLMNs, filled by CertPeerIdentity, which fails
// when there is no TLS state). Only an identity injected by a test lacks the
// set; it then stands for {PLMN}. Ref: TS 33.501 §13.1.2.
func certPLMNSet(peer PeerIdentity) map[string]bool {
	set := map[string]bool{peer.PLMN.Key(): true}
	for _, p := range peer.PLMNs {
		set[p.Key()] = true
	}
	return set
}

// senderUnderCertDomain reports whether sender ends in
// ".5gc.mnc<MNC3>.mcc<MCC>.3gppnetwork.org" for a certificate PLMN.
// Ref: TS 23.003 §28.5.1.
func senderUnderCertDomain(sender string, plmns map[string]bool) bool {
	s := strings.TrimSuffix(strings.ToLower(sender), ".")
	for k := range plmns {
		mcc, mnc, _ := strings.Cut(k, "-")
		if strings.HasSuffix(s, ".5gc.mnc"+mnc+".mcc"+mcc+"."+homeNetworkDomainSuffix) {
			return true
		}
	}
	return false
}

// peerCertPLMNs is the PLMN set stored in the N32 context: the certificate
// set, or {PLMN} for an identity without one.
func peerCertPLMNs(id PeerIdentity) []PlmnId {
	if len(id.PLMNs) > 0 {
		return append([]PlmnId(nil), id.PLMNs...)
	}
	return []PlmnId{id.PLMN.Canonical()}
}
