package n32c

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/francurieses/claudia-5gc/shared/logging"
	"github.com/francurieses/claudia-5gc/shared/sbi/apiversion"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

// Initiator error classes (use errors.Is).
var (
	// ErrNegotiationNotAllowed: peer answered 403 NEGOTIATION_NOT_ALLOWED (E1). Do not retry.
	ErrNegotiationNotAllowed = errors.New("n32c: negotiation not allowed")
	// ErrForbidden: peer answered 403 with another cause (E2/E3 on the peer side).
	ErrForbidden = errors.New("n32c: forbidden by peer")
	// ErrCollision: peer answered 409 N32C_EXCHANGE_CAPABILITY_ONGOING; the peer's own request wins.
	ErrCollision = errors.New("n32c: exchange-capability collision, peer continues")
	// ErrInvalidSelected: the selected capability was not offered or is PRINS/unknown.
	ErrInvalidSelected = errors.New("n32c: invalid selected security capability")
	// ErrPeerStatus: any other non-200 status.
	ErrPeerStatus = errors.New("n32c: unexpected peer status")
	// ErrResponderIdentity: the responder's certificate or body PLMN does not match the target.
	ErrResponderIdentity = errors.New("n32c: responder identity mismatch")
	// ErrTeardownNotAllowed: NONE needs a stored context with NFTLST negotiated.
	ErrTeardownNotAllowed = errors.New("n32c: teardown requires negotiated NFTLST")
)

// Exchange runs the initiator side of the Security Capability Negotiation
// towards peerAPIRoot and stores the N32 context on 200 OK. It offers TLS only.
// Ref: TS 29.573 §5.2.2 step 1.
func (s *Service) Exchange(ctx context.Context, peerAPIRoot string, targetPLMN PlmnId) (Context, error) {
	if s.cfg.HTTPClient == nil {
		return Context{}, errors.New("n32c: exchange: no HTTP client configured")
	}
	if ctx.Err() != nil {
		return Context{}, fmt.Errorf("n32c: exchange: %w", ctx.Err())
	}
	if logging.CorrelationID(ctx) == "" {
		ctx = logging.WithCorrelationID(ctx, "")
	}
	cctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	tok := s.registerInflight(targetPLMN, cancel)
	defer s.clearInflight(tok)

	// supportedFeatures is sent whenever at least one feature is supported,
	// under both profiles (TS 29.573 §6.1.7; NFTLST must be offered for
	// teardown to become possible).
	offer := s.offerFeatures()
	req := SecNegotiateReqData{
		Sender:                     s.cfg.LocalFQDN,
		SupportedSecCapabilityList: []SecurityCapability{CapTLS},
		TargetAPIRootSupported:     s.cfg.TargetAPIRootSupported,
		PlmnIDList:                 []PlmnId{s.cfg.LocalPLMN},
		TargetPlmnID:               &targetPLMN,
		IntendedUsagePurpose:       []IntendedN32Purpose{{UsagePurpose: PurposeRoaming}},
		SupportedFeatures:          offer,
	}
	lg := s.plog(cctx, "OUT").With("peer_plmn", targetPLMN.String())
	var rsp SecNegotiateRspData
	rspMeta, err := s.post(cctx, peerAPIRoot, req, &rsp)
	if err != nil {
		if errors.Is(context.Cause(cctx), ErrAbandoned) {
			err = ErrAbandoned
		}
		countResult(resultFailure)
		lg.Warn("exchange-capability failed", "result", resultFailure, "cause", err.Error(), "spec_ref", specStep1)
		return Context{}, fmt.Errorf("n32c: exchange: %w", err)
	}
	if rsp.SelectedSecCapability != CapTLS { // offered only TLS; PRINS/NONE/unknown are invalid
		countResult(resultFailure)
		lg.Warn("exchange-capability invalid selection", "result", resultFailure,
			"cause", "invalid_selected_capability", "selected", string(rsp.SelectedSecCapability), "spec_ref", specStep2a)
		return Context{}, fmt.Errorf("n32c: exchange: selected %q: %w", rsp.SelectedSecCapability, ErrInvalidSelected)
	}
	// H1: the responder is authenticated by its server certificate, not by
	// the body. A re-check of the collision cause guards the store update.
	id, ierr := s.cfg.ResponderIdentity(rspMeta)
	if ierr == nil && id.PLMN.Key() != targetPLMN.Key() {
		ierr = fmt.Errorf("n32c: responder certificate PLMN %s is not the target %s", id.PLMN, targetPLMN)
	}
	if ierr == nil {
		ierr = checkResponseConsistency(rsp, targetPLMN)
	}
	if ierr != nil {
		countResult(resultFailure)
		lg.Warn("responder verification failed", "result", resultFailure,
			"cause", "responder_identity_mismatch", "error", ierr.Error(), "spec_ref", "TS 33.501 §13.1.2")
		return Context{}, fmt.Errorf("n32c: exchange: verify responder: %w: %w", ErrResponderIdentity, ierr)
	}
	if errors.Is(context.Cause(cctx), ErrAbandoned) {
		countResult(resultFailure)
		lg.Warn("exchange abandoned before storing context", "result", resultFailure,
			"cause", "abandoned", "spec_ref", specStep2b)
		return Context{}, fmt.Errorf("n32c: exchange: %w", ErrAbandoned)
	}
	neg, ferr := features.Accept(offer, rsp.SupportedFeatures)
	if ferr != nil {
		lg.Warn("peer supportedFeatures ignored", "cause", ferr.Error(), "spec_ref", "TS 29.500 §6.6.2")
	}
	c := Context{
		RemotePLMN: targetPLMN, SecCapability: CapTLS,
		TargetAPIRootHeader: s.cfg.TargetAPIRootSupported && rsp.TargetAPIRootSupported,
		Features:            neg, NFTLST: neg.Has(featureNFTLST),
		PeerFQDN: id.FQDN, CreatedAt: s.cfg.Now(),
	}
	if _, existed := s.store.Replace(c); existed && s.cfg.Terminator != nil {
		s.cfg.Terminator(cctx, targetPLMN, reasonReplace)
	}
	// The N32-c HTTP/2 connection is terminated once TLS is selected.
	s.cfg.HTTPClient.CloseIdleConnections()
	countResult(resultOK)
	lg.Info("exchange-capability completed", "result", resultOK, "selected", string(CapTLS), "spec_ref", specStep2a)
	return c, nil
}

// Teardown asks the peer to close the N32-f TLS connection by offering only
// NONE; allowed only if NFTLST was negotiated. Ref: TS 29.573 §5.2.2.
func (s *Service) Teardown(ctx context.Context, peerAPIRoot string, remote PlmnId) error {
	if s.cfg.HTTPClient == nil {
		return errors.New("n32c: teardown: no HTTP client configured")
	}
	cur, ok := s.store.Get(remote)
	if !ok || !cur.NFTLST {
		return fmt.Errorf("n32c: teardown: %w", ErrTeardownNotAllowed)
	}
	if logging.CorrelationID(ctx) == "" {
		ctx = logging.WithCorrelationID(ctx, "")
	}
	lg := s.plog(ctx, "OUT").With("peer_plmn", remote.String())
	req := SecNegotiateReqData{
		Sender:                     s.cfg.LocalFQDN,
		SupportedSecCapabilityList: []SecurityCapability{CapNone},
		PlmnIDList:                 []PlmnId{s.cfg.LocalPLMN},
	}
	req.SupportedFeatures = s.offerFeatures()
	var rsp SecNegotiateRspData
	rspMeta, err := s.post(ctx, peerAPIRoot, req, &rsp)
	if err != nil {
		countResult(resultFailure)
		lg.Warn("teardown failed", "result", resultFailure, "cause", err.Error(), "spec_ref", specStep1)
		return fmt.Errorf("n32c: teardown: %w", err)
	}
	if id, ierr := s.cfg.ResponderIdentity(rspMeta); ierr != nil || id.PLMN.Key() != remote.Key() {
		countResult(resultFailure)
		lg.Warn("responder verification failed", "result", resultFailure,
			"cause", "responder_identity_mismatch", "spec_ref", "TS 33.501 §13.1.2")
		return fmt.Errorf("n32c: teardown: verify responder: %w", ErrResponderIdentity)
	}
	if rsp.SelectedSecCapability != CapNone {
		lg.Warn("teardown rejected: responder selected a capability other than NONE", "result", resultFailure,
			"cause", "unexpected_selected_capability", "selected", string(rsp.SelectedSecCapability), "spec_ref", specStep2a)
		return fmt.Errorf("n32c: teardown: selected %q: %w", rsp.SelectedSecCapability, ErrInvalidSelected)
	}
	if cerr := checkResponseConsistency(rsp, remote); cerr != nil {
		countResult(resultFailure)
		lg.Warn("responder verification failed", "result", resultFailure,
			"cause", "responder_identity_mismatch", "error", cerr.Error(), "spec_ref", "TS 33.501 §13.1.2")
		return fmt.Errorf("n32c: teardown: verify responder: %w: %w", ErrResponderIdentity, cerr)
	}
	s.store.Delete(remote)
	// Both SEPPs terminate the N32-c and N32-f TLS connections (TS 29.573 §5.2.2).
	s.cfg.HTTPClient.CloseIdleConnections()
	if s.cfg.Terminator != nil {
		s.cfg.Terminator(ctx, remote, reasonTeardown)
	}
	countResult(resultOK)
	lg.Info("teardown completed", "result", resultOK, "spec_ref", specStep2a)
	return nil
}

// post sends req and decodes a 200 body into rsp; other statuses map to the
// error classes above.
func (s *Service) post(ctx context.Context, apiRoot string, req SecNegotiateReqData, rsp *SecNegotiateRspData) (*http.Response, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}
	url := strings.TrimRight(apiRoot, "/") + "/" + string(apiversion.N32cHandshake) + "/" +
		apiversion.Of(s.cfg.Profile, apiversion.N32cHandshake).InURI + exchangeCapabilityPath
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	hr.Header.Set("Content-Type", "application/json")
	hr.Header.Set("Accept", "application/json, application/problem+json")
	hr.Header.Set("X-Correlation-Id", logging.CorrelationID(ctx))
	resp, err := s.cfg.HTTPClient.Do(hr)
	if err != nil {
		return nil, fmt.Errorf("send: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode == http.StatusOK {
		if err := json.Unmarshal(body, rsp); err != nil {
			return nil, fmt.Errorf("decode response: %w", err)
		}
		if rsp.SelectedSecCapability == "" {
			return nil, fmt.Errorf("response without selectedSecCapability: %w", ErrInvalidSelected)
		}
		return resp, nil
	}
	var pd ProblemDetails
	_ = json.Unmarshal(body, &pd)
	switch {
	case resp.StatusCode == http.StatusForbidden && pd.Cause == CauseNegotiationNotAllowed:
		return nil, fmt.Errorf("status 403 cause %s: %w", pd.Cause, ErrNegotiationNotAllowed)
	case resp.StatusCode == http.StatusForbidden:
		return nil, fmt.Errorf("status 403 cause %q: %w", pd.Cause, ErrForbidden)
	case resp.StatusCode == http.StatusConflict && pd.Cause == CauseExchangeOngoing:
		return nil, fmt.Errorf("status 409: %w", ErrCollision)
	default:
		return nil, fmt.Errorf("status %d cause %q: %w", resp.StatusCode, pd.Cause, ErrPeerStatus)
	}
}

// offerFeatures is the supportedFeatures value this SEPP sends: the supported
// set under both profiles ("" only when nothing is supported).
func (s *Service) offerFeatures() string {
	sup := s.catalog.Supported(s.cfg.Profile)
	if sup.IsEmpty() {
		return ""
	}
	return sup.String()
}

// checkResponseConsistency requires the body to agree with the target: when
// sender is a 3gppnetwork.org FQDN its PLMN, and every plmnIdList entry, must
// be the target PLMN (TS 33.501 §13.1.2).
func checkResponseConsistency(rsp SecNegotiateRspData, target PlmnId) error {
	if p, err := ParsePLMNFromFQDN(rsp.Sender); err != nil || p.Key() != target.Key() {
		return fmt.Errorf("n32c: response sender %q is not in target PLMN %s", rsp.Sender, target)
	}
	for _, p := range rsp.PlmnIDList {
		if p.Key() != target.Key() {
			return fmt.Errorf("n32c: response plmnIdList entry %s is not the target PLMN %s", p, target)
		}
	}
	return nil
}
