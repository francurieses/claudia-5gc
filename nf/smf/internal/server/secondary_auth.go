package server

// Secondary Authentication / Authorization by a DN-AAA Server.
// Ref: TS 23.501 §5.6.6, TS 23.502 §4.3.2.3, TS 24.501 §8.3.5-§8.3.7 (EAP-in-
// 5GSM), TS 24.501 §9.11.4.2 (5GSM cause), RFC 3748 (EAP framing).
// See docs/procedures/SecondaryAuthentication.md for the full sequence
// diagram and known limitations.
//
// The SMF acts as an EAP pass-through authenticator: it relays the UE's EAP
// packets (received over N1, via the AMF) to a Data Network AAA server
// reached over N6, and gates PDU Session Establishment on the terminal EAP
// result. This MVP implements the "external DN-AAA over N6" variant only
// (TS 23.502 §4.3.2.3) with the DN-AAA itself SIMULATED in-core (single EAP
// round: Identity → Success/Failure), the same posture as the AUSF NSSAA
// relay (nf/ausf/internal/server/nssaa.go) and NW-Triggered PDU Session
// steering. The DNAAAClient seam below is the swap point for a real
// RADIUS/Diameter N6 client.
//
// KNOWN LIMITATION — AMF integration gap (not fixable within this NF-scoped
// task): the AMF's Nsmf_PDUSession_CreateSMContext caller
// (nf/amf/internal/nas/nas.go, handleULNASTransport PDU-session branch)
// unconditionally wraps whatever bytes the SMF returns as n1SmMsg with the
// PDU SESSION ESTABLISHMENT ACCEPT header (WrapPDUSessionEstablishmentAcceptBody),
// and the AMF's N1N2MessageTransfer producer does not yet forward the N1/N2
// payload to a CM-CONNECTED UE (see nf/amf/CLAUDE.md §15). Live delivery of
// the AUTH COMMAND/RESULT/REJECT to a real UE therefore needs a follow-up AMF
// change; UERANSIM v3.2.8 has no secondary-auth UE peer to exercise it
// against in the meantime, so this SMF-side implementation is validated by
// unit + functional tests that call the handlers directly (same posture as
// NSSAA, EAP-AKA', URSP).

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/francurieses/claudia-5gc/shared/crypto/eap"
	"github.com/francurieses/claudia-5gc/shared/logging"
	"github.com/francurieses/claudia-5gc/shared/nas"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

// secondaryAuthSpecRef is the TS 23.502 clause governing the whole secondary
// authentication procedure; used as the "spec_ref" OTel span/log attribute
// on every leg of the state machine below.
const secondaryAuthSpecRef = "TS 23.502 §4.3.2.3"

// secondaryAuthState models the per-PDU-session EAP relay state machine.
// Mirrors the NSSAA AMF state machine (AMF-005). Ref: TS 23.501 §5.6.6.
type secondaryAuthState string

const (
	// authStatePendingAuth: AUTH COMMAND sent (EAP-Request), awaiting the
	// UE's AUTH COMPLETE.
	authStatePendingAuth secondaryAuthState = "PENDING_AUTH"
	// authStateAwaitingAAA: AUTH COMPLETE received, EAP relayed to the
	// DN-AAA, awaiting its terminal result.
	authStateAwaitingAAA secondaryAuthState = "AWAITING_AAA"
	// authStateAuthorized: EAP-Success — proceed to N4 PFCP + ACCEPT.
	authStateAuthorized secondaryAuthState = "AUTHORIZED"
	// authStateRejected: EAP-Failure/timeout — ESTABLISHMENT REJECT sent.
	authStateRejected secondaryAuthState = "REJECTED"
)

// eapIdentifierInitial is the EAP identifier the SMF assigns to the first
// (and, for the simulated DN-AAA, only) EAP-Request/Identity of a secondary
// authentication round.
const eapIdentifierInitial byte = 1

// SecondaryAuthDNAAATimeout bounds the SMF's wait for the DN-AAA EAP result
// over N6 (RADIUS/Diameter in a real deployment). TS 23.502 §4.3.2.3 does not
// mandate an explicit timer value for this leg; this is an operator-
// configured guard so a stuck/unreachable DN-AAA yields a clean
// ESTABLISHMENT REJECT instead of hanging PDU Session Establishment
// indefinitely.
const SecondaryAuthDNAAATimeout = 5 * time.Second

// pendingSecondaryAuth holds per-PDU-session EAP relay state while the SMF
// waits for the UE's PDU SESSION AUTHENTICATION COMPLETE and the DN-AAA's
// terminal EAP result. The address material (IPv4/IPv6) and per-session
// identifiers (TEID/SEID) are reserved up front (at CreateSMContext time) so
// they can be released cleanly on rejection, and reused unchanged on
// authorization.
type pendingSecondaryAuth struct {
	SmContextRef string
	SUPI         string
	DNN          string
	PDUSessionID uint8
	PTI          uint8
	Slice        SliceID
	State        secondaryAuthState
	CreatedAt    time.Time

	GrantedType uint8
	IPv4        net.IP
	V6Prefix    *net.IPNet
	V6IID       []byte

	// PCORequest is the UE's decoded PDU SESSION ESTABLISHMENT REQUEST held
	// from CreateSMContext so the post-authorization ACCEPT can answer the
	// UE's (E)PCO container list in the UE's own order (nas.BuildEPCOReply)
	// and emit the #50/#51 downgrade cause. Nil when the request did not
	// decode. Ref: TS 24.008 §10.5.6.3, TS 24.501 §9.11.4.2.
	PCORequest *nas.PDUSessionEstablishmentRequest

	ULTEID uint32
	SEID   uint64
}

// DNAAAClient is the SMF's seam onto the Data Network AAA server reached over
// N6 (TS 23.501 §5.6.6). A production implementation would speak RADIUS or
// Diameter to a real external AAA-S; this MVP wires the in-core simulated
// implementation below by default. Tests inject their own implementation.
type DNAAAClient interface {
	// Authenticate relays one EAP round (the UE's EAP-Response, e.g.
	// EAP-Response/Identity) to the DN-AAA for the given DNN and returns the
	// terminal EAP packet (EAP-Success or EAP-Failure). A non-nil error
	// models an unreachable or timing-out DN-AAA.
	Authenticate(ctx context.Context, dnn string, eapResponse []byte) ([]byte, error)
}

// simulatedDNAAAClient is the in-core simulated DN-AAA: a single EAP round
// (Identity → Success/Failure), deterministic decision — mirrors
// nf/ausf/internal/server/nssaa.go's simulated AAA-S. It rejects when the
// EAP-Response/Identity NAI contains "reject" (case-insensitive), and treats
// the DNNs listed in unreachableDNNs as unreachable/timing-out (dev/test
// knob, TS 24.501 §9.11.4.2 unreachable/timeout error case).
type simulatedDNAAAClient struct {
	unreachableDNNs map[string]bool
}

func newSimulatedDNAAAClient(unreachableDNNs map[string]bool) *simulatedDNAAAClient {
	return &simulatedDNAAAClient{unreachableDNNs: unreachableDNNs}
}

func (a *simulatedDNAAAClient) Authenticate(ctx context.Context, dnn string, eapResponse []byte) ([]byte, error) {
	if a.unreachableDNNs[dnn] {
		return nil, fmt.Errorf("smf: dn-aaa unreachable for dnn %q", dnn)
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("smf: dn-aaa relay: %w", err)
	}
	if err := eap.Validate(eapResponse); err != nil {
		return nil, fmt.Errorf("smf: malformed EAP response from UE: %w", err)
	}
	identifier, _ := eap.Identifier(eapResponse)
	identity, idErr := eap.Identity(eapResponse)
	if idErr != nil || strings.Contains(strings.ToLower(identity), "reject") {
		return eap.BuildFailure(identifier), nil
	}
	return eap.BuildSuccess(identifier), nil
}

// secondaryAuthRequired reports whether the DNN requires DN-AAA secondary
// authentication/authorization (TS 23.501 §5.6.6). A DNN not explicitly
// configured with secondary_auth: true establishes exactly as before — no
// regression for existing DNNs (internet, ims, ...).
func (s *Server) secondaryAuthRequired(dnn string) bool {
	return s.secondaryAuthDNNs[dnn]
}

func (s *Server) storePendingAuth(p *pendingSecondaryAuth) {
	s.pendingAuthMu.Lock()
	defer s.pendingAuthMu.Unlock()
	s.pendingAuth[p.SmContextRef] = p
	metrics.SMFSecondaryAuthPending.Inc()
}

func (s *Server) getPendingAuth(smContextRef string) *pendingSecondaryAuth {
	s.pendingAuthMu.Lock()
	defer s.pendingAuthMu.Unlock()
	return s.pendingAuth[smContextRef]
}

func (s *Server) deletePendingAuth(smContextRef string) {
	s.pendingAuthMu.Lock()
	defer s.pendingAuthMu.Unlock()
	if _, ok := s.pendingAuth[smContextRef]; ok {
		delete(s.pendingAuth, smContextRef)
		metrics.SMFSecondaryAuthPending.Dec()
	}
}

// startSecondaryAuth gates PDU Session Establishment on a DN-AAA EAP exchange
// (TS 23.501 §5.6.6, TS 23.502 §4.3.2.3). Called from handleCreateSMContext
// once the DNN has been resolved to require secondary auth and the address
// material has already been reserved by the caller. It stores the pending
// state and pushes a PDU SESSION AUTHENTICATION COMMAND (EAP-Request/Identity)
// towards the UE via Namf_Communication_N1N2MessageTransfer.
func (s *Server) startSecondaryAuth(ctx context.Context, pending *pendingSecondaryAuth) {
	log := logging.NewProcedureLogger(ctx, s.logger, "SecondaryAuthentication")

	pending.State = authStatePendingAuth
	pending.CreatedAt = time.Now()
	s.storePendingAuth(pending)

	eapReq := eap.BuildIdentityRequest(eapIdentifierInitial)
	n1Msg := nas.WrapPDUSessionAuthenticationCommandBody(pending.PDUSessionID, pending.PTI, eapReq)

	log.Info("secondary authentication started — AUTH COMMAND built",
		"nf", "SMF", "interface", "N1", "direction", "OUT",
		"spec_ref", "TS 23.502 §4.3.2.3 step 3",
		"supi", pending.SUPI, "pdu_session_id", pending.PDUSessionID, "dnn", pending.DNN,
	)
	// Not a terminal exit of the procedure — the ProcedureTotal{result=...}
	// counter is incremented once at the terminal AUTHORIZED/REJECTED
	// transition (completeSecondaryAuth / rejectSecondaryAuth /
	// handleSecondaryAuthComplete's early-return error branches), matching
	// the "one increment per procedure completion" convention used by every
	// other NF. SMFSecondaryAuthPending (incremented in storePendingAuth
	// above) tracks the in-flight state instead.
	if span := trace.SpanFromContext(ctx); span != nil {
		span.SetAttributes(
			attribute.String("supi", pending.SUPI),
			attribute.String("dnn", pending.DNN),
			attribute.Int("pdu_session_id", int(pending.PDUSessionID)),
			attribute.String("spec_ref", secondaryAuthSpecRef),
			attribute.Bool("secondary_auth_pending", true),
		)
	}

	if _, err := s.n1n2Push(ctx, pending.SUPI, pending.PDUSessionID, n1Msg, nil, ""); err != nil {
		log.Warn("secondary authentication: N1N2MessageTransfer for AUTH COMMAND failed",
			"nf", "SMF", "interface", "N1", "direction", "OUT", "error", err,
			"spec_ref", "TS 29.518 §5.2.2.3",
		)
	}
}

// pushN1N2Message sends Namf_Communication_N1N2MessageTransfer carrying an N1
// SM NAS message (and optionally N2 SM info) towards the UE via the AMF. Used
// for the SMF-initiated pushes of secondary authentication (AUTH COMMAND, and
// the terminal ESTABLISHMENT ACCEPT|REJECT), which — unlike the normal
// (non-gated) Establishment Accept — are not direct responses to a
// CreateSMContext/UpdateSMContext call. Mirrors the paging.go
// triggerN1N2MessageTransfer pattern, extended to carry an N1 SM payload.
// Ref: TS 29.518 §5.2.2.3, TS 23.502 §4.3.2.3.
func (s *Server) pushN1N2Message(ctx context.Context, supi string, psi uint8, n1SmMsg, n2SmInfo []byte, n2SmInfoType string) (string, error) {
	if s.cfg.Peers.AMF == "" {
		return "", fmt.Errorf("smf: amf SBI peer not configured")
	}
	payload := map[string]any{"pduSessionId": psi}
	if len(n1SmMsg) > 0 {
		payload["n1SmMsg"] = base64.StdEncoding.EncodeToString(n1SmMsg)
	}
	if len(n2SmInfo) > 0 {
		payload["n2SmInfo"] = base64.StdEncoding.EncodeToString(n2SmInfo)
		payload["n2SmInfoType"] = n2SmInfoType
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("smf: marshal N1N2 payload: %w", err)
	}
	u := fmt.Sprintf("https://%s/namf-comm/v1/ue-contexts/%s/n1-n2-messages",
		s.cfg.Peers.AMF, url.PathEscape(supi))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("smf: build N1N2 request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("smf: N1N2MessageTransfer: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return "", fmt.Errorf("smf: N1N2MessageTransfer: status %d", resp.StatusCode)
	}
	var rsp struct {
		Cause string `json:"cause"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&rsp)
	return rsp.Cause, nil
}

// handleSecondaryAuthComplete processes the UE's PDU SESSION AUTHENTICATION
// COMPLETE (0xC6), relayed by the AMF via Nsmf_PDUSession_UpdateSMContext. It
// relays the EAP-Response to the DN-AAA and, on the terminal result, either
// proceeds to N4 PFCP Session Establishment (EAP-Success) or releases the
// reserved UE IP and rejects the establishment (EAP-Failure / unreachable).
// Ref: TS 23.502 §4.3.2.3, TS 24.501 §8.3.6.
func (s *Server) handleSecondaryAuthComplete(w http.ResponseWriter, r *http.Request, smContextRef string, n1SmMsgBytes []byte) {
	log := logging.NewProcedureLogger(r.Context(), s.logger, "SecondaryAuthentication")

	psi := n1SmMsgBytes[1]

	span := trace.SpanFromContext(r.Context())

	eapResp, err := nas.DecodePDUSessionAuthenticationCompleteBody(n1SmMsgBytes[4:])
	if err != nil {
		log.Warn("AUTH COMPLETE: malformed EAP message IE",
			"nf", "SMF", "interface", "N1", "direction", "IN",
			"spec_ref", "TS 24.501 §9.11.2.2", "result", "REJECT", "error", err,
		)
		if span != nil {
			span.RecordError(err)
			span.SetAttributes(
				attribute.String("result", "REJECT"),
				attribute.String("spec_ref", "TS 24.501 §9.11.2.2"),
			)
			span.SetStatus(codes.Error, "malformed EAP message IE in AUTH COMPLETE")
		}
		metrics.ProcedureTotal.WithLabelValues("SMF", "SecondaryAuthentication", "REJECT").Inc()
		problem(w, http.StatusBadRequest, "INVALID_MANDATORY_INFORMATION", err.Error())
		return
	}

	pending := s.getPendingAuth(smContextRef)
	if pending == nil {
		log.Warn("AUTH COMPLETE: no pending secondary authentication for sm context",
			"nf", "SMF", "smContextRef", smContextRef, "result", "REJECT")
		if span != nil {
			span.SetAttributes(
				attribute.String("result", "REJECT"),
				attribute.String("spec_ref", secondaryAuthSpecRef),
			)
			span.SetStatus(codes.Error, "no pending secondary authentication for sm context")
		}
		metrics.ProcedureTotal.WithLabelValues("SMF", "SecondaryAuthentication", "REJECT").Inc()
		problem(w, http.StatusNotFound, "CONTEXT_NOT_FOUND", "no pending secondary authentication for this sm context")
		return
	}

	if span != nil {
		span.SetAttributes(
			attribute.String("supi", pending.SUPI),
			attribute.String("dnn", pending.DNN),
			attribute.Int("pdu_session_id", int(psi)),
			attribute.String("spec_ref", secondaryAuthSpecRef),
		)
	}

	log.Info("AUTH COMPLETE received — relaying EAP-Response to DN-AAA over N6",
		"nf", "SMF", "interface", "N1", "direction", "IN",
		"spec_ref", "TS 23.502 §4.3.2.3 step 5",
		"supi", pending.SUPI, "pdu_session_id", psi, "dnn", pending.DNN,
	)
	pending.State = authStateAwaitingAAA

	// Detach from the HTTP request context (which is cancelled the instant
	// this handler returns) but still bound by the DN-AAA relay timeout.
	detached := context.WithoutCancel(r.Context())
	aaCtx, cancel := context.WithTimeout(detached, SecondaryAuthDNAAATimeout)
	terminal, aaErr := s.dnAAA.Authenticate(aaCtx, pending.DNN, eapResp)
	cancel()

	if aaErr != nil {
		log.Warn("DN-AAA unreachable/timeout — rejecting PDU session establishment",
			"nf", "SMF", "interface", "N6", "direction", "OUT",
			"spec_ref", "TS 24.501 §9.11.4.2",
			"supi", pending.SUPI, "pdu_session_id", psi, "dnn", pending.DNN,
			"result", "REJECT", "cause", nas.Cause5GSMUserAuthOrAuthorizationFailed, "error", aaErr,
		)
		s.rejectSecondaryAuth(detached, pending, nil, log)
		w.WriteHeader(http.StatusOK)
		return
	}

	code, _ := eap.Code(terminal)
	if code == eap.CodeSuccess {
		log.Info("DN-AAA returned EAP-Success — proceeding to N4",
			"nf", "SMF", "interface", "N6", "direction", "IN",
			"spec_ref", "TS 23.502 §4.3.2.3 step 6",
			"supi", pending.SUPI, "pdu_session_id", psi, "dnn", pending.DNN, "result", "OK",
		)
		s.completeSecondaryAuth(detached, pending, terminal, log)
	} else {
		log.Info("DN-AAA returned EAP-Failure — rejecting PDU session establishment",
			"nf", "SMF", "interface", "N6", "direction", "IN",
			"spec_ref", "TS 24.501 §9.11.4.2",
			"supi", pending.SUPI, "pdu_session_id", psi, "dnn", pending.DNN,
			"result", "REJECT", "cause", nas.Cause5GSMUserAuthOrAuthorizationFailed,
		)
		s.rejectSecondaryAuth(detached, pending, terminal, log)
	}
	w.WriteHeader(http.StatusOK)
}

// completeSecondaryAuth finalises a successful secondary authentication:
// fetches the subscribed QoS + PCF policy (deferred from CreateSMContext so a
// session that is ultimately rejected never touches the PCF), activates the
// session, triggers N4 PFCP Session Establishment, and pushes the terminal
// PDU SESSION ESTABLISHMENT ACCEPT (carrying EAP-Success, IEI 0x78) towards
// the UE. Ref: TS 23.502 §4.3.2.3 steps 7-9.
func (s *Server) completeSecondaryAuth(ctx context.Context, pending *pendingSecondaryAuth, eapSuccess []byte, log *slog.Logger) {
	s.deletePendingAuth(pending.SmContextRef)
	pending.State = authStateAuthorized

	subQoS := s.fetchSubscribedQoS(ctx, pending.SUPI, pending.DNN, pending.Slice)
	ueIPv4Str := ""
	if pending.IPv4 != nil {
		ueIPv4Str = pending.IPv4.String()
	}
	smPolicyID, policyQoS := s.createSMPolicy(ctx, pending.SUPI, pending.DNN, ueIPv4Str, pending.Slice, subQoS)

	var v6PrefixStr string
	if pending.V6Prefix != nil {
		v6PrefixStr = pending.V6Prefix.String()
	}

	sess := &Session{
		SUPI:           pending.SUPI,
		PDUSessionID:   pending.PDUSessionID,
		DNN:            pending.DNN,
		UEIP:           pending.IPv4,
		ULTEID:         pending.ULTEID,
		SEID:           pending.SEID,
		SliceID:        pending.Slice,
		SmPolicyID:     smPolicyID,
		FiveQI:         policyQoS.FiveQI,
		ARPPriority:    policyQoS.ARPPriority,
		AMBRULMbps:     policyQoS.AMBRULMbps,
		AMBRDLMbps:     policyQoS.AMBRDLMbps,
		QoSSource:      policyQoS.Source,
		State:          "ACTIVE",
		CreatedAt:      time.Now(),
		PDUSessionType: pending.GrantedType,
		UEIPv6Prefix:   v6PrefixStr,
	}
	s.sessionMu.Lock()
	s.sessions[pending.SmContextRef] = sess
	s.sessionMu.Unlock()
	s.persistSession(ctx, pending.SmContextRef, sess)
	metrics.PDUSessionTotal.WithLabelValues("SMF", pending.DNN, "OK").Inc()
	metrics.PDUSessionsActive.WithLabelValues("SMF", pending.DNN).Inc()

	if pending.IPv4 != nil || pduTypeNeedsIPv6(pending.GrantedType) {
		go s.sendPFCPSessionEstablishment(context.Background(), sess)
	}

	// EAP message IE (0x78) must precede the Authorized QoS flow descriptions
	// IE (0x79) and the DNN IE (0x25) per TS 24.501 §8.3.2 Table 8.3.2.1.1 —
	// the params encoder places it in the spec-correct slot. The EPCO answers
	// the held UE request (container order + IPCP) and carries the DNN's DNS
	// resolvers, exactly like the non-secondary-auth ACCEPT path.
	n1Body, err := nas.EncodeEstablishmentAcceptBody(nas.EstablishmentAcceptParams{
		Addr:       nas.PDUAddressInfo{SessionType: pending.GrantedType, IPv4: pending.IPv4, IPv6IID: pending.V6IID},
		SSCMode:    nas.SSCMode1,
		DNN:        pending.DNN,
		QFI:        1, // QFI=1 for default flow
		FiveQI:     policyQoS.FiveQI,
		DLMbps:     policyQoS.AMBRDLMbps,
		ULMbps:     policyQoS.AMBRULMbps,
		DNSv4:      s.dnsServersFor(pending.DNN),
		MTU:        nas.DefaultIPv4LinkMTU,
		SNSSAI:     []nas.SNSSAI{{SST: pending.Slice.SST, SD: nas.SDFromString(pending.Slice.SD)}},
		EAPMessage: eapSuccess,
		Request:    pending.PCORequest,
	})
	if err != nil {
		log.Error("secondary auth: Establishment Accept body encoding failed",
			"error", err, "supi", pending.SUPI, "pdu_session_id", pending.PDUSessionID)
		return
	}
	n1Accept := nas.WrapPDUSessionEstablishmentAcceptBody(pending.PDUSessionID, pending.PTI, n1Body)

	n2SmInfo, err := buildPDUSessionResourceSetupRequestTransfer(
		net.ParseIP(s.cfg.UPFN3Addr), pending.ULTEID, 1, int64(policyQoS.FiveQI),
		int64(policyQoS.AMBRULMbps)*1_000_000, int64(policyQoS.AMBRDLMbps)*1_000_000,
		ngapPDUSessionType(pending.GrantedType),
	)
	if err != nil {
		log.Error("secondary auth: N2SM Transfer encoding failed", "error", err)
		n2SmInfo = nil
	}

	log.Info("secondary authentication authorized — ESTABLISHMENT ACCEPT built",
		"nf", "SMF", "interface", "N1", "direction", "OUT",
		"spec_ref", "TS 23.502 §4.3.2.3 step 9",
		"supi", pending.SUPI, "pdu_session_id", pending.PDUSessionID, "dnn", pending.DNN,
		"5qi", policyQoS.FiveQI, "result", "OK",
	)
	if span := trace.SpanFromContext(ctx); span != nil {
		span.SetAttributes(
			attribute.String("result", "OK"),
			attribute.String("spec_ref", secondaryAuthSpecRef),
			attribute.Int("5qi", int(policyQoS.FiveQI)),
		)
		span.SetStatus(codes.Ok, "")
	}
	metrics.ProcedureTotal.WithLabelValues("SMF", "SecondaryAuthentication", "OK").Inc()
	if _, err := s.n1n2Push(ctx, pending.SUPI, pending.PDUSessionID, n1Accept, n2SmInfo, "PDU_RES_SETUP_REQ"); err != nil {
		log.Warn("secondary auth: N1N2MessageTransfer for ESTABLISHMENT ACCEPT failed",
			"error", err, "spec_ref", "TS 29.518 §5.2.2.3")
	}
}

// rejectSecondaryAuth tears down a failed secondary authentication: releases
// the reserved UE IP address(es), drops the pending/session state, and pushes
// the terminal PDU SESSION ESTABLISHMENT REJECT (5GSM cause #29, optionally
// carrying EAP-Failure in IEI 0x78) towards the UE. No N4 session is ever
// created. Ref: TS 24.501 §9.11.4.2, TS 23.502 §4.3.2.3.
func (s *Server) rejectSecondaryAuth(ctx context.Context, pending *pendingSecondaryAuth, eapFailure []byte, log *slog.Logger) {
	s.deletePendingAuth(pending.SmContextRef)
	pending.State = authStateRejected

	s.sessionMu.Lock()
	delete(s.sessions, pending.SmContextRef)
	s.sessionMu.Unlock()
	s.deleteSession(ctx, pending.SmContextRef)

	if pending.IPv4 != nil {
		pool := s.ipPools[pending.DNN]
		if pool == nil {
			pool = s.ipPools["internet"]
		}
		if pool != nil {
			pool.Release(pending.IPv4)
		}
	}
	if pending.V6Prefix != nil {
		if v6pool := s.ipv6Pools[pending.DNN]; v6pool != nil {
			v6pool.Release(pending.V6Prefix)
		}
	}

	metrics.PDUSessionTotal.WithLabelValues("SMF", pending.DNN, "FAILURE").Inc()

	n1Reject := nas.WrapPDUSessionEstablishmentRejectBody(
		pending.PDUSessionID, pending.PTI, nas.Cause5GSMUserAuthOrAuthorizationFailed, eapFailure)

	log.Info("secondary authentication rejected — ESTABLISHMENT REJECT built",
		"nf", "SMF", "interface", "N1", "direction", "OUT",
		"spec_ref", "TS 24.501 §9.11.4.2",
		"supi", pending.SUPI, "pdu_session_id", pending.PDUSessionID, "dnn", pending.DNN,
		"result", "REJECT", "cause", nas.Cause5GSMUserAuthOrAuthorizationFailed,
	)
	if span := trace.SpanFromContext(ctx); span != nil {
		span.SetAttributes(
			attribute.String("result", "REJECT"),
			attribute.Int("cause", int(nas.Cause5GSMUserAuthOrAuthorizationFailed)),
			attribute.String("spec_ref", "TS 24.501 §9.11.4.2"),
		)
		span.SetStatus(codes.Error, "secondary authentication rejected — 5GSM cause #29")
	}
	metrics.ProcedureTotal.WithLabelValues("SMF", "SecondaryAuthentication", "REJECT").Inc()
	if _, err := s.n1n2Push(ctx, pending.SUPI, pending.PDUSessionID, n1Reject, nil, ""); err != nil {
		log.Warn("secondary auth: N1N2MessageTransfer for ESTABLISHMENT REJECT failed",
			"error", err, "spec_ref", "TS 29.518 §5.2.2.3")
	}
}
