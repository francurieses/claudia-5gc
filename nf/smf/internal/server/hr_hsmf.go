package server

// hr_hsmf.go — H-SMF role of the home-routed PDU session (ROAM-002, phase 1): Nsmf_PDUSession
// Create (POST /pdu-sessions) and Release (POST /pdu-sessions/{pduSessionRef}/release) served to
// the V-SMF over N16, and the N4 rule set installed on the H-UPF (N9 towards the V-UPF, N6 to the DN).
// Design: docs/procedures/HomeRoutedPduSession.md §4, §5, §7.4; behaviour: nf/smf/tests/features/
// home_routed_pdu_session.feature (@hsmf).
// Ref: TS 23.502 §4.3.2.2.2 steps 6-13, §4.3.4.3; TS 29.502 §5.2.2.7.1, §5.2.2.9; TS 23.501 §4.2.4.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	pfcpie "github.com/wmnsk/go-pfcp/ie"
	pfcpmsg "github.com/wmnsk/go-pfcp/message"

	"github.com/francurieses/claudia-5gc/shared/logging"
	"github.com/francurieses/claudia-5gc/shared/nas"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

// Log constants of the home-routed procedure.
const (
	hrProcedure = "HomeRoutedPduSession"
	hrSMFRole   = "H-SMF"
)

// hrN4Timeout bounds the H-SMF's wait for the H-UPF PFCP Session Establishment / Deletion
// Response (implementation guard, not a 3GPP timer; the V-SMF's N16 timeout must exceed it).
const hrN4Timeout = 8 * time.Second

// ohcGTPUUDPIPv4 is the Outer Header Creation Description for GTP-U/UDP/IPv4 (TS 29.244 §8.2.56).
const ohcGTPUUDPIPv4 uint16 = 0x0100

// hrSmDataError is a failed H-SMF subscription check: an application error cause + HTTP status.
type hrSmDataError struct {
	status int
	cause  string
	n1sm   int
	detail string
}

func (e *hrSmDataError) Error() string { return e.cause + ": " + e.detail }

// hrReject writes a PduSessionCreateError (application/json). n1sm < 0 omits n1smCause
// (it "shall be present if the request included n1SmInfoFromUe", TS 29.502 §5.2.2.7.1 step 2b).
func hrReject(ctx context.Context, log *slog.Logger, w http.ResponseWriter, status int, cause, detail string, n1sm int, params []HRInvalidParam) {
	body := PduSessionCreateError{Error: HRProblemDetails{
		Title: cause, Status: status, Cause: cause, Detail: detail, InvalidParams: params,
	}}
	if n1sm >= 0 {
		body.N1smCause = n1smCauseHex(n1sm)
	}
	w.Header().Set("Content-Type", mediaTypeJSON)
	w.WriteHeader(status)
	hrWriteJSON(ctx, log, w, body)
}

// hrWriteJSON encodes v as the response body; a write failure (client gone) is logged, never
// silently dropped. Ref: TS 29.502 §5.2.2.7.1.
// log must already carry an "interface" attribute.
func hrWriteJSON(ctx context.Context, log *slog.Logger, w http.ResponseWriter, v any) {
	_ = hrWriteJSONErr(ctx, log, w, v)
}

// hrWriteJSONErr is hrWriteJSON returning the write error, for callers that must roll back when the
// peer is gone (H-SMF 201, TS 29.502 §5.2.2.7.1).
func hrWriteJSONErr(ctx context.Context, log *slog.Logger, w http.ResponseWriter, v any) error {
	err := json.NewEncoder(w).Encode(v)
	if err != nil {
		log.WarnContext(ctx, "N16 response body not written", "direction", "OUT", "result", "FAILURE",
			"error", err, "spec_ref", "TS 29.502 §5.2.2.7.1")
	}
	return err
}

// hrBodyErrorStatus classifies an undecodable or oversize N16 request body: 413 MAX_JSON_SIZE_EXCEEDED when a
// size limit was hit, else 400 INVALID_MSG_FORMAT. Ref: TS 29.500 Table 5.2.7.2-1, §5.2.7.1.
func hrBodyErrorStatus(err error) (int, string) {
	var mbe *http.MaxBytesError
	if errors.Is(err, errHRBodyTooLarge) || errors.As(err, &mbe) {
		return http.StatusRequestEntityTooLarge, causeMaxJSONSizeExceeded
	}
	return http.StatusBadRequest, causeInvalidMsgFormat
}

// hrLogger returns the canonical procedure logger of the H-SMF role. It deliberately carries no
// "interface": every log line adds exactly one (slog's JSON handler does not de-duplicate keys), either
// through log.With("interface", ...) or as an attribute of the call.
func (s *Server) hrLogger(ctx context.Context) *slog.Logger {
	// nf="SMF" is already on the root logger (cmd/smf/main.go); never add it again.
	return logging.NewProcedureLogger(ctx, s.logger, hrProcedure).With("smf_role", hrSMFRole)
}

// Cause values and constants of the N16 originating-network check (TS 29.500 §5.2.3.2.15).
const (
	// causeOriginNotAllowed is the 403 application error of a PostPduSessions / ReleasePduSession whose
	// 3gpp-Sbi-Originating-Network-Id is missing, differs from the servingNetwork / stored serving PLMN,
	// or names the H-SMF's own PLMN. Choice: SUBSCRIPTION_DENIED is the closest cause of TS 29.502
	// Table 6.1.3.5.3.1-3 (the roaming agreement for that PLMN is not in place); the release table
	// (ReleasePduSession) defines no 403 cause list, the common 403 ProblemDetails applies.
	causeOriginNotAllowed = causeSubscriptionDenied
)

// ownPLMNKey is this SMF's "MCC-MNC", "" when the PLMN is not configured.
func (s *Server) ownPLMNKey() string {
	if s.cfg.PLMN.MCC == "" || s.cfg.PLMN.MNC == "" {
		return ""
	}
	return s.cfg.PLMN.MCC + "-" + s.cfg.PLMN.MNC
}

// checkOriginatingNetwork enforces TS 29.500 §5.2.3.2.15 on an N16 request to the H-SMF: the header is
// mandatory (fail closed), its PLMN must be the expected visited PLMN (servingNetwork on create, the
// stored serving PLMN on release) and never the H-SMF's own PLMN (a visited network is by definition
// another PLMN). It returns "" when the request is acceptable, else the reason.
func (s *Server) checkOriginatingNetwork(nid, expected string) string {
	switch got := originPLMN(nid); {
	case strings.TrimSpace(nid) == "":
		return "3gpp-Sbi-Originating-Network-Id missing"
	case got == "" || got != expected:
		return "3gpp-Sbi-Originating-Network-Id does not match the serving PLMN"
	case got == s.ownPLMNKey():
		return "3gpp-Sbi-Originating-Network-Id names the home PLMN"
	}
	return ""
}

// handleHsmfCreatePduSession serves Nsmf_PDUSession Create (PostPduSessions) as H-SMF.
// Ref: TS 29.502 §5.2.2.7.1; TS 23.502 §4.3.2.2.2 steps 6-13.
func (s *Server) handleHsmfCreatePduSession(w http.ResponseWriter, r *http.Request) {
	corrID := r.Header.Get("X-Correlation-Id")
	ctx := logging.WithCorrelationID(r.Context(), corrID)
	base := s.hrLogger(ctx) // no "interface": helpers add their own, handler lines use log
	log := base.With("interface", "Nsmf")
	finish := func(result string) { metrics.ProcedureTotal.WithLabelValues("SMF", hrProcedure, result).Inc() }

	body, err := readHRBody(r.Header.Get("Content-Type"), http.MaxBytesReader(w, r.Body, maxHRRequestBody))
	var req PduSessionCreateData
	if err == nil {
		err = json.Unmarshal(body.JSON, &req)
	}
	if err != nil {
		status, cause := hrBodyErrorStatus(err)
		log.WarnContext(ctx, "PduSessionCreateData undecodable", "direction", "IN", "result", "REJECT",
			"cause", cause, "http_status", status, "error", err, "spec_ref", "TS 29.500 Table 5.2.7.2-1")
		finish("REJECT")
		hrReject(ctx, log, w, status, cause, err.Error(), -1, nil)
		return
	}
	base = base.With("supi", req.SUPI)
	if req.PduSessionID != nil {
		base = base.With("pdu_session_id", *req.PduSessionID)
	}
	log = base.With("interface", "Nsmf")
	log.InfoContext(ctx, "Nsmf_PDUSession_Create (PostPduSessions) received",
		"direction", "IN", "dnn", req.DNN, "message_type", "PduSessionCreateData",
		"spec_ref", "TS 29.502 §5.2.2.7.1; TS 23.502 §4.3.2.2.2 step 6")

	if missing, incorrect := validatePduSessionCreateData(&req); len(missing)+len(incorrect) > 0 {
		cause, params := causeMandatoryIEMissing, missing
		if len(incorrect) > 0 {
			cause, params = causeMandatoryIEIncorrect, append(append([]HRInvalidParam(nil), incorrect...), missing...)
		}
		log.WarnContext(ctx, "PduSessionCreateData rejected", "direction", "OUT", "result", "REJECT",
			"cause", cause, "invalid_params", params, "spec_ref", "TS 29.500 Table 5.2.7.2-1")
		finish("REJECT")
		hrReject(ctx, log, w, http.StatusBadRequest, cause, "invalid PduSessionCreateData", -1, params)
		return
	}

	// vcnTunnelInfo address guard: refuse non-routable N9 addresses and, when configured, addresses
	// outside vupf_n9_allowed_cidrs (the H-UPF would send GTP-U there). Before any N4 / address work.
	if bad := checkVcnAddress(req.VcnTunnelInfo, s.vupfN9Allowed); len(bad) > 0 {
		log.WarnContext(ctx, "PduSessionCreateData rejected: vcnTunnelInfo address", "direction", "OUT", "result", "REJECT",
			"cause", causeMandatoryIEIncorrect, "invalid_params", bad, "spec_ref", "TS 29.502 Table 6.1.6.2.28-1; TS 29.500 Table 5.2.7.2-1")
		finish("REJECT")
		hrReject(ctx, log, w, http.StatusBadRequest, causeMandatoryIEIncorrect, "invalid vcnTunnelInfo", -1, bad)
		return
	}

	// n1SmInfoFromUe: its presence entitles the answer to an n1smCause (step 2b).
	hasN1 := req.N1SmInfoFromUe != nil
	n1 := func(c int) int { // n1smCause to put in an error, -1 when none is allowed
		if hasN1 {
			return c
		}
		return -1
	}
	reject := func(status int, cause, detail string, n1sm int) {
		log.WarnContext(ctx, "PduSessionCreateError returned", "direction", "OUT", "result", "REJECT",
			"cause", cause, "http_status", status, "detail", detail,
			"spec_ref", "TS 29.502 §5.2.2.7.1 step 2b; TS 23.502 §4.3.2.2.2 step 6")
		metrics.PDUSessionTotal.WithLabelValues("SMF", stripDNNOperatorID(req.DNN), "REJECT").Inc()
		finish("REJECT")
		hrReject(ctx, log, w, status, cause, detail, n1(n1sm), nil)
	}

	// 3gpp-Sbi-Originating-Network-Id is mandatory (inserted by the hSEPP) and must be the PLMN of
	// servingNetwork, never this PLMN: fail closed. Ref: TS 29.500 §5.2.3.2.15; TS 29.502 Table 6.1.3.5.3.1-3.
	if why := s.checkOriginatingNetwork(r.Header.Get(hdrOriginatingNetworkID), plmnKey(req.ServingNetwork)); why != "" {
		log.WarnContext(ctx, "PostPduSessions refused: originating network", "direction", "IN", "result", "REJECT",
			"detail", why, "originating_network_id", sanitizeLogValue(r.Header.Get(hdrOriginatingNetworkID)),
			"serving_network", plmnKey(req.ServingNetwork), "spec_ref", "TS 29.500 §5.2.3.2.15")
		reject(http.StatusForbidden, causeOriginNotAllowed, why, n1smCauseNotSubscribed)
		return
	}
	if p := unsupportedHRFeature(&req); p != "" {
		reject(http.StatusForbidden, causeNotSupportedWithISMF, "unsupported attribute "+p, n1smCauseNetworkFailure)
		return
	}
	// The SUPI must belong to the PLMN this H-SMF serves (it is the HPLMN SMF); the answer uses the
	// 403 causes PostPduSessions allows (TS 29.502 Table 6.1.3.5.3.1-3).
	if !s.supiServedHere(req.SUPI) {
		reject(http.StatusForbidden, causeSubscriptionDenied, "SUPI does not belong to the PLMN served by this H-SMF", n1smCauseNotSubscribed)
		return
	}
	vcn, _ := parseHRTunnel(req.VcnTunnelInfo) // validated above

	// N1 SM IEs the V-SMF forwarded: PDU session type / SSC mode (TS 29.502 §5.2.3.1.2).
	var pduReq *nas.PDUSessionEstablishmentRequest
	if hasN1 {
		raw, ok := body.Parts[strings.Trim(req.N1SmInfoFromUe.ContentID, "<> ")]
		if !ok {
			reject(http.StatusForbidden, causeN1SMError, "n1SmInfoFromUe binary part missing", n1smCauseProtocolError)
			return
		}
		// The IEs arrive without the mandatory "Integrity protection maximum data rate" V-IE
		// (it travels as maxIntegrityProtectedDataRate*), so prepend a zero placeholder for the decoder.
		pduReq, err = nas.DecodePDUSessionEstablishmentRequest(append([]byte{0, 0}, raw...))
		if err != nil {
			reject(http.StatusForbidden, causeN1SMError, "n1SmInfoFromUe: "+err.Error(), n1smCauseProtocolError)
			return
		}
	}
	var requestedType *uint8
	if pduReq != nil {
		requestedType = pduReq.PDUSessionType
	}

	// Strip the Operator Identifier before matching sm-data and the IP pools (TS 29.571 Dnn, TS 23.003 §9.1.2).
	dnnNI := stripDNNOperatorID(req.DNN)
	pool, poolDNN := s.hrPoolFor(dnnNI)
	if pool == nil {
		reject(http.StatusForbidden, causeDNNNotSupported, fmt.Sprintf("DNN %q not served by this H-SMF", dnnNI), n1smCauseMissingOrUnknownDNN)
		return
	}
	slice := SliceID{SST: uint8(req.SNSSAI.SST), SD: req.SNSSAI.SD}
	psi := uint8(*req.PduSessionID)

	unlockEst := s.lockEstablishment(req.SUPI, psi)
	defer unlockEst()
	s.releaseStaleSessions(ctx, log, req.SUPI, psi)

	// Subscription check at the home UDM with the HPLMN S-NSSAI (step 6 "SM subscription retrieval").
	subQoS, serr := s.fetchHRSmData(ctx, base, req.SUPI, dnnNI, slice)
	if serr != nil {
		reject(serr.status, serr.cause, serr.detail, serr.n1sm)
		return
	}

	// UE address from the H-SMF pool(s) (TS 23.501 §5.8.2); IPv6 only when the DNN has a prefix pool.
	v6Pool := s.ipv6Pools[poolDNN]
	grantedType := selectPDUSessionType(requestedType, v6Pool != nil)
	var ip net.IP
	if pduTypeNeedsIPv4(grantedType) {
		if ip, err = pool.Allocate(); err != nil {
			log.ErrorContext(ctx, "H-SMF UE IPv4 pool exhausted", "error", err, "dnn", dnnNI)
			reject(http.StatusInternalServerError, causeInsufficientResSlice, err.Error(), n1smCauseInsufficientResSlice)
			return
		}
	}
	var v6Prefix *net.IPNet
	if pduTypeNeedsIPv6(grantedType) {
		if v6Prefix, _, err = v6Pool.Allocate(); err != nil {
			if ip != nil {
				pool.Release(ip)
			}
			log.ErrorContext(ctx, "H-SMF UE IPv6 pool exhausted", "error", err, "dnn", dnnNI)
			reject(http.StatusInternalServerError, causeInsufficientResSlice, err.Error(), n1smCauseInsufficientResSlice)
			return
		}
	}
	ueIPv4 := ""
	if ip != nil {
		ueIPv4 = ip.String()
	}
	// QoS precedence unchanged: PCF > UDM sm-data > operator default (TS 23.502 §4.3.2.2.1 step 6).
	smPolicyID, qos := s.createSMPolicy(ctx, req.SUPI, dnnNI, ueIPv4, slice, subQoS)

	ref := uuid.NewString()
	sess := &Session{
		SUPI: req.SUPI, PDUSessionID: psi, DNN: poolDNN, UEIP: ip,
		ULTEID: s.nextTEID.Add(1), SEID: s.nextSEID.Add(1), SliceID: slice,
		SmPolicyID: smPolicyID, FiveQI: qos.FiveQI, ARPPriority: qos.ARPPriority,
		AMBRULMbps: qos.AMBRULMbps, AMBRDLMbps: qos.AMBRDLMbps,
		AMBRULKbps: qos.AMBRULKbps, AMBRDLKbps: qos.AMBRDLKbps,
		QoSSource: qos.Source, State: "ESTABLISHING", CreatedAt: time.Now(),
		PDUSessionType: grantedType,
		HR: &HRSession{
			Role: HRRoleHSMF, VSmfPduSessionURI: req.VsmfPduSessionURI, VsmfID: req.VsmfID,
			PeerTunnel: vcn, HplmnSnssai: slice, ChargingID: req.ChargingID,
			OriginPLMN: plmnKey(req.ServingNetwork),
		},
	}
	if v6Prefix != nil {
		sess.UEIPv6Prefix = v6Prefix.String()
	}
	if pduReq != nil {
		sess.Capability5GSM = pduReq.Capability5GSM
	}
	s.sessionMu.Lock()
	s.sessions[ref] = sess
	s.sessionMu.Unlock()
	metrics.PDUSessionsActive.WithLabelValues("SMF", poolDNN).Inc()

	// N4 Establishment on the H-UPF: UL PDR on the N9 F-TEID, DL FAR FORW + OHC to vcnTunnelInfo.
	if err := s.hrEstablishN4(ctx, base, sess); err != nil {
		s.releaseSessionLocal(ctx, ref, sess, false)
		// UPF_NOT_RESPONDING is not allowed on PostPduSessions (TS 29.502 Table 6.1.3.5.3.1-3).
		reject(http.StatusInternalServerError, causeSystemFailure, "H-UPF N4 establishment failed: "+err.Error(), n1smCauseInsufficientResources)
		return
	}
	// rollback undoes a session the V-SMF will never learn about (it is gone or its timeout fired):
	// H-UPF N4 deletion, UE address, SM policy and context are all released locally.
	rollback := func(reason string, rerr error) {
		s.releaseSessionLocal(context.WithoutCancel(ctx), ref, sess, false)
		derr := s.hrDeleteN4(ctx, base, sess)
		log.WarnContext(ctx, "H-SMF session rolled back: the V-SMF did not receive the 201", "direction", "OUT",
			"result", "FAILURE", "reason", reason, "error", rerr, "n4_delete_error", derr, "pdu_session_ref", ref,
			"seid", sess.SEID, "spec_ref", "TS 29.502 §5.2.2.7.1; TS 23.502 §4.3.4.3")
		metrics.PDUSessionTotal.WithLabelValues("SMF", poolDNN, "FAILURE").Inc()
		finish("FAILURE")
	}
	if cerr := ctx.Err(); cerr != nil {
		rollback("request cancelled before the answer", cerr)
		return
	}
	s.sessionMu.Lock()
	sess.State = "ACTIVE"
	created := s.buildPduSessionCreated(sess, grantedType)
	s.sessionMu.Unlock()
	s.persistSession(ctx, ref, sess)

	log.InfoContext(ctx, "Nsmf_PDUSession_Create answered", "direction", "OUT", "result", "OK",
		"pdu_session_ref", ref, "ue_ip", ueIPv4, "ue_ipv6_prefix", created.UeIPv6Prefix,
		"seid", sess.SEID, "n9_teid", sess.ULTEID, "n9_addr", s.n9Addr().String(), "5qi", qos.FiveQI,
		"qos_source", qos.Source, "vsmf_id", req.VsmfID, "charging_id", req.ChargingID, "dnn", dnnNI,
		"spec_ref", "TS 29.502 §5.2.2.7.1; TS 23.502 §4.3.2.2.2 step 13")
	w.Header().Set("Content-Type", mediaTypeJSON)
	// Location is an absolute URI built from this H-SMF's apiRoot (TS 29.502 Table 6.1.3.5.3.1-4).
	w.Header().Set("Location", s.hsmfAPIRoot(r)+hsmfPduSessionsPath+ref)
	w.WriteHeader(http.StatusCreated)
	if werr := hrWriteJSONErr(ctx, log, w, created); werr != nil {
		rollback("201 body not written", werr)
		return
	}
	metrics.PDUSessionTotal.WithLabelValues("SMF", poolDNN, "OK").Inc()
	finish("OK")
}

// hsmfPduSessionsPath is the path prefix of an individual PDU session resource of the H-SMF
// (TS 29.502 §6.1.3.5; the resource URI is {apiRoot}/nsmf-pdusession/v1/pdu-sessions/{pduSessionRef}).
const hsmfPduSessionsPath = "/nsmf-pdusession/v1/pdu-sessions/"

// hsmfAPIRoot is the apiRoot of this H-SMF for the Location header: sbi.fqdn (+ the SBI port when
// configured), else the Host of the request. Ref: TS 29.500 §6.1.1; TS 29.502 Table 6.1.3.5.3.1-4.
func (s *Server) hsmfAPIRoot(r *http.Request) string {
	if s.cfg.SBI.FQDN == "" {
		return "https://" + r.Host
	}
	host := s.cfg.SBI.FQDN
	if _, port, err := net.SplitHostPort(s.cfg.SBI.Address); err == nil && port != "" {
		host = net.JoinHostPort(host, port)
	}
	return "https://" + host
}

// plmnKey renders a PLMN as "MCC-MNC" (the 3gpp-Sbi-Originating-Network-Id format, TS 29.500 §5.2.3.2.15).
func plmnKey(p *HRPlmnIDNid) string {
	if p == nil {
		return ""
	}
	return p.MCC + "-" + p.MNC
}

// originPLMN returns the "MCC-MNC" of a 3gpp-Sbi-Originating-Network-Id value
// ("123-45", "123-45-000007ed9d5", "123-45; src: SEPP-..."). Ref: TS 29.500 §5.2.3.2.15.
func originPLMN(header string) string {
	h := strings.TrimSpace(header)
	if i := strings.IndexByte(h, ';'); i >= 0 {
		h = strings.TrimSpace(h[:i])
	}
	parts := strings.Split(h, "-")
	if len(parts) < 2 {
		return h
	}
	return parts[0] + "-" + parts[1]
}

// supiServedHere reports whether the SUPI belongs to the PLMN of this SMF. Only IMSI-format SUPIs
// are checked (MCC+MNC prefix); other formats and an unconfigured PLMN are not restricted.
// Ref: TS 23.003 §2.2A; TS 23.501 §4.2.4.2 (the H-SMF is in the HPLMN).
func (s *Server) supiServedHere(supi string) bool {
	digits, ok := strings.CutPrefix(supi, "imsi-")
	if !ok || s.cfg.PLMN.MCC == "" || s.cfg.PLMN.MNC == "" {
		return true
	}
	return strings.HasPrefix(digits, s.cfg.PLMN.MCC+s.cfg.PLMN.MNC)
}

// hrPoolFor returns the IPv4 pool of the DNN (case-insensitive Network Identifier match) and the
// configured DNN name; nil when the DNN is not served. There is deliberately no fallback to the
// "internet" pool: a roamer must not silently land on another DNN. Ref: TS 29.571 Dnn.
func (s *Server) hrPoolFor(dnnNI string) (*IPPool, string) {
	for name, p := range s.ipPools {
		if strings.EqualFold(name, dnnNI) {
			return p, name
		}
	}
	return nil, ""
}

// hrSubscribed is one sm-data entry's relevant content.
type hrSubscribedEntry struct {
	SingleNSSAI struct {
		SST int    `json:"sst"`
		SD  string `json:"sd"`
	} `json:"singleNssai"`
	DNNConfigurations map[string]struct {
		QoSProfile struct {
			FiveQI int `json:"5qi"`
			ARP    struct {
				PriorityLevel int    `json:"priorityLevel"`
				PreemptCap    string `json:"preemptCap"`
				PreemptVuln   string `json:"preemptVuln"`
			} `json:"arp"`
		} `json:"5gQosProfile"`
		SessionAMBR struct {
			Uplink   string `json:"uplink"`
			Downlink string `json:"downlink"`
		} `json:"sessionAmbr"`
	} `json:"dnnConfigurations"`
}

// fetchHRSmData checks the subscription at this SMF's own UDM (peers.udm = the home UDM) with the
// HPLMN S-NSSAI and returns the subscribed default QoS (nil = subscribed without a QoS profile, the
// operator default applies). 404 -> 403 SUBSCRIPTION_DENIED; empty for the S-NSSAI -> SNSSAI_DENIED;
// S-NSSAI present without the DNN -> DNN_DENIED. A transport error or any other status is NOT
// swallowed (unlike the non-roaming fetchSubscribedQoS): it is logged, counted and answered 500
// SYSTEM_FAILURE. With no peers.udm configured the check is skipped (operator defaults).
// Ref: TS 29.503 §5.2.2.2, §6.1.6.2.7; docs/procedures/HomeRoutedPduSession.md §5.
func (s *Server) fetchHRSmData(ctx context.Context, log *slog.Logger, supi, dnnNI string, slice SliceID) (*subscribedQoS, *hrSmDataError) {
	if s.cfg.Peers.UDM == "" {
		return nil, nil
	}
	fail := func(detail string, err error) (*subscribedQoS, *hrSmDataError) {
		log.ErrorContext(ctx, "H-SMF sm-data fetch failed", "interface", "N10", "direction", "OUT",
			"result", "FAILURE", "error", err, "spec_ref", "TS 29.503 §5.2.2.2")
		metrics.ProcedureTotal.WithLabelValues("SMF", "HrSmDataFetch", "FAILURE").Inc()
		return nil, &hrSmDataError{status: http.StatusInternalServerError, cause: causeSystemFailure,
			n1sm: n1smCauseInsufficientResources, detail: detail}
	}
	get := func(withDNN bool) ([]hrSubscribedEntry, int, error) {
		sn, _ := json.Marshal(map[string]any{"sst": slice.SST, "sd": slice.SD})
		u := fmt.Sprintf("https://%s/nudm-sdm/v2/%s/sm-data?single-nssai=%s",
			s.cfg.Peers.UDM, url.PathEscape(supi), url.QueryEscape(string(sn)))
		if withDNN {
			u += "&dnn=" + url.QueryEscape(dnnNI)
		}
		rq, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, 0, err
		}
		rq.Header.Set("X-Correlation-Id", logging.CorrelationID(ctx))
		resp, err := s.httpClient.Do(rq)
		if err != nil {
			return nil, 0, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, resp.StatusCode, nil
		}
		var entries []hrSubscribedEntry
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxHRSmDataBody)).Decode(&entries); err != nil {
			return nil, resp.StatusCode, fmt.Errorf("smf: decode sm-data: %w", err)
		}
		return entries, resp.StatusCode, nil
	}
	find := func(entries []hrSubscribedEntry) (*subscribedQoS, bool) {
		for _, e := range entries {
			for name, c := range e.DNNConfigurations {
				if !strings.EqualFold(name, dnnNI) {
					continue
				}
				if c.QoSProfile.FiveQI == 0 {
					return nil, true
				}
				q := &subscribedQoS{FiveQI: c.QoSProfile.FiveQI, ARPPriority: c.QoSProfile.ARP.PriorityLevel,
					ARPPreemptCap: c.QoSProfile.ARP.PreemptCap, ARPPreemptVuln: c.QoSProfile.ARP.PreemptVuln}
				q.AMBRULKbps, q.AMBRULMbps = parseAMBR(c.SessionAMBR.Uplink, 100_000, 100)
				q.AMBRDLKbps, q.AMBRDLMbps = parseAMBR(c.SessionAMBR.Downlink, 100_000, 100)
				return q, true
			}
		}
		return nil, false
	}

	entries, status, err := get(true)
	if err != nil {
		return fail("home UDM unreachable", err)
	}
	switch {
	case status == http.StatusNotFound:
		log.WarnContext(ctx, "no sm-data for the SUPI at the home UDM", "interface", "N10", "direction", "IN",
			"result", "REJECT", "cause", causeSubscriptionDenied, "spec_ref", "TS 29.503 §5.2.2.2")
		return nil, &hrSmDataError{status: http.StatusForbidden, cause: causeSubscriptionDenied,
			n1sm: n1smCauseNotSubscribed, detail: "no session management subscription data"}
	case status != http.StatusOK:
		return fail(fmt.Sprintf("home UDM answered %d", status), fmt.Errorf("sm-data status %d", status))
	}
	if q, ok := find(entries); ok {
		log.InfoContext(ctx, "H-SMF subscribed default QoS fetched", "interface", "N10", "direction", "IN",
			"result", "OK", "dnn", dnnNI, "snssai_sst", slice.SST, "snssai_sd", slice.SD,
			"spec_ref", "TS 29.503 §6.1.6.2.7")
		return q, nil
	}
	// Nothing for (S-NSSAI, DNN): distinguish a missing S-NSSAI from a missing DNN.
	byNSSAI, status, err := get(false)
	if err != nil {
		return fail("home UDM unreachable", err)
	}
	if status != http.StatusOK && status != http.StatusNotFound {
		return fail(fmt.Sprintf("home UDM answered %d", status), fmt.Errorf("sm-data status %d", status))
	}
	cause, n1sm := causeSNSSAIDenied, n1smCauseNotSubscribed
	if len(byNSSAI) > 0 {
		cause, n1sm = causeDNNDenied, n1smCauseMissingOrUnknownDNN
	}
	log.WarnContext(ctx, "subscription check failed at the home UDM", "interface", "N10", "direction", "IN",
		"result", "REJECT", "cause", cause, "dnn", dnnNI, "snssai_sst", slice.SST, "snssai_sd", slice.SD,
		"spec_ref", "TS 29.502 §5.2.2.7.1 step 2b")
	return nil, &hrSmDataError{status: http.StatusForbidden, cause: cause, n1sm: n1sm,
		detail: "not subscribed: " + cause}
}

// n9Addr is the H-UPF N9 address of hcnTunnelInfo and of the UL PDR F-TEID (upf_n9_addr, default
// upf_n3_addr). Ref: TS 29.244 §8.2.3.
func (s *Server) n9Addr() net.IP {
	if s.cfg.UPFN9Addr != "" {
		return net.ParseIP(s.cfg.UPFN9Addr)
	}
	return net.ParseIP(s.cfg.UPFN3Addr)
}

// buildPduSessionCreated builds the 201 body from the session (TS 29.502 Table 6.1.6.2.10-1).
// The QoS rules / flow descriptions use the same TS 24.501 §9.11.4.13 / §9.11.4.12 encoders as the
// non-roaming Accept; the V-SMF copies them unchanged.
func (s *Server) buildPduSessionCreated(sess *Session, grantedType uint8) *PduSessionCreatedData {
	ulKbps, dlKbps := sessionAMBRKbps(sess)
	out := &PduSessionCreatedData{
		PduSessionType: pduSessionTypeName(grantedType),
		SscMode:        sscModeName(nas.SSCMode1), // only SSC mode 1 is supported (as non-roaming)
		HcnTunnelInfo:  &HRTunnelInfo{IPv4Addr: s.n9Addr().String(), GtpTeid: formatTEID(sess.ULTEID)},
		SessionAmbr:    &HRAmbr{Uplink: fmt.Sprintf("%d Kbps", ulKbps), Downlink: fmt.Sprintf("%d Kbps", dlKbps)},
		QosFlowsSetupList: []HRQosFlowSetupItem{{
			QFI:                int(defaultQFI),
			QosRules:           base64.StdEncoding.EncodeToString(nas.BuildDefaultQoSRules(defaultQFI)),
			QosFlowDescription: base64.StdEncoding.EncodeToString(nas.BuildQoSFlowDescriptions(defaultQFI, sess.FiveQI, sess.AMBRULMbps, sess.AMBRDLMbps)),
			QosFlowProfile: &HRQosFlowProfile{FiveQI: int(sess.FiveQI), ARP: &HRArp{
				PriorityLevel: arpOrDefault(sess.ARPPriority), PreemptCap: "NOT_PREEMPT", PreemptVuln: "NOT_PREEMPTABLE"}},
			DefaultQosRuleInd: true,
		}},
		HSmfInstanceID: s.cfg.NFInstanceID,
	}
	if sess.UEIP != nil {
		out.UeIPv4Address = sess.UEIP.String()
	}
	out.UeIPv6Prefix = sess.UEIPv6Prefix
	return out
}

// sscModeName renders an SSC mode as the SscMode enumeration of TS 29.571 §5.4.3.6
// ("SSC_MODE_1" .. "SSC_MODE_3").
func sscModeName(m uint8) string { return fmt.Sprintf("SSC_MODE_%d", m) }

// arpOrDefault returns the ARP priority level, 8 (operator default) when unset.
func arpOrDefault(p int) int {
	if p <= 0 {
		return 8
	}
	return p
}

// pduSessionTypeName maps the granted NAS PDU session type to the PduSessionType enum
// (TS 29.571 PduSessionType; TS 24.501 §9.11.4.11).
func pduSessionTypeName(t uint8) string {
	switch t {
	case nas.PDUSessionTypeIPv6:
		return "IPV6"
	case nas.PDUSessionTypeIPv4v6:
		return "IPV4V6"
	}
	return "IPV4"
}

// hrEstablishN4 sends the H-UPF PFCP Session Establishment and checks the Cause.
// Ref: TS 23.502 §4.3.2.2.2 step 10-11; TS 29.244 §7.5.2, §7.5.3.
func (s *Server) hrEstablishN4(ctx context.Context, log *slog.Logger, sess *Session) error {
	s.sessionMu.Lock()
	req, err := s.buildHSMFEstablishmentRequest(sess, s.nextPFCPSeq())
	ueIP, peer := sess.UEIP, sess.HR.PeerTunnel
	s.sessionMu.Unlock()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, hrN4Timeout)
	defer cancel()
	nlog := log.With("interface", "N4", "seid", sess.SEID)
	nlog.InfoContext(ctx, "PFCP Session Establishment Request sent (H-UPF)", "direction", "OUT",
		"message_type", "PFCPSessionEstablishmentRequest", "n9_teid", sess.ULTEID, "ue_ip", ueIP,
		"vcn_ip", peer.IP.String(), "vcn_teid", peer.TEID, "seq", req.Sequence(),
		"spec_ref", "TS 23.502 §4.3.2.2.2 step 10; TS 29.244 §7.5.2")
	start := time.Now()
	msg, err := s.pfcpTransact(ctx, s.logger, req, pfcpmsg.MsgTypeSessionEstablishmentResponse)
	if err != nil {
		nlog.WarnContext(ctx, "PFCP Session Establishment Response not received", "direction", "IN",
			"result", "FAILURE", "error", err, "duration_ms", time.Since(start).Milliseconds(),
			"spec_ref", "TS 29.244 §7.5.3")
		// The UPF may have created the session although its answer was lost (or the request was
		// cancelled): best-effort Session Deletion for this SEID so no orphan remains on the H-UPF.
		if derr := s.hrDeleteN4(ctx, log, sess); derr != nil {
			nlog.WarnContext(ctx, "best-effort H-UPF deletion after establishment failure failed", "direction", "OUT",
				"result", "FAILURE", "error", derr, "spec_ref", "TS 29.244 §7.5.6")
		}
		return fmt.Errorf("smf: hr n4 establishment: %w", err)
	}
	rsp, ok := msg.(*pfcpmsg.SessionEstablishmentResponse)
	if !ok || rsp.Cause == nil {
		return fmt.Errorf("smf: hr n4 establishment: %w", errPFCPCauseMissing)
	}
	cause, _ := rsp.Cause.Cause()
	if cause != pfcpie.CauseRequestAccepted {
		nlog.WarnContext(ctx, "PFCP Session Establishment rejected by H-UPF", "direction", "IN",
			"result", "REJECT", "pfcp_cause", cause, "spec_ref", "TS 29.244 §7.5.3")
		return fmt.Errorf("smf: hr n4 establishment: %w: cause %d", errPFCPRejected, cause)
	}
	s.sessionMu.Lock()
	sess.N4EstablishedAt = time.Now()
	s.sessionMu.Unlock()
	nlog.InfoContext(ctx, "PFCP Session Establishment Response received (H-UPF)", "direction", "IN",
		"result", "OK", "pfcp_cause", cause, "duration_ms", time.Since(start).Milliseconds(),
		"spec_ref", "TS 29.244 §7.5.3")
	return nil
}

// buildHSMFEstablishmentRequest builds the H-UPF PFCP Session Establishment Request of a
// home-routed session (docs/procedures/HomeRoutedPduSession.md §4 "PFCP H-UPF Establishment"):
//
//	UL PDR 1: Source Interface Access (the UL direction, although the peer is the V-UPF on N9;
//	          TS 29.244 §8.2.2 NOTE 1), F-TEID = H-UPF N9 address + UL TEID, UE IP, Network Instance
//	          = DNN, OHR GTP-U/UDP/IPv4 -> FAR 2 (FORW, Destination Interface Core = N6)
//	DL PDR 2: Source Interface Core, UE IP (S/D = destination) -> FAR 1 (FORW, Destination
//	          Interface Access, Outer Header Creation GTP-U/UDP/IPv4 to vcnTunnelInfo)
//
// Create QER 1/2 and Create URR 1 as the non-roaming layout. There is no BAR: the H-UPF never
// buffers for paging (UE reachability is a VPLMN matter). The non-roaming builder is untouched.
// Ref: TS 29.244 §7.5.2.2, §7.5.2.3, §8.2.2, §8.2.3, §8.2.56, §8.2.62.
func (s *Server) buildHSMFEstablishmentRequest(sess *Session, seq uint32) (*pfcpmsg.SessionEstablishmentRequest, error) {
	if sess.HR == nil || sess.HR.PeerTunnel.IP == nil {
		return nil, errors.New("smf: hr n4 establishment: no vcnTunnelInfo")
	}
	n9 := s.n9Addr()
	if n9 == nil {
		return nil, errors.New("smf: hr n4 establishment: no valid upf N9/N3 address")
	}
	ambrUL, ambrDL := sessionAMBRKbps(sess)
	ueIPIE, _, err := buildUEIPAddressIE(sess)
	if err != nil {
		return nil, fmt.Errorf("smf: hr n4 establishment: %w", err)
	}
	dlUEIPIE, _, err := buildUEIPAddressIEDest(sess, true)
	if err != nil {
		return nil, fmt.Errorf("smf: hr n4 establishment: %w", err)
	}
	return pfcpmsg.NewSessionEstablishmentRequest(0, 0, 0, seq, 0,
		pfcpie.NewNodeID("", "", "smf"),
		pfcpie.NewFSEID(sess.SEID, net.ParseIP("0.0.0.0"), nil),
		pfcpie.NewCreatePDR(
			pfcpie.NewPDRID(ulPDRID),
			pfcpie.NewPrecedence(100),
			pfcpie.NewPDI(
				pfcpie.NewSourceInterface(pfcpie.SrcInterfaceAccess),
				pfcpie.NewFTEID(0x01, sess.ULTEID, n9, nil, 0),
				ueIPIE,
				pfcpie.NewNetworkInstance(sess.DNN),
			),
			pfcpie.NewOuterHeaderRemoval(0, 0),
			pfcpie.NewFARID(ulFARID),
			pfcpie.NewQERID(sessionAMBRQERID),
			pfcpie.NewQERID(defaultFlowQERID),
			pfcpie.NewURRID(usageReportingURRID),
		),
		pfcpie.NewCreatePDR(
			pfcpie.NewPDRID(dlPDRID),
			pfcpie.NewPrecedence(100),
			pfcpie.NewPDI(
				pfcpie.NewSourceInterface(pfcpie.SrcInterfaceCore),
				dlUEIPIE,
				pfcpie.NewNetworkInstance(sess.DNN),
			),
			pfcpie.NewFARID(dlFARID),
			pfcpie.NewURRID(usageReportingURRID),
			pfcpie.NewQERID(sessionAMBRQERID),
			pfcpie.NewQERID(defaultFlowQERID),
		),
		// DL FAR: FORW with the V-UPF tunnel known at establishment (no later update).
		pfcpie.NewCreateFAR(
			pfcpie.NewFARID(dlFARID),
			pfcpie.NewApplyAction(0x02), // FORW
			pfcpie.NewForwardingParameters(
				pfcpie.NewDestinationInterface(pfcpie.DstInterfaceAccess),
				pfcpie.NewOuterHeaderCreation(ohcGTPUUDPIPv4, sess.HR.PeerTunnel.TEID, sess.HR.PeerTunnel.IP.String(), "", 0, 0, 0),
			),
		),
		pfcpie.NewCreateFAR(
			pfcpie.NewFARID(ulFARID),
			pfcpie.NewApplyAction(0x02), // FORW
			pfcpie.NewForwardingParameters(pfcpie.NewDestinationInterface(pfcpie.DstInterfaceCore)),
		),
		buildSessionAMBRCreateQER(ambrUL, ambrDL),
		buildDefaultFlowCreateQER(),
		pfcpie.NewCreateURR(
			pfcpie.NewURRID(usageReportingURRID),
			pfcpie.NewMeasurementMethod(0, 1, 1),
			pfcpie.NewReportingTriggers(reportingTriggersPerioVolth),
			pfcpie.NewVolumeThreshold(volumeThresholdFlagTOVOL, s.cfg.N4.VolumeThresholdBytes, 0, 0),
			pfcpie.NewMeasurementPeriod(time.Duration(s.cfg.N4.MeasurementPeriodSeconds)*time.Second),
		),
	), nil
}

// handleHsmfReleasePduSession serves Nsmf_PDUSession Release (ReleasePduSession) as H-SMF: the
// H-UPF N4 session is deleted, the UE address and the SM policy are freed, answer 204.
// Only sessions created by this H-SMF role can be released here; any other ref is 404.
// Ref: TS 29.502 §5.2.2.9; TS 23.502 §4.3.4.3 steps 4-6.
func (s *Server) handleHsmfReleasePduSession(w http.ResponseWriter, r *http.Request) {
	ref := r.PathValue("pduSessionRef")
	corrID := r.Header.Get("X-Correlation-Id")
	ctx := logging.WithCorrelationID(r.Context(), corrID)
	base := s.hrLogger(ctx).With("pdu_session_ref", ref)
	log := base.With("interface", "Nsmf")
	finish := func(result string) {
		metrics.ProcedureTotal.WithLabelValues("SMF", hrProcedure+"Release", result).Inc()
	}

	// ReleaseData is optional and every attribute of it is optional.
	var rel ReleaseData
	body, derr := readHRBody(r.Header.Get("Content-Type"), http.MaxBytesReader(w, r.Body, maxHRRequestBody))
	if derr == nil && len(body.JSON) > 0 {
		derr = json.Unmarshal(body.JSON, &rel)
	}
	if derr != nil {
		status, cause := hrBodyErrorStatus(derr)
		log.WarnContext(ctx, "ReleaseData undecodable", "direction", "IN", "result", "REJECT",
			"cause", cause, "http_status", status, "error", derr, "spec_ref", "TS 29.500 Table 5.2.7.2-1")
		finish("REJECT")
		problem(w, status, cause, derr.Error())
		return
	}
	log.InfoContext(ctx, "Nsmf_PDUSession_Release (ReleasePduSession) received", "direction", "IN",
		"release_cause", rel.Cause, "spec_ref", "TS 29.502 §5.2.2.9; TS 23.502 §4.3.4.3 step 4")

	sess, ok := s.hsmfAuthorizeRef(ctx, base, w, r, ref, "ReleasePduSession", "TS 29.502 §5.2.2.9", false, finish)
	if !ok {
		return
	}
	base = base.With("supi", sess.SUPI, "pdu_session_id", sess.PDUSessionID) // seid: added by the N4 helper
	log = base.With("interface", "Nsmf")
	finish(s.hsmfReleaseSession(ctx, base, log, ref, sess))
	w.WriteHeader(http.StatusNoContent)
}

// hsmfAuthorizeRef is the access check shared by the ReleasePduSession and Update requests on an
// individual PDU session resource of the H-SMF. It answers and returns ok=false when the request must
// be refused; otherwise it returns the session this H-SMF created for ref.
//   - 3gpp-Sbi-Originating-Network-Id missing: 403 MISSING_PARAMETER on /release (TS 29.500 Table
//     5.2.7.2-1), 403 SUBSCRIPTION_DENIED on /modify (the 403 cause listed in TS 29.502 Table 6.1.3.6.4.2.2-2).
//   - header names this H-SMF's own PLMN, an unknown ref, a ref not created by the H-SMF role, or a
//     session owned by another PLMN: 404 CONTEXT_NOT_FOUND with one identical body, so the answer is
//     no oracle on which refs exist (the real reason is only logged). Ref: TS 29.500 §5.2.3.2.15;
//     TS 29.502 §5.2.2.8.2.1, §5.2.2.9, Table 6.1.3.6.4.2.2-2 (404 CONTEXT_NOT_FOUND).
func (s *Server) hsmfAuthorizeRef(ctx context.Context, base *slog.Logger, w http.ResponseWriter, r *http.Request,
	ref, op, specRef string, updateErr bool, finish func(string)) (*Session, bool) {
	log := base.With("interface", "Nsmf")
	nid := r.Header.Get(hdrOriginatingNetworkID)
	if strings.TrimSpace(nid) == "" {
		cause := causeMissingParameter
		if updateErr { // /modify: MISSING_PARAMETER is not in Table 6.1.3.6.4.2.2-2, SUBSCRIPTION_DENIED is
			cause = causeSubscriptionDenied
		}
		s.refuseOrigin(ctx, log, w, finish, op, specRef, updateErr, http.StatusForbidden, cause,
			"3gpp-Sbi-Originating-Network-Id missing", nid, "")
		return nil, false
	}
	if originPLMN(nid) == s.ownPLMNKey() {
		s.refuseOrigin(ctx, log, w, finish, op, specRef, updateErr, http.StatusNotFound, causeContextNotFound,
			"3gpp-Sbi-Originating-Network-Id names the home PLMN", nid, "")
		return nil, false
	}
	s.sessionMu.Lock()
	sess := s.sessions[ref]
	var origin string
	if sess != nil && sess.HR != nil {
		origin = sess.HR.OriginPLMN
	}
	s.sessionMu.Unlock()
	if sess == nil || sess.HR == nil || sess.HR.Role != HRRoleHSMF {
		log.WarnContext(ctx, "H-SMF "+op+": unknown pduSessionRef", "direction", "OUT", "result", "REJECT",
			"cause", causeContextNotFound, "spec_ref", "TS 29.500 Table 5.2.7.1-1")
		finish("REJECT")
		hsmfError(ctx, log, w, updateErr, http.StatusNotFound, causeContextNotFound, "unknown pduSessionRef", nil, nil)
		return nil, false
	}
	// Only the PLMN that created the session may act on it: the SEPP-inserted
	// 3gpp-Sbi-Originating-Network-Id must name the stored servingNetwork (fail closed).
	// Ref: TS 29.500 §5.2.3.2.15; TS 29.502 §5.2.2.9.
	if why := s.checkOriginatingNetwork(nid, origin); why != "" {
		s.refuseOrigin(ctx, log, w, finish, op, specRef, updateErr, http.StatusNotFound, causeContextNotFound, why, nid, origin)
		return nil, false
	}
	return sess, true
}

// refuseOrigin logs the real reason and answers the refusal of hsmfAuthorizeRef.
func (s *Server) refuseOrigin(ctx context.Context, log *slog.Logger, w http.ResponseWriter, finish func(string),
	op, specRef string, updateErr bool, status int, cause, why, nid, sessionPLMN string) {
	log.WarnContext(ctx, op+" refused: originating network", "direction", "IN", "result", "REJECT",
		"cause", cause, "http_status", status, "detail", why, "originating_network_id", sanitizeLogValue(nid),
		"session_plmn", sessionPLMN, "spec_ref", "TS 29.500 §5.2.3.2.15, Table 5.2.7.2-1; "+specRef)
	finish("REJECT")
	detail := why
	if status == http.StatusNotFound {
		detail = "unknown pduSessionRef" // no existence oracle
	}
	hsmfError(ctx, log, w, updateErr, status, cause, detail, nil, nil)
}

// hsmfError writes a 4xx/5xx answer of an individual-PDU-session-resource request of the H-SMF: an
// HsmfUpdateError ({"error": ProblemDetails}, application/json) when updateErr (the {ref}/modify route,
// TS 29.502 Table 6.1.3.6.4.2.2-2, §5.2.2.8.2.1 step 2b), otherwise a plain ProblemDetails
// (the {ref}/release route, Table 6.1.3.6.3.2-2). Both routes share the refusal bodies so the 404 stays
// identical for every refusal reason (no oracle). pti is echoed in HsmfUpdateError when known.
func hsmfError(ctx context.Context, log *slog.Logger, w http.ResponseWriter, updateErr bool, status int,
	cause, detail string, params []HRInvalidParam, pti *uint8) {
	if !updateErr {
		problem(w, status, cause, detail) // the release route carries no invalidParams
		return
	}
	w.Header().Set("Content-Type", mediaTypeJSON)
	w.WriteHeader(status)
	hrWriteJSON(ctx, log, w, HsmfUpdateError{Error: HRProblemDetails{
		Title: cause, Status: status, Cause: cause, Detail: detail, InvalidParams: params}, PTI: pti})
}

// maxLoggedHeaderLen caps header-derived values in log lines (log-injection / flooding guard).
const maxLoggedHeaderLen = 64

// sanitizeLogValue strips control characters from a peer-supplied value and truncates it to
// maxLoggedHeaderLen runes before it is logged.
func sanitizeLogValue(v string) string {
	out := make([]rune, 0, len(v))
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			continue
		}
		out = append(out, r)
		if len(out) >= maxLoggedHeaderLen {
			break
		}
	}
	return string(out)
}

// hsmfReleaseSession is the release core shared by ReleasePduSession and Update UE_REQ_PDU_SES_REL:
// SMF-side resources (UE address, SM policy, context) are freed, then the H-UPF N4 session is deleted.
// A concurrent release that already freed the session makes it an idempotent success; an H-UPF
// deletion failure does not change the answer (TS 29.502 §5.2.2.9) but is logged and counted FAILURE.
// It returns the procedure result (OK | FAILURE). Ref: TS 23.502 §4.3.4.3 steps 4-6.
func (s *Server) hsmfReleaseSession(ctx context.Context, base, log *slog.Logger, ref string, sess *Session) string {
	s.sessionMu.Lock()
	n4Stale := sess.N4Stale
	s.sessionMu.Unlock()
	if !s.releaseSessionLocal(ctx, ref, sess, false) {
		log.InfoContext(ctx, "H-SMF session already released by a concurrent request", "direction", "OUT", "result", "OK",
			"spec_ref", "TS 29.502 §5.2.2.9")
		return "OK"
	}
	result := "OK"
	if !n4Stale {
		if derr := s.hrDeleteN4(ctx, base, sess); derr != nil {
			result = "FAILURE"
			log.WarnContext(ctx, "H-SMF session released with H-UPF deletion failure", "direction", "OUT",
				"result", result, "error", derr, "spec_ref", "TS 29.502 §5.2.2.9; TS 29.244 §7.5.7")
		}
	}
	if result == "OK" {
		log.InfoContext(ctx, "H-SMF session released", "direction", "OUT", "result", result,
			"spec_ref", "TS 29.502 §5.2.2.9; TS 23.502 §4.3.4.3 step 6")
	}
	return result
}

// handleHsmfUpdatePduSession serves Nsmf_PDUSession Update (POST {pduSessionRef}/modify, HsmfUpdateData)
// as H-SMF. Only requestIndication UE_REQ_PDU_SES_REL is implemented: the session is released exactly
// as by ReleasePduSession and the answer is 204 (no HsmfUpdatedData needed, TS 29.502 §5.2.2.8.2.1
// step 2a; Table 6.1.3.6.4.2.2-2). Errors: 413 / 400 INVALID_MSG_FORMAT undecodable body, 400
// MANDATORY_IE_MISSING /requestIndication, 403 SUBSCRIPTION_DENIED (missing header) and 404 CONTEXT_NOT_FOUND (see
// hsmfAuthorizeRef), and for any other requestIndication 500 SYSTEM_FAILURE (TS 29.500 Table 5.2.7.2-1,
// allowed on this resource by Table 6.1.3.6.4.2.2-2) in an HsmfUpdateError body.
// Ref: TS 29.502 §5.2.2.8.2.1, §5.2.2.8.2.3; TS 23.502 §4.3.4.3 steps 2-6.
func (s *Server) handleHsmfUpdatePduSession(w http.ResponseWriter, r *http.Request) {
	ref := r.PathValue("pduSessionRef")
	corrID := r.Header.Get("X-Correlation-Id")
	ctx := logging.WithCorrelationID(r.Context(), corrID)
	base := s.hrLogger(ctx).With("pdu_session_ref", ref)
	log := base.With("interface", "Nsmf")
	finish := func(result string) {
		metrics.ProcedureTotal.WithLabelValues("SMF", hrProcedure+"Update", result).Inc()
	}

	var upd HsmfUpdateData
	body, derr := readHRBody(r.Header.Get("Content-Type"), http.MaxBytesReader(w, r.Body, maxHRRequestBody))
	if derr == nil {
		derr = json.Unmarshal(body.JSON, &upd)
	}
	if derr != nil {
		status, cause := hrBodyErrorStatus(derr)
		log.WarnContext(ctx, "HsmfUpdateData undecodable", "direction", "IN", "result", "REJECT",
			"cause", cause, "http_status", status, "error", derr, "spec_ref", "TS 29.500 Table 5.2.7.2-1")
		finish("REJECT")
		// 413 is a generic TS 29.500 error: plain ProblemDetails; other body errors are HsmfUpdateError.
		hsmfError(ctx, log, w, status != http.StatusRequestEntityTooLarge, status, cause, derr.Error(), nil, nil)
		return
	}
	log.InfoContext(ctx, "Nsmf_PDUSession_Update (HsmfUpdateData) received", "direction", "IN",
		"message_type", "HsmfUpdateData", "request_indication", upd.RequestIndication,
		"spec_ref", "TS 29.502 §5.2.2.8.2.1; TS 23.502 §4.3.4.3 step 2")

	sess, ok := s.hsmfAuthorizeRef(ctx, base, w, r, ref, "Update", "TS 29.502 §5.2.2.8.2.1", true, finish)
	if !ok {
		return
	}
	base = base.With("supi", sess.SUPI, "pdu_session_id", sess.PDUSessionID)
	log = base.With("interface", "Nsmf")

	switch upd.RequestIndication {
	case "":
		params := []HRInvalidParam{{Param: "/requestIndication", Reason: "mandatory attribute missing"}}
		log.WarnContext(ctx, "HsmfUpdateData rejected", "direction", "OUT", "result", "REJECT",
			"cause", causeMandatoryIEMissing, "spec_ref", "TS 29.502 Table 6.1.6.2.14-1; TS 29.500 Table 5.2.7.2-1")
		finish("REJECT")
		hsmfError(ctx, log, w, true, http.StatusBadRequest, causeMandatoryIEMissing, "requestIndication is mandatory", params, upd.PTI)
	case requestIndicationUEReqPduSesRel:
		pti := -1 // -1 = pti absent (it is optional in HsmfUpdateData)
		if upd.PTI != nil {
			pti = int(*upd.PTI)
		}
		log.InfoContext(ctx, "Nsmf_PDUSession_Update UE_REQ_PDU_SES_REL: releasing the home-routed session", "direction", "IN",
			"request_indication", upd.RequestIndication, "pti", pti,
			"spec_ref", "TS 29.502 §5.2.2.8.2.3; TS 23.502 §4.3.4.3 steps 4-6")
		result := s.hsmfReleaseSession(ctx, base, log, ref, sess)
		finish(result) // counted once, under ...Update
		w.WriteHeader(http.StatusNoContent)
	default:
		// Not implemented (NW_REQ_PDU_SES_MOD, UE_REQ_PDU_SES_MOD, ...): the session is left untouched.
		log.WarnContext(ctx, "HsmfUpdateData requestIndication not supported", "direction", "OUT", "result", "REJECT",
			"cause", causeSystemFailure, "request_indication", upd.RequestIndication,
			"spec_ref", "TS 29.502 Table 6.1.3.6.4.2.2-2; TS 29.500 Table 5.2.7.2-1")
		finish("REJECT")
		out := HsmfUpdateError{Error: HRProblemDetails{Title: causeSystemFailure, Status: http.StatusInternalServerError,
			Cause: causeSystemFailure, Detail: "requestIndication " + upd.RequestIndication + " not supported by this H-SMF"}, PTI: upd.PTI}
		w.Header().Set("Content-Type", mediaTypeJSON)
		w.WriteHeader(http.StatusInternalServerError)
		hrWriteJSON(ctx, log, w, out)
	}
}

// hrDeleteN4 deletes the H-UPF N4 session and waits for the response. It runs detached from the
// caller's cancellation (a cancelled N16 request must not skip the deletion) under its own hrN4Timeout.
// A transport failure, a missing Cause or a Cause other than Request accepted is returned as an error;
// it is also logged (WARN, result FAILURE). Ref: TS 29.244 §7.5.6, §7.5.7.
func (s *Server) hrDeleteN4(ctx context.Context, log *slog.Logger, sess *Session) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), hrN4Timeout)
	defer cancel()
	nlog := log.With("interface", "N4", "seid", sess.SEID)
	req := pfcpmsg.NewSessionDeletionRequest(0, 0, sess.SEID, s.nextPFCPSeq(), 0)
	nlog.InfoContext(ctx, "PFCP Session Deletion Request sent (H-UPF)", "direction", "OUT",
		"message_type", "PFCPSessionDeletionRequest", "spec_ref", "TS 23.502 §4.3.4.3 step 5; TS 29.244 §7.5.6")
	msg, err := s.pfcpTransact(ctx, s.logger, req, pfcpmsg.MsgTypeSessionDeletionResponse)
	if err != nil {
		nlog.WarnContext(ctx, "PFCP Session Deletion Response not received", "direction", "IN",
			"result", "FAILURE", "error", err, "spec_ref", "TS 29.244 §7.5.7")
		return fmt.Errorf("smf: hr n4 deletion: %w", err)
	}
	rsp, ok := msg.(*pfcpmsg.SessionDeletionResponse)
	if !ok || rsp.Cause == nil {
		nlog.WarnContext(ctx, "PFCP Session Deletion Response without Cause (H-UPF)", "direction", "IN",
			"result", "FAILURE", "spec_ref", "TS 29.244 §7.5.7")
		return fmt.Errorf("smf: hr n4 deletion: %w", errPFCPCauseMissing)
	}
	if c, _ := rsp.Cause.Cause(); c != pfcpie.CauseRequestAccepted {
		nlog.WarnContext(ctx, "PFCP Session Deletion rejected by H-UPF", "direction", "IN",
			"result", "REJECT", "pfcp_cause", c, "spec_ref", "TS 29.244 §7.5.7")
		return fmt.Errorf("smf: hr n4 deletion: %w: cause %d", errPFCPRejected, c)
	}
	nlog.InfoContext(ctx, "PFCP Session Deletion Response received (H-UPF)", "direction", "IN",
		"result", "OK", "spec_ref", "TS 29.244 §7.5.7")
	return nil
}
