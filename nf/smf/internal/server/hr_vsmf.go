package server

// hr_vsmf.go — V-SMF role of the home-routed PDU session (ROAM-002, phase 1): CreateSMContext with
// hSmfUri, the V-UPF N4 rule set (N3 UL / N9 DL), Nsmf_PDUSession Create and Release towards the
// H-SMF over N16 through the local SEPP, the PDU SESSION ESTABLISHMENT ACCEPT / REJECT built from
// the answer, and the serving-network release. The non-roaming path never reaches this file.
// Design: docs/procedures/HomeRoutedPduSession.md §4, §5, §7.2, §7.3, §7.6; behaviour:
// nf/smf/tests/features/home_routed_pdu_session.feature (@vsmf).
// Ref: TS 23.502 §4.3.2.2.2 steps 3-17, §4.3.4.3; TS 29.502 §5.2.2.7, §5.2.2.9, §5.2.3.1.2;
// TS 29.500 §6.1.4.3; TS 23.501 §4.2.4.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	pfcpie "github.com/wmnsk/go-pfcp/ie"
	pfcpmsg "github.com/wmnsk/go-pfcp/message"

	"github.com/francurieses/claudia-5gc/shared/logging"
	"github.com/francurieses/claudia-5gc/shared/nas"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

// hrVSMFRole is the smf_role log value of the V-SMF.
const hrVSMFRole = "V-SMF"

// SBI headers of a request routed through the SEPP: 3gpp-Sbi-Target-apiRoot (TS 29.500 §5.2.3.2.4,
// §6.1.4.3.3) and 3gpp-Sbi-Originating-Network-Id (§5.2.3.2.15).
const (
	hdrTargetAPIRoot        = "3gpp-Sbi-Target-apiRoot"
	hdrOriginatingNetworkID = "3gpp-Sbi-Originating-Network-Id"
)

// hrN16Timeout bounds the N16 PostPduSessions call (V-SMF -> local SEPP -> hSEPP -> H-SMF ->
// hUDM + H-UPF N4). Implementation guard, not a 3GPP timer; it must stay below the AMF's
// home-routed CreateSMContext timeout (30 s, nf/amf/cmd/amf/clients.go hrCreateSMContextTimeout)
// and above the H-SMF's own hrN4Timeout.
const hrN16Timeout = 20 * time.Second

// hrN16ReleaseTimeout bounds the N16 ReleasePduSession call; the V-SMF-side cleanup does not wait
// longer than this for the home network (TS 29.502 §5.2.2.9 defines no retry). Implementation guard.
const hrN16ReleaseTimeout = 5 * time.Second

// maxHRResponseBody bounds an N16 response body read; a longer answer is an explicit failure.
const maxHRResponseBody = 1 << 20

// maxLoggedErrBody is the most bytes of an unparseable N16 error body put in a log line.
const maxLoggedErrBody = 256

// Length of the NAS 5GSM header (EPD | PSI | PTI | MT) and of the mandatory "Integrity protection
// maximum data rate" V-IE that follows it in the PDU SESSION ESTABLISHMENT REQUEST (TS 24.501 §8.3.1).
const (
	nas5GSMHeaderLen = 4
	nasIPMDRLen      = 2
)

// Integrity protection maximum data rate octet values (TS 24.501 §9.11.4.7) and the matching
// MaxIntegrityProtectedDataRate enum values (TS 29.502 §6.1.6.3.13).
const (
	ipmdr64kbps  = 0x00
	ipmdrFull    = 0xFF
	rate64Kbps   = "64_KBPS"
	rateMaxUE    = "MAX_UE_RATE"
	partNameN1Ue = "n1SmInfoFromUe"
	// partNameUnknownN1 is the Content-Id of the unknownN1SmInfo binary part (TS 29.502 §6.1.6.4.4).
	partNameUnknownN1 = "unknownN1SmInfo"
	mediaType5GS      = "application/vnd.3gpp.5gnas"
)

// vsmfCreateIn carries the parsed CreateSMContext request into the V-SMF branch.
type vsmfCreateIn struct {
	req        map[string]interface{}
	hSmfURI    string
	supi, dnn  string
	psi, pti   uint8
	slice      SliceID
	pduReq     *nas.PDUSessionEstablishmentRequest
	n1SmMsg    []byte
	corrID     string
	negotiated features.Set
	sfAnswer   string
}

// vsmfFailure is a failed home-routed establishment: what to tell the AMF and the UE.
type vsmfFailure struct {
	status    int    // HTTP status of the SmContextCreateError
	cause     string // application error cause of the ProblemDetails
	detail    string
	cause5GSM uint8  // 5GSM cause of the REJECT
	result    string // REJECT (peer said no) | FAILURE (path or internal error)
	n16Err    bool   // the failure happened on the N16 interface (log interface)
	// invalidParam is the JSON Pointer of an invalid request attribute (TS 29.571 §5.2.4.6), "" = none.
	invalidParam string
}

// hrLoggerRole is hrLogger for an explicit smf_role. Like hrLogger it carries no "interface": each
// line adds exactly one.
func (s *Server) hrLoggerRole(ctx context.Context, role string) *slog.Logger {
	return logging.NewProcedureLogger(ctx, s.logger, hrProcedure).With("smf_role", role)
}

// n16TimeoutFor returns d, or the test override when set.
func (s *Server) n16TimeoutFor(d time.Duration) time.Duration {
	if s.n16Timeout > 0 {
		return s.n16Timeout
	}
	return d
}

// allocChargingID returns a new Charging ID (TS 32.255 §5.1.9.1: unique 32-bit value per PDU
// session). The counter is seeded from the clock on first use so IDs do not repeat after a restart.
func (s *Server) allocChargingID() uint32 {
	if s.nextChargingID.Load() == 0 {
		s.nextChargingID.CompareAndSwap(0, uint32(time.Now().Unix()))
	}
	return s.nextChargingID.Add(1)
}

// vsmfAPIRoot is the apiRoot the H-SMF uses to reach this V-SMF (vsmfPduSessionUri): sbi.fqdn when
// set, else the TS 23.003 §28.5 FQDN smf.5gc.mnc<MNC3>.mcc<MCC>.3gppnetwork.org, with the SBI port; never
// the bind address (0.0.0.0 / unspecified is not routable). Without a configured PLMN the SBI address
// host is used when it is a concrete one, else the bare label "smf". Ref: TS 29.502 Table 6.1.6.2.9-1.
func (s *Server) vsmfAPIRoot() string {
	bindHost, port, err := net.SplitHostPort(s.cfg.SBI.Address)
	if err != nil {
		bindHost, port = s.cfg.SBI.Address, ""
	}
	host := s.cfg.SBI.FQDN
	if host == "" {
		switch ip := net.ParseIP(bindHost); {
		case s.cfg.PLMN.MCC != "" && s.cfg.PLMN.MNC != "":
			host = "smf.5gc.mnc" + pad3(s.cfg.PLMN.MNC) + ".mcc" + s.cfg.PLMN.MCC + ".3gppnetwork.org"
		case bindHost != "" && (ip == nil || !ip.IsUnspecified()):
			host = bindHost
		default:
			host = "smf"
		}
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	}
	return "https://" + host
}

// pad3 left-pads a 2-digit MNC with a zero (TS 23.003 §28.2: MNC is three digits in the FQDN).
func pad3(mnc string) string {
	for len(mnc) < 3 {
		mnc = "0" + mnc
	}
	return mnc
}

// hSmfHostRe is the home-network FQDN of an SMF (TS 23.003 §28.5): <label(s)>.5gc.mnc<MNC>.mcc<MCC>.3gppnetwork.org.
var hSmfHostRe = regexp.MustCompile(`(?i)^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*\.5gc\.mnc([0-9]{3})\.mcc([0-9]{3})\.3gppnetwork\.org$`)

// nsmfPDUSessionAPIPath is the API URI path of the Nsmf_PDUSession service (TS 29.502 §6.1.1).
const nsmfPDUSessionAPIPath = "/nsmf-pdusession/v1"

// validateHSmfURI checks the hSmfUri the AMF relayed before it is used as 3gpp-Sbi-Target-apiRoot:
// https, no userinfo / query / fragment, a path that is empty, "/" or the Nsmf_PDUSession API URI
// (/nsmf-pdusession/v1), a TS 23.003 §28.5 home-network SMF FQDN whose MCC equals the SUPI's MCC and whose
// MNC matches the SUPI digits (2- or 3-digit MNC), in a PLMN other than this SMF's own. It returns the
// parsed URI. Ref: TS 29.500 §6.1.4.3; TS 23.003 §28.5; TS 29.502 Table 6.1.6.2.2-1.
func (s *Server) validateHSmfURI(raw, supi string) (*url.URL, error) {
	hu, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("hSmfUri is not a valid URI: %w", err)
	}
	switch {
	case hu.Scheme != "https" || hu.Host == "":
		return nil, errors.New("hSmfUri is not an https URI")
	case hu.User != nil:
		return nil, errors.New("hSmfUri carries userinfo")
	case hu.RawQuery != "" || hu.ForceQuery || hu.Fragment != "":
		return nil, errors.New("hSmfUri carries a query or fragment")
	}
	switch strings.TrimSuffix(hu.EscapedPath(), "/") {
	case "", nsmfPDUSessionAPIPath:
	default:
		return nil, fmt.Errorf("hSmfUri path %q is not the Nsmf_PDUSession API URI", hu.EscapedPath())
	}
	m := hSmfHostRe.FindStringSubmatch(hu.Hostname())
	if m == nil {
		return nil, fmt.Errorf("hSmfUri host %q is not a TS 23.003 §28.5 SMF FQDN", hu.Hostname())
	}
	mnc3, mcc := m[4], m[5]
	digits, ok := strings.CutPrefix(supi, "imsi-")
	if !ok || len(digits) < 6 {
		return nil, errors.New("hSmfUri cannot be checked against a non-IMSI SUPI")
	}
	if digits[:3] != mcc {
		return nil, fmt.Errorf("hSmfUri MCC %s differs from the SUPI MCC", mcc)
	}
	if mnc3 != digits[3:6] && (mnc3[0] != '0' || mnc3[1:] != digits[3:5]) {
		return nil, fmt.Errorf("hSmfUri MNC %s does not match the SUPI", mnc3)
	}
	if own := s.cfg.PLMN; own.MCC != "" && own.MNC != "" && own.MCC == mcc && pad3(own.MNC) == mnc3 {
		return nil, errors.New("hSmfUri names this SMF's own PLMN")
	}
	return hu, nil
}

// homePLMNRe extracts the home PLMN from the Operator Identifier of a full DNN (TS 23.003 §9.1.2).
var homePLMNRe = regexp.MustCompile(`(?i)\.mnc([0-9]{3})\.mcc([0-9]{3})\.gprs$`)

func homePLMNFromDNN(dnn string) string {
	if m := homePLMNRe.FindStringSubmatch(dnn); m != nil {
		return m[2] + "-" + m[1]
	}
	return ""
}

// plmnIDNid is the servingNetwork of this (visited) PLMN.
func (s *Server) servingNetwork() *HRPlmnIDNid {
	return &HRPlmnIDNid{MCC: s.cfg.PLMN.MCC, MNC: s.cfg.PLMN.MNC}
}

// snssaiFromMap decodes {"sst":n,"sd":"hex"} (TS 29.571 Snssai).
func snssaiFromMap(m map[string]interface{}) (SliceID, bool) {
	sst, ok := m["sst"].(float64)
	if !ok {
		return SliceID{}, false
	}
	sd, _ := m["sd"].(string)
	return SliceID{SST: uint8(sst), SD: sd}, true
}

// sendCreateError answers the AMF with an SmContextCreateError: ProblemDetails + the PDU SESSION
// ESTABLISHMENT REJECT in n1SmMsg (TS 29.502 §5.2.2.3.1, §6.1.6.2.4; same shape as the
// association-gate rejection in restart_recovery.go).
func sendCreateError(ctx context.Context, log *slog.Logger, w http.ResponseWriter, f *vsmfFailure, psi, pti uint8) {
	n1 := nas.WrapPDUSessionEstablishmentRejectBody(psi, pti, f.cause5GSM, nil)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(f.status)
	pd := map[string]interface{}{"status": f.status, "cause": f.cause, "detail": f.detail}
	if f.invalidParam != "" {
		pd["invalidParams"] = []map[string]string{{"param": f.invalidParam, "reason": f.detail}}
	}
	hrWriteJSON(ctx, log, w, map[string]interface{}{
		"error":   pd,
		"n1SmMsg": base64.StdEncoding.EncodeToString(n1),
	})
}

// handleVSMFCreateSMContext is the V-SMF branch of CreateSMContext (hSmfUri present).
// Ref: TS 23.502 §4.3.2.2.2 steps 3-17; TS 29.502 §5.2.2.7.1.
func (s *Server) handleVSMFCreateSMContext(w http.ResponseWriter, r *http.Request, in *vsmfCreateIn) {
	ctx := logging.WithCorrelationID(r.Context(), in.corrID)
	base := s.hrLoggerRole(ctx, hrVSMFRole).With("supi", in.supi, "pdu_session_id", in.psi) // no "interface"
	log := base.With("interface", "Nsmf")
	finish := func(result string) { metrics.ProcedureTotal.WithLabelValues("SMF", hrProcedure, result).Inc() }
	dnnNI := stripDNNOperatorID(in.dnn)
	log.InfoContext(ctx, "Nsmf_PDUSession_CreateSMContext received (home-routed)", "direction", "IN",
		"message_type", "SmContextCreateData", "dnn", in.dnn, "h_smf_uri", in.hSmfURI, "via_sepp", s.cfg.Peers.SEPP,
		"home_plmn", homePLMNFromDNN(in.dnn), "spec_ref", "TS 23.502 §4.3.2.2.2 step 3; TS 29.502 Table 6.1.6.2.2-1")

	// reject answers the AMF; the caller already did its cleanup.
	reject := func(f *vsmfFailure) {
		iface := "Nsmf"
		if f.n16Err {
			iface = "N16"
		}
		base.With("interface", iface).WarnContext(ctx, "home-routed PDU session establishment rejected",
			"direction", "OUT", "result", f.result, "cause", f.cause, "cause_5gsm", f.cause5GSM,
			"detail", f.detail, "http_status", f.status,
			"spec_ref", "TS 29.502 §5.2.2.7.1 step 2b; TS 23.502 §4.3.2.2.2 step 6; HomeRoutedPduSession.md §5")
		metrics.PDUSessionTotal.WithLabelValues("SMF", dnnNI, "REJECT").Inc()
		finish(f.result)
		sendCreateError(ctx, log, w, f, in.psi, in.pti)
	}

	// Preconditions that need no state: hSmfUri, the local SEPP, the HPLMN S-NSSAI, the N9 address.
	hu, err := s.validateHSmfURI(in.hSmfURI, in.supi)
	if err != nil {
		reject(&vsmfFailure{status: http.StatusBadRequest, cause: causeMandatoryIEIncorrect, result: "FAILURE",
			cause5GSM: n1smCauseNetworkFailure, detail: err.Error(), invalidParam: "/hSmfUri"})
		return
	}
	hSmfAPIRoot := hu.Scheme + "://" + hu.Host
	hSmfBasePath := nsmfPDUSessionAPIPath // validateHSmfURI accepted only this path (or none)
	if s.cfg.Peers.SEPP == "" {
		base.With("interface", "N16").ErrorContext(ctx, "home-routed session without a local SEPP (peers.sepp)",
			"direction", "OUT", "result", "FAILURE", "spec_ref", "TS 29.500 §6.1.4.3")
		reject(&vsmfFailure{status: http.StatusInternalServerError, cause: causeSystemFailure, result: "FAILURE",
			cause5GSM: n1smCauseNetworkFailure, detail: "no local SEPP configured", n16Err: true})
		return
	}
	hplmn := in.slice
	if m, ok := in.req["hplmnSnssai"].(map[string]interface{}); ok {
		if v, ok := snssaiFromMap(m); ok {
			hplmn = v
		}
	} else {
		log.WarnContext(ctx, "hplmnSnssai missing in a roaming SmContextCreateData, using sNssai", "direction", "IN",
			"spec_ref", "TS 29.502 Table 6.1.6.2.2-1")
	}
	n9 := s.n9Addr()
	if n9 == nil || s.cfg.UPFN3Addr == "" {
		reject(&vsmfFailure{status: http.StatusInternalServerError, cause: causeSystemFailure, result: "FAILURE",
			cause5GSM: n1smCauseNetworkFailure, detail: "no valid upf_n3_addr / upf_n9_addr"})
		return
	}
	log.InfoContext(ctx, "V-UPF N9 address selected for the home-routed session", "direction", "OUT",
		"n9_addr", n9.String(), "n9_addr_is_n3_fallback", s.cfg.UPFN9Addr == "", "n3_addr", s.cfg.UPFN3Addr,
		"spec_ref", "TS 29.244 §8.2.3; TS 23.501 §4.2.4")

	// Session state: no UE IP (it comes from the H-SMF), no SM policy, no sm-data (visited UDM is not asked).
	ref := uuid.NewString()
	chargingID := s.allocChargingID()
	n9DLTEID := s.nextTEID.Add(1)
	sess := &Session{
		SUPI: in.supi, PDUSessionID: in.psi, DNN: dnnNI,
		ULTEID: s.nextTEID.Add(1), SEID: s.nextSEID.Add(1), SliceID: in.slice,
		State: "ESTABLISHING", CreatedAt: time.Now(), Features: in.negotiated,
		PDUSessionType: nas.PDUSessionTypeIPv4, QoSSource: "H-SMF",
		HR: &HRSession{
			Role: HRRoleVSMF, HSmfURI: in.hSmfURI, HplmnSnssai: hplmn,
			ChargingID: strconv.FormatUint(uint64(chargingID), 10), N9DLTEID: n9DLTEID,
		},
	}
	if in.pduReq != nil {
		sess.Capability5GSM = in.pduReq.Capability5GSM
	}
	s.sessionMu.Lock()
	s.sessions[ref] = sess
	s.sessionMu.Unlock()
	metrics.PDUSessionsActive.WithLabelValues("SMF", dnnNI).Inc()

	// abort undoes the local state; n4Up = the V-UPF session exists, n16Ref != "" = the H-SMF session exists.
	abort := func(f *vsmfFailure, n4Up bool, n16Ref string) {
		if n16Ref != "" {
			s.vsmfN16Release(ctx, base, n16Ref, "", false)
		}
		s.releaseSessionLocal(ctx, ref, sess, false)
		if n4Up {
			_ = s.vsmfDeleteN4(ctx, base, sess) // already logged WARN; the rejection is what the AMF needs
		}
		reject(f)
	}

	// Step 3b-3c: N4 Establishment with the V-UPF (UL PDR on N3, DL PDR on the N9 F-TEID).
	if err := s.vsmfEstablishN4(ctx, base, sess); err != nil {
		abort(&vsmfFailure{status: http.StatusInternalServerError, cause: causeSystemFailure, result: "FAILURE",
			cause5GSM: n1smCauseInsufficientResources, detail: "V-UPF N4 establishment failed: " + err.Error()}, false, "")
		return
	}

	// Step 6: Nsmf_PDUSession_Create towards the H-SMF through the local SEPP.
	data := s.buildPduSessionCreateData(sess, in, ref)
	n1bin, unknownN1, alwaysOn := n1SmInfoFromUe(in)
	data.AlwaysOnRequested = alwaysOn
	if len(n1bin) > 0 {
		data.N1SmInfoFromUe = &HRRefToBinaryData{ContentID: partNameN1Ue}
	}
	if len(unknownN1) > 0 {
		data.UnknownN1SmInfo = &HRRefToBinaryData{ContentID: partNameUnknownN1}
	}
	status, hdr, body, ferr := s.vsmfPostCreate(ctx, base, sess, data, n1bin, unknownN1, hSmfAPIRoot, hSmfBasePath)
	if ferr != nil {
		abort(ferr, true, "")
		return
	}
	if status != http.StatusCreated {
		abort(s.classifyCreateFailure(ctx, base, status, hdr.Get("Content-Type"), body), true, "")
		return
	}

	// 201: Location = pduSessionRef (stored absolute so the release can derive the target apiRoot).
	href, err := resolveHSMFLocation(hdr.Get("Location"), in.hSmfURI)
	if err != nil {
		base.With("interface", "N16").WarnContext(ctx, "H-SMF Location refused", "direction", "IN", "result", "FAILURE",
			"error", err, "location", hdr.Get("Location"), "spec_ref", "TS 29.502 Table 6.1.3.5.3.1-4")
		abort(&vsmfFailure{status: http.StatusInternalServerError, cause: causeSystemFailure, result: "FAILURE",
			cause5GSM: n1smCauseNetworkFailure, n16Err: true, detail: "H-SMF 201 without a usable Location: " + err.Error()}, true, "")
		return
	}
	created, toUe, err := decodeCreatedData(hdr.Get("Content-Type"), body)
	if err == nil {
		err = validateCreatedData(created)
	}
	if err != nil {
		// Table 6.1.6.2.10-1 violated: tear the H-SMF session down again (§5 "No hcnTunnelInfo" row).
		abort(&vsmfFailure{status: http.StatusInternalServerError, cause: causeSystemFailure, result: "FAILURE",
			cause5GSM: n1smCauseNetworkFailure, n16Err: true, detail: "invalid PduSessionCreatedData: " + err.Error()}, true, href)
		return
	}
	hcn, _ := parseHRTunnel(created.HcnTunnelInfo) // validated
	s.sessionMu.Lock()
	sess.HR.HSmfPduSessionRef = href
	sess.HR.PeerTunnel = hcn
	applyCreatedToSession(sess, created)
	s.sessionMu.Unlock()
	base.With("interface", "N16").InfoContext(ctx, "Nsmf_PDUSession_Create answered by the H-SMF", "direction", "IN",
		"result", "OK", "pdu_session_ref", href, "ue_ipv4", created.UeIPv4Address, "ue_ipv6_prefix", created.UeIPv6Prefix,
		"hcn_ip", hcn.IP.String(), "hcn_teid", hcn.TEID, "charging_id", sess.HR.ChargingID,
		"spec_ref", "TS 23.502 §4.3.2.2.2 step 13; TS 29.502 §5.2.2.7.1")

	// Step 13a: V-UPF Update FAR UL FORW + OHC towards the H-UPF (hcnTunnelInfo).
	if err := s.vsmfUpdateULFAR(ctx, base, sess); err != nil {
		abort(&vsmfFailure{status: http.StatusInternalServerError, cause: causeSystemFailure, result: "FAILURE",
			cause5GSM: n1smCauseInsufficientResources, detail: "V-UPF UL FAR update failed: " + err.Error()}, true, href)
		return
	}

	// Steps 14-17: N1 Accept (V-SMF owns N1) + N2 PDU Session Resource Setup Request Transfer.
	s.sessionMu.Lock()
	n1Accept, n2, err := s.buildHRAcceptAndN2(sess, in, created, toUe)
	s.sessionMu.Unlock()
	if err != nil {
		abort(&vsmfFailure{status: http.StatusInternalServerError, cause: causeSystemFailure, result: "FAILURE",
			cause5GSM: n1smCauseInsufficientResources, detail: "N1/N2 encoding failed: " + err.Error()}, true, href)
		return
	}

	if cerr := ctx.Err(); cerr != nil {
		// The AMF is gone (or its timeout fired): nobody will use this session, release everything
		// including the H-SMF session (TS 29.502 §5.2.2.9).
		abort(&vsmfFailure{status: http.StatusGatewayTimeout, cause: causePeerNotResponding, result: "FAILURE",
			cause5GSM: n1smCauseNetworkFailure, detail: "request cancelled before the answer: " + cerr.Error()}, true, href)
		return
	}
	s.sessionMu.Lock()
	sess.State = "ACTIVE"
	fiveQI := sess.FiveQI
	s.sessionMu.Unlock()
	s.persistSession(ctx, ref, sess)
	metrics.PDUSessionTotal.WithLabelValues("SMF", dnnNI, "OK").Inc()
	finish("OK")
	log.InfoContext(ctx, "home-routed PDU session established (V-SMF)", "direction", "OUT", "result", "OK",
		"sm_context_ref", ref, "ue_ipv4", created.UeIPv4Address, "ue_ipv6_prefix", created.UeIPv6Prefix, "seid", sess.SEID,
		"n3_teid", sess.ULTEID, "n9_dl_teid", n9DLTEID, "5qi", fiveQI, "dnn", dnnNI,
		"spec_ref", "TS 23.502 §4.3.2.2.2 steps 14-17")

	resp := map[string]interface{}{
		"smContextRef": ref,
		"n1SmMsg":      base64.StdEncoding.EncodeToString(n1Accept),
		"n2SmInfo":     base64.StdEncoding.EncodeToString(n2),
		"n2SmInfoType": "PDU_RES_SETUP_REQ",
	}
	if in.sfAnswer != "" {
		resp["supportedFeatures"] = in.sfAnswer
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Location", "/nsmf-pdusession/v1/sm-contexts/"+ref)
	w.WriteHeader(http.StatusCreated)
	if werr := hrWriteJSONErr(ctx, log, w, resp); werr != nil {
		// The AMF did not get the answer: release the H-SMF session, the V-UPF and the local state.
		log.WarnContext(ctx, "home-routed PDU session released: the AMF did not receive the 201", "direction", "OUT",
			"result", "FAILURE", "error", werr, "sm_context_ref", ref, "spec_ref", "TS 29.502 §5.2.2.9; TS 23.502 §4.3.4.3")
		s.releaseSessionLocal(context.WithoutCancel(ctx), ref, sess, true)
	}
}

// n1SmInfoFromUe returns the binary n1SmInfoFromUe and unknownN1SmInfo contents: the optional IEs
// of the PDU SESSION ESTABLISHMENT REQUEST with their Type fields, exactly as the UE sent them (after
// the 5GSM header and the mandatory Integrity protection maximum data rate V-IE, which travels as
// maxIntegrityProtectedDataRateUl/Dl). IEs this V-SMF does not comprehend go to unknownN1SmInfo, the
// rest to n1SmInfoFromUe; the V-SMF interprets none of them. Ref: TS 29.502 §5.2.3.1.2.
// The Always-on PDU session requested IE is not forwarded in either part: it is returned as alwaysOn
// (PduSessionCreateData.alwaysOnRequested; no V-SMF policy denies it).
func n1SmInfoFromUe(in *vsmfCreateIn) (known, unknown []byte, alwaysOn bool) {
	if in.pduReq == nil || len(in.n1SmMsg) <= nas5GSMHeaderLen+nasIPMDRLen {
		return nil, nil, false
	}
	return splitN1SmInfo(in.n1SmMsg[nas5GSMHeaderLen+nasIPMDRLen:])
}

// ipmdrName maps an integrity protection maximum data rate octet to the enum ("" = not representable).
func ipmdrName(b byte) string {
	switch b {
	case ipmdr64kbps:
		return rate64Kbps
	case ipmdrFull:
		return rateMaxUE
	}
	return ""
}

// buildPduSessionCreateData builds the PostPduSessions body (TS 29.502 Table 6.1.6.2.9-1,
// HomeRoutedPduSession.md §4). sNssai is the HPLMN S-NSSAI; hplmnSnssai is deliberately not sent
// (LBO with I-SMF only). The caller sets n1SmInfoFromUe when it sends the binary part.
func (s *Server) buildPduSessionCreateData(sess *Session, in *vsmfCreateIn, ref string) *PduSessionCreateData {
	psi := int(sess.PDUSessionID)
	anType, _ := in.req["anType"].(string)
	if anType == "" {
		anType = "3GPP_ACCESS"
	}
	ratType, _ := in.req["ratType"].(string)
	s.sessionMu.Lock()
	hp, n9DLTEID, chargingID := sess.HR.HplmnSnssai, sess.HR.N9DLTEID, sess.HR.ChargingID
	s.sessionMu.Unlock()
	d := &PduSessionCreateData{
		SUPI: sess.SUPI, PduSessionID: &psi, DNN: in.dnn,
		SNSSAI:            &HRSnssai{SST: int(hp.SST), SD: hp.SD},
		VsmfID:            s.cfg.NFInstanceID,
		ServingNetwork:    s.servingNetwork(),
		RequestType:       "INITIAL_REQUEST",
		VsmfPduSessionURI: s.vsmfAPIRoot() + "/nsmf-pdusession/v1/vsmf-pdu-sessions/" + ref,
		VcnTunnelInfo:     &HRTunnelInfo{IPv4Addr: s.n9Addr().String(), GtpTeid: formatTEID(n9DLTEID)},
		AnType:            anType,
		RatType:           ratType,
		ChargingID:        chargingID,
	}
	if in.pduReq != nil {
		d.MaxIntegrityProtectedDataRateUl = ipmdrName(in.pduReq.IntegrityProtectionMaxDataRate[0])
		d.MaxIntegrityProtectedDataRateDl = ipmdrName(in.pduReq.IntegrityProtectionMaxDataRate[1])
	}
	return d
}

// encodeCreateRequest returns the Content-Type and body of PostPduSessions: plain JSON, or
// multipart/related (JSON part + binary n1SmInfoFromUe and unknownN1SmInfo parts, each only when
// not empty). Ref: TS 29.502 §6.1.3.5.2.2; TS 29.500 §6.1.2.4.
func encodeCreateRequest(data *PduSessionCreateData, n1, unknown []byte) (string, []byte, error) {
	js, err := json.Marshal(data)
	if err != nil {
		return "", nil, fmt.Errorf("smf: encode PduSessionCreateData: %w", err)
	}
	if len(n1) == 0 && len(unknown) == 0 {
		return mediaTypeJSON, js, nil
	}
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	jp, err := mw.CreatePart(textproto.MIMEHeader{"Content-Type": {mediaTypeJSON}})
	if err == nil {
		_, err = jp.Write(js)
	}
	for _, bin := range []struct {
		id string
		b  []byte
	}{{partNameN1Ue, n1}, {partNameUnknownN1, unknown}} {
		if err != nil || len(bin.b) == 0 {
			continue
		}
		var bp io.Writer
		bp, err = mw.CreatePart(textproto.MIMEHeader{"Content-Type": {mediaType5GS}, "Content-Id": {bin.id}})
		if err == nil {
			_, err = bp.Write(bin.b)
		}
	}
	if err == nil {
		err = mw.Close()
	}
	if err != nil {
		return "", nil, fmt.Errorf("smf: encode multipart/related: %w", err)
	}
	return fmt.Sprintf("multipart/related; boundary=%s; type=%q", mw.Boundary(), mediaTypeJSON), buf.Bytes(), nil
}

// n16Request sends one request to the local SEPP (never to the home FQDN): the TCP target is
// peers.sepp, the home NF apiRoot goes in 3gpp-Sbi-Target-apiRoot. Ref: TS 29.500 §6.1.4.3.
func (s *Server) n16Request(ctx context.Context, method, apiRoot, path, contentType string, body []byte) (int, http.Header, []byte, error) {
	rq, err := http.NewRequestWithContext(ctx, method, "https://"+s.cfg.Peers.SEPP+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, nil, fmt.Errorf("smf: n16 request: %w", err)
	}
	rq.Header.Set(hdrTargetAPIRoot, apiRoot)
	if s.cfg.PLMN.MCC != "" {
		rq.Header.Set(hdrOriginatingNetworkID, s.cfg.PLMN.MCC+"-"+s.cfg.PLMN.MNC)
	}
	rq.Header.Set("Content-Type", contentType)
	rq.Header.Set("Accept", mediaTypeJSON+", "+mediaTypeMultipartRel)
	if id := logging.CorrelationID(ctx); id != "" {
		rq.Header.Set("X-Correlation-Id", id)
	}
	resp, err := s.httpClient.Do(rq)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	// Read one byte more than the limit so an oversize answer fails explicitly instead of being cut.
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxHRResponseBody+1))
	if err != nil {
		return 0, nil, nil, fmt.Errorf("smf: n16 read response: %w", err)
	}
	if len(b) > maxHRResponseBody {
		// Status and headers are returned with the error: a 201 Location is still needed for the cleanup.
		return resp.StatusCode, resp.Header, nil, fmt.Errorf("smf: n16 response exceeds %d bytes: %w", maxHRResponseBody, errHRBodyTooLarge)
	}
	return resp.StatusCode, resp.Header, b, nil
}

// vsmfPostCreate sends PostPduSessions. A transport error or timeout is returned as a *vsmfFailure
// (#38, FAILURE); otherwise the raw answer is returned.
func (s *Server) vsmfPostCreate(ctx context.Context, log *slog.Logger, sess *Session, data *PduSessionCreateData,
	n1, unknownN1 []byte, apiRoot, hsmfBasePath string) (int, http.Header, []byte, *vsmfFailure) {
	ct, body, err := encodeCreateRequest(data, n1, unknownN1)
	if err != nil {
		return 0, nil, nil, &vsmfFailure{status: http.StatusInternalServerError, cause: causeSystemFailure,
			result: "FAILURE", cause5GSM: n1smCauseNetworkFailure, detail: err.Error(), n16Err: true}
	}
	path := strings.TrimSuffix(hsmfBasePath, "/") + "/pdu-sessions"
	ctx, cancel := context.WithTimeout(ctx, s.n16TimeoutFor(hrN16Timeout))
	defer cancel()
	nlog := log.With("interface", "N16")
	hsmfBase := apiRoot + hsmfBasePath
	nlog.InfoContext(ctx, "Nsmf_PDUSession_Create (PostPduSessions) sent via SEPP", "direction", "OUT",
		"message_type", "PduSessionCreateData", "via_sepp", s.cfg.Peers.SEPP, "target_api_root", apiRoot,
		"home_plmn", homePLMNFromDNN(data.DNN), "charging_id", data.ChargingID, "n1_sm_info_bytes", len(n1), "unknown_n1_sm_info_bytes", len(unknownN1),
		"spec_ref", "TS 23.502 §4.3.2.2.2 step 6; TS 29.502 §5.2.2.7.1; TS 29.500 §6.1.4.3")
	start := time.Now()
	status, hdr, rb, err := s.n16Request(ctx, http.MethodPost, apiRoot, path, ct, body)
	if err != nil && errors.Is(err, errHRBodyTooLarge) {
		nlog.ErrorContext(ctx, "N16 PostPduSessions answer too large", "direction", "IN", "result", "FAILURE", "error", err,
			"http_status", status, "limit_bytes", maxHRResponseBody, "spec_ref", "TS 29.502 §5.2.2.7.1; TS 29.500 §5.2.7")
		if status == http.StatusCreated {
			// The H-SMF created the session: release it through the Location if it is usable.
			if href, lerr := resolveHSMFLocation(hdr.Get("Location"), hsmfBase); lerr == nil {
				s.vsmfN16Release(ctx, log, href, "", false)
			}
		}
		return 0, nil, nil, &vsmfFailure{status: http.StatusInternalServerError, cause: causeSystemFailure, result: "FAILURE",
			cause5GSM: n1smCauseNetworkFailure, n16Err: true, detail: "H-SMF answer exceeds the size limit"}
	}
	if err != nil {
		nlog.ErrorContext(ctx, "N16 PostPduSessions failed", "direction", "IN", "result", "FAILURE", "error", err,
			"duration_ms", time.Since(start).Milliseconds(), "via_sepp", s.cfg.Peers.SEPP,
			"spec_ref", "TS 29.502 §5.2.2.7.1; TS 29.500 §6.1.4.3")
		return 0, nil, nil, &vsmfFailure{status: http.StatusGatewayTimeout, cause: causePeerNotResponding, result: "FAILURE",
			cause5GSM: n1smCauseNetworkFailure, n16Err: true, detail: "H-SMF path unavailable: " + err.Error()}
	}
	nlog.InfoContext(ctx, "N16 PostPduSessions answered", "direction", "IN", "http_status", status,
		"duration_ms", time.Since(start).Milliseconds(), "spec_ref", "TS 29.502 §5.2.2.7.1")
	return status, hdr, rb, nil
}

// classifyCreateFailure maps a non-201 PostPduSessions answer to the AMF/UE rejection. A
// PduSessionCreateError ({error, n1smCause}) comes from the H-SMF: n1smCause is used when present,
// else the fallback of the cause (HomeRoutedPduSession.md §5). Anything else (plain ProblemDetails
// raised by a SEPP, empty or unparsable body, 5xx) is an N16 path failure: #38. The HTTP status and
// application cause returned to the AMF are mapped to those PostSmContexts allows
// (mapPostSmContextsError); the cause the peer sent is only logged.
func (s *Server) classifyCreateFailure(ctx context.Context, log *slog.Logger, status int, contentType string, body []byte) *vsmfFailure {
	f := &vsmfFailure{status: status, cause: causeSystemFailure, result: "FAILURE", cause5GSM: n1smCauseNetworkFailure, n16Err: true,
		detail: fmt.Sprintf("H-SMF path answered %d", status)}
	if status < 400 {
		f.status = http.StatusInternalServerError
		f.detail = fmt.Sprintf("unexpected N16 status %d", status)
		return f
	}
	var wrapped struct {
		Error     *HRProblemDetails `json:"error"`
		N1smCause string            `json:"n1smCause"`
	}
	var plain HRProblemDetails
	werr := json.Unmarshal(body, &wrapped)
	perr := json.Unmarshal(body, &plain)
	if werr != nil && perr != nil && len(body) > 0 {
		snippet := body
		if len(snippet) > maxLoggedErrBody {
			snippet = snippet[:maxLoggedErrBody]
		}
		log.WarnContext(ctx, "N16 error body is neither a PduSessionCreateError nor a ProblemDetails", "interface", "N16",
			"direction", "IN", "result", "FAILURE", "http_status", status, "error", fmt.Errorf("smf: decode N16 error body: %w", perr),
			"content_type", contentType, "body", string(snippet), "body_bytes", len(body),
			"spec_ref", "TS 29.502 Table 6.1.6.2.37-1; TS 29.571 §5.2.4.1")
	}
	peerCause, fromHSMF := "", false
	switch {
	case wrapped.Error != nil:
		// PduSessionCreateError from the H-SMF.
		fromHSMF = true
		f.result = "REJECT"
		peerCause = wrapped.Error.Cause
		f.detail = wrapped.Error.Detail
		if v, err := strconv.ParseUint(wrapped.N1smCause, 16, 8); err == nil && v != 0 && len(wrapped.N1smCause) == 2 {
			f.cause5GSM = uint8(v)
		} else {
			if wrapped.N1smCause != "" {
				log.WarnContext(ctx, "H-SMF n1smCause ignored (not two hex digits)", "interface", "N16", "direction", "IN",
					"n1sm_cause", wrapped.N1smCause, "spec_ref", "TS 29.502 Table 6.1.6.2.37-1")
			}
			f.cause5GSM = fallback5GSMCause(wrapped.Error.Cause)
		}
	case plain.Cause != "" || plain.Status != 0:
		// ProblemDetails raised by a SEPP (or an intermediary): path failure.
		peerCause = plain.Cause
		f.detail = plain.Detail
	}
	f.status, f.cause = mapPostSmContextsError(status, peerCause, fromHSMF)
	if f.status != status || f.cause != peerCause {
		log.InfoContext(ctx, "N16 error mapped to a PostSmContexts error", "interface", "N16", "direction", "IN",
			"peer_http_status", status, "peer_cause", peerCause, "http_status", f.status, "cause", f.cause,
			"from_hsmf", fromHSMF, "spec_ref", "TS 29.502 Table 6.1.3.2.3.1-3")
	}
	return f
}

// postSmContexts403Causes are the application errors of a 403 SmContextCreateError a V-SMF may
// pass on from the H-SMF. Ref: TS 29.502 Table 6.1.3.2.3.1-3 (intersected with Table 6.1.3.5.3.1-3).
var postSmContexts403Causes = map[string]bool{
	causeN1SMError: true, causeSNSSAIDenied: true, causeDNNDenied: true, "PDUTYPE_DENIED": true,
	"SSC_DENIED": true, causeSubscriptionDenied: true, causeDNNNotSupported: true,
	"PDUTYPE_NOT_SUPPORTED": true, "SSC_NOT_SUPPORTED": true, "NO_EPS_5GS_CONTINUITY": true,
	"INTEGRITY_PROTECTED_MDR_NOT_ACCEPTABLE": true, causeNotSupportedWithISMF: true,
	"EXCEEDED_UE_SLICE_DATA_RATE": true, "EXCEEDED_SLICE_DATA_RATE": true,
}

// mapPostSmContextsError maps what the home network (or a SEPP on the path) answered to the HTTP
// status and application cause of the SmContextCreateError the V-SMF returns to the AMF; only values
// listed in TS 29.502 Table 6.1.3.2.3.1-3 are produced.
//
//   - H-SMF 403 with a cause the AMF's table allows: relayed; any other 403 cause: 500 SYSTEM_FAILURE.
//   - H-SMF 500 INSUFFICIENT_RESOURCES_SLICE[_DNN]: relayed; any other 500: 500 SYSTEM_FAILURE.
//   - H-SMF 503 DNN_CONGESTION / S_NSSAI_CONGESTION: relayed; any other 503, and 502/504: 504 PEER_NOT_RESPONDING.
//   - H-SMF 400 / 404 (the V-SMF's own N16 request was wrong, or the H-SMF has no such context): 500
//     SYSTEM_FAILURE, never relayed (the AMF's request is not at fault).
//   - not from the H-SMF (SEPP ProblemDetails, empty body, transport): 502/503/504 -> 504
//     PEER_NOT_RESPONDING, everything else -> 500 SYSTEM_FAILURE.
func mapPostSmContextsError(status int, cause string, fromHSMF bool) (int, string) {
	switch status {
	case http.StatusBadGateway, http.StatusGatewayTimeout, http.StatusRequestTimeout:
		return http.StatusGatewayTimeout, causePeerNotResponding
	case http.StatusServiceUnavailable:
		if fromHSMF && (cause == causeDNNCongestion || cause == causeSNSSAICongestion) {
			return status, cause
		}
		return http.StatusGatewayTimeout, causePeerNotResponding
	}
	if !fromHSMF {
		return http.StatusInternalServerError, causeSystemFailure
	}
	switch {
	case status == http.StatusForbidden && postSmContexts403Causes[cause]:
		return status, cause
	case status == http.StatusInternalServerError && (cause == causeInsufficientResSl || cause == causeInsufficientResSlice):
		return status, cause
	}
	return http.StatusInternalServerError, causeSystemFailure
}

// fallback5GSMCause is the 5GSM cause of a PduSessionCreateError without n1smCause
// (HomeRoutedPduSession.md §5; TS 24.501 §9.11.4.2). Unknown causes map to #38.
func fallback5GSMCause(cause string) uint8 {
	switch cause {
	case causeDNNDenied, causeDNNNotSupported:
		return n1smCauseMissingOrUnknownDNN
	case causeSNSSAIDenied, causeSubscriptionDenied:
		return n1smCauseNotSubscribed
	case "PDUTYPE_DENIED", "PDUTYPE_NOT_SUPPORTED":
		return n1smCauseUnknownPDUType
	case "SSC_DENIED", "SSC_NOT_SUPPORTED":
		return nas.Cause5GSMNotSupportedSSCMode
	case causeN1SMError:
		return n1smCauseProtocolError
	case causeInsufficientResSl:
		return nas.Cause5GSMInsufficientResourcesSlice
	case causeInsufficientResSlice:
		return n1smCauseInsufficientResSlice
	case causeSystemFailure, causeDNNCongestion, causeSNSSAICongestion:
		return n1smCauseInsufficientResources
	}
	return n1smCauseNetworkFailure
}

// resolveHSMFLocation turns the 201 Location (absolute, or relative to the H-SMF apiRoot) into the
// absolute pduSessionRef URI. The target is pinned: the Location must be https, name the same host
// (and port) as hSmfUri and lie under the PDU session collection, so a hostile or buggy peer cannot
// steer the later release to another endpoint. Ref: TS 29.502 Table 6.1.3.5.3.1-4, §5.2.2.9.
func resolveHSMFLocation(loc, hSmfURI string) (string, error) {
	if loc == "" {
		return "", errors.New("location header missing")
	}
	base, err := url.Parse(hSmfURI)
	if err != nil {
		return "", fmt.Errorf("hSmfUri: %w", err)
	}
	l, err := url.Parse(loc)
	if err != nil {
		return "", fmt.Errorf("location: %w", err)
	}
	abs := base.ResolveReference(l)
	if abs.Scheme != "https" || abs.Host == "" {
		return "", fmt.Errorf("location %q is not an https resource URI", loc)
	}
	if !strings.EqualFold(abs.Host, base.Host) {
		return "", fmt.Errorf("location host %q differs from hSmfUri host %q", abs.Host, base.Host)
	}
	if abs.User != nil || abs.RawQuery != "" || abs.Fragment != "" {
		return "", fmt.Errorf("location %q carries userinfo, query or fragment", loc)
	}
	rest, ok := strings.CutPrefix(abs.Path, hsmfPduSessionsPath)
	if !ok || rest == "" || strings.Contains(rest, "/") || strings.Contains(abs.EscapedPath(), "..") {
		return "", fmt.Errorf("location path %q is not under %s", abs.Path, hsmfPduSessionsPath)
	}
	return abs.String(), nil
}

// decodeCreatedData decodes the 201 body (JSON or multipart/related) and the binary n1SmInfoToUe.
func decodeCreatedData(contentType string, body []byte) (*PduSessionCreatedData, []byte, error) {
	mp, err := readHRBody(contentType, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	var c PduSessionCreatedData
	if err := json.Unmarshal(mp.JSON, &c); err != nil {
		return nil, nil, fmt.Errorf("smf: decode PduSessionCreatedData: %w", err)
	}
	var toUe []byte
	if c.N1SmInfoToUe != nil {
		toUe = mp.Parts[strings.Trim(c.N1SmInfoToUe.ContentID, "<> ")]
	}
	return &c, toUe, nil
}

// validateCreatedData checks the attributes the V-SMF needs from PduSessionCreatedData
// (TS 29.502 Table 6.1.6.2.10-1: pduSessionType, sscMode M; hcnTunnelInfo C, shall be present for HR).
func validateCreatedData(c *PduSessionCreatedData) error {
	if c.PduSessionType == "" || c.SscMode == "" {
		return errors.New("pduSessionType/sscMode missing")
	}
	if c.HcnTunnelInfo == nil {
		return errors.New("hcnTunnelInfo missing")
	}
	if _, err := parseHRTunnel(c.HcnTunnelInfo); err != nil {
		return err
	}
	if c.UeIPv4Address == "" && c.UeIPv6Prefix == "" {
		return errors.New("no UE address")
	}
	if c.UeIPv4Address != "" && net.ParseIP(c.UeIPv4Address).To4() == nil {
		return fmt.Errorf("ueIpv4Address %q invalid", c.UeIPv4Address)
	}
	return nil
}

// pduSessionTypeFromName is the inverse of pduSessionTypeName (TS 29.571 PduSessionType).
func pduSessionTypeFromName(n string) uint8 {
	switch n {
	case "IPV6":
		return nas.PDUSessionTypeIPv6
	case "IPV4V6":
		return nas.PDUSessionTypeIPv4v6
	}
	return nas.PDUSessionTypeIPv4
}

// applyCreatedToSession copies the H-SMF answer into the session (QoS, AMBR, type, UE address).
// The caller holds Server.sessionMu.
func applyCreatedToSession(sess *Session, c *PduSessionCreatedData) {
	sess.PDUSessionType = pduSessionTypeFromName(c.PduSessionType)
	sess.HR.UEIPv4 = net.ParseIP(c.UeIPv4Address).To4()
	sess.HR.UEIPv6Prefix = c.UeIPv6Prefix
	if c.SessionAmbr != nil {
		sess.AMBRULKbps, sess.AMBRULMbps = parseAMBR(c.SessionAmbr.Uplink, 0, 0)
		sess.AMBRDLKbps, sess.AMBRDLMbps = parseAMBR(c.SessionAmbr.Downlink, 0, 0)
	}
	if f := defaultFlowOf(c); f != nil && f.QosFlowProfile != nil {
		sess.FiveQI = uint8(f.QosFlowProfile.FiveQI)
		if f.QosFlowProfile.ARP != nil {
			sess.ARPPriority = f.QosFlowProfile.ARP.PriorityLevel
		}
	}
	sess.QoSSource = "H-SMF"
}

// defaultFlowOf returns the QoS flow of the default QoS rule (defaultQosRuleInd), else the first one.
func defaultFlowOf(c *PduSessionCreatedData) *HRQosFlowSetupItem {
	for i := range c.QosFlowsSetupList {
		if c.QosFlowsSetupList[i].DefaultQosRuleInd {
			return &c.QosFlowsSetupList[i]
		}
	}
	if len(c.QosFlowsSetupList) > 0 {
		return &c.QosFlowsSetupList[0]
	}
	return nil
}

// buildHRAcceptAndN2 builds the N1 PDU SESSION ESTABLISHMENT ACCEPT body (everything after the 5GSM
// header, like the non-roaming path) and the N2 PDUSessionResourceSetupRequestTransfer
// (UL NG-U = V-UPF N3 F-TEID). The H-SMF qosRules octets are copied unchanged into the Authorized QoS
// rules IE; the DNN is the one the UE requested; S-NSSAI is the VPLMN value.
// Ref: TS 23.502 §4.3.2.2.2 steps 14-17; TS 29.502 §5.2.3.1.2; TS 24.501 §8.3.2.
func (s *Server) buildHRAcceptAndN2(sess *Session, in *vsmfCreateIn, c *PduSessionCreatedData, toUe []byte) ([]byte, []byte, error) {
	qfi, fiveQI := defaultQFI, sess.FiveQI
	var rules []byte
	if f := defaultFlowOf(c); f != nil {
		if f.QFI > 0 {
			qfi = uint8(f.QFI)
		}
		if b, err := base64.StdEncoding.DecodeString(f.QosRules); err == nil && len(b) > 0 {
			rules = b
		}
	}
	if fiveQI == 0 {
		fiveQI = 9
		sess.FiveQI = fiveQI
	}
	var req *nas.PDUSessionEstablishmentRequest
	if in.pduReq != nil { // only the requested type is needed (#50/#51 downgrade cause)
		req = &nas.PDUSessionEstablishmentRequest{PDUSessionType: in.pduReq.PDUSessionType}
	}
	addr := nas.PDUAddressInfo{SessionType: sess.PDUSessionType, IPv4: sess.HR.UEIPv4}
	if sess.HR.UEIPv6Prefix != "" && sess.PDUSessionType != nas.PDUSessionTypeIPv4 {
		addr.IPv6IID = defaultIID()
	}
	body, err := nas.EncodeEstablishmentAcceptBody(nas.EstablishmentAcceptParams{
		Addr: addr, SSCMode: sscModeOf(c.SscMode), QFI: qfi, FiveQI: fiveQI,
		DLMbps: sess.AMBRDLMbps, ULMbps: sess.AMBRULMbps,
		SNSSAI:  []nas.SNSSAI{{SST: sess.SliceID.SST, SD: nas.SDFromString(sess.SliceID.SD)}},
		Request: req,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("smf: encode accept: %w", err)
	}
	// Replace the locally generated Authorized QoS rules (LV-E at offset 1) with the H-SMF octets.
	if rules != nil && len(body) >= 3 {
		n := int(body[1])<<8 | int(body[2])
		if 3+n > len(body) {
			return nil, nil, errors.New("smf: encoded accept: bad QoS rules length")
		}
		out := make([]byte, 0, len(body)+len(rules))
		out = append(out, body[0], byte(len(rules)>>8), byte(len(rules)))
		out = append(out, rules...)
		body = append(out, body[3+n:]...)
	}
	// n1SmInfoToUe (ePCO first, before the DNN IE; anything else appended at the end) and the DNN.
	epco, unknown := splitN1SmInfoToUe(toUe)
	body = append(body, epco...)
	body = append(body, nas.IEIDNN5GSM)
	apn := dnnLabels(stripDNNOperatorID(in.dnn))
	body = append(body, byte(len(apn)))
	body = append(body, apn...)
	body = append(body, unknown...)

	n2, err := buildPDUSessionResourceSetupRequestTransfer(net.ParseIP(s.cfg.UPFN3Addr), sess.ULTEID, qfi, int64(fiveQI),
		int64(sess.AMBRULMbps)*1_000_000, int64(sess.AMBRDLMbps)*1_000_000, ngapPDUSessionType(sess.PDUSessionType))
	if err != nil {
		return nil, nil, fmt.Errorf("smf: encode n2 transfer: %w", err)
	}
	return body, n2, nil
}

// sscModeOf parses the SscMode enumeration (TS 29.571 §5.4.3.6: "SSC_MODE_1".."SSC_MODE_3"); a bare
// digit "1".."3" (sent by earlier builds of this H-SMF) is accepted too. SSC mode 1 on error.
func sscModeOf(s string) uint8 {
	d := strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(s)), "SSC_MODE_")
	if v, err := strconv.ParseUint(d, 10, 8); err == nil && v >= 1 && v <= 3 {
		return uint8(v)
	}
	return nas.SSCMode1
}

// dnnLabels encodes a DNN as the APN label sequence of the DNN IE (TS 23.003 §9.1).
func dnnLabels(dnn string) []byte {
	var out []byte
	for _, l := range strings.Split(dnn, ".") {
		out = append(out, byte(len(l)))
		out = append(out, l...)
	}
	return out
}

// splitN1SmInfoToUe splits the H-SMF n1SmInfoToUe IEs: the Extended PCO (IEI 0x7B, TLV-E) is returned
// as encoded for its place before the DNN IE; every other IE is returned in "unknown" to be appended at
// the end of the Accept (TS 29.502 §5.2.3.1.2; TS 24.501 §8.3.2).
func splitN1SmInfoToUe(b []byte) (epco, unknown []byte) {
	if len(b) >= 3 && b[0] == nas.IEIEPCO {
		n := 3 + (int(b[1])<<8 | int(b[2]))
		if n <= len(b) {
			return b[:n], b[n:]
		}
	}
	return nil, b
}

// vsmfEstablishN4 sends the V-UPF PFCP Session Establishment and checks the Cause. Failure
// returns an error; the caller does not send a Deletion (nothing was installed).
// Ref: TS 23.502 §4.3.2.2.2 step 3b-3c; TS 29.244 §7.5.2, §7.5.3.
func (s *Server) vsmfEstablishN4(ctx context.Context, log *slog.Logger, sess *Session) error {
	req, err := s.buildVSMFEstablishmentRequest(sess, s.nextPFCPSeq())
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, hrN4Timeout)
	defer cancel()
	nlog := log.With("interface", "N4", "seid", sess.SEID)
	nlog.InfoContext(ctx, "PFCP Session Establishment Request sent (V-UPF)", "direction", "OUT",
		"message_type", "PFCPSessionEstablishmentRequest", "n3_teid", sess.ULTEID, "n9_dl_teid", s.hrN9DLTEID(sess),
		"seq", req.Sequence(), "spec_ref", "TS 23.502 §4.3.2.2.2 step 3b; TS 29.244 §7.5.2")
	start := time.Now()
	msg, err := s.pfcpTransact(ctx, s.logger, req, pfcpmsg.MsgTypeSessionEstablishmentResponse)
	if err != nil {
		nlog.WarnContext(ctx, "PFCP Session Establishment Response not received (V-UPF)", "direction", "IN",
			"result", "FAILURE", "error", err, "duration_ms", time.Since(start).Milliseconds(), "spec_ref", "TS 29.244 §7.5.3")
		return fmt.Errorf("smf: vsmf n4 establishment: %w", err)
	}
	rsp, ok := msg.(*pfcpmsg.SessionEstablishmentResponse)
	if !ok || rsp.Cause == nil {
		return fmt.Errorf("smf: vsmf n4 establishment: %w", errPFCPCauseMissing)
	}
	cause, _ := rsp.Cause.Cause()
	if cause != pfcpie.CauseRequestAccepted {
		nlog.WarnContext(ctx, "PFCP Session Establishment rejected by V-UPF", "direction", "IN", "result", "REJECT",
			"pfcp_cause", cause, "spec_ref", "TS 29.244 §7.5.3")
		return fmt.Errorf("smf: vsmf n4 establishment: %w: cause %d", errPFCPRejected, cause)
	}
	s.sessionMu.Lock()
	sess.N4EstablishedAt = time.Now()
	s.sessionMu.Unlock()
	nlog.InfoContext(ctx, "PFCP Session Establishment Response received (V-UPF)", "direction", "IN", "result", "OK",
		"pfcp_cause", cause, "duration_ms", time.Since(start).Milliseconds(), "spec_ref", "TS 29.244 §7.5.3")
	return nil
}

// buildVSMFEstablishmentRequest builds the V-UPF PFCP Session Establishment Request of a
// home-routed session (HomeRoutedPduSession.md §4 "PFCP V-UPF Establishment"):
//
//	UL PDR 1: Source Interface Access, F-TEID = N3 address + UL TEID, OHR GTP-U/UDP/IPv4
//	          -> FAR 2 (FORW, Destination Interface Core; Outer Header Creation added by the
//	          Session Modification once hcnTunnelInfo is known)
//	DL PDR 2: Source Interface Core, F-TEID = N9 address + DL TEID (vcnTunnelInfo), OHR
//	          -> FAR 1 (FORW, Destination Interface Access, BAR 1) — as the non-roaming DL FAR
//
// QER 1 carries no MBR: the Session-AMBR is enforced at the PDU Session Anchor (H-UPF).
// There is no UE IP and no Network Instance (no N6 at the V-UPF). The non-roaming builder
// (sendPFCPSessionEstablishment) is untouched. Ref: TS 29.244 §7.5.2.2, §8.2.3, §8.2.2 NOTE 1.
func (s *Server) buildVSMFEstablishmentRequest(sess *Session, seq uint32) (*pfcpmsg.SessionEstablishmentRequest, error) {
	n9DLTEID := s.hrN9DLTEID(sess)
	n3 := net.ParseIP(s.cfg.UPFN3Addr)
	n9 := s.n9Addr()
	if n3 == nil || n9 == nil {
		return nil, errors.New("smf: vsmf n4 establishment: no valid upf N3/N9 address")
	}
	return pfcpmsg.NewSessionEstablishmentRequest(0, 0, 0, seq, 0,
		pfcpie.NewNodeID("", "", "smf"),
		pfcpie.NewFSEID(sess.SEID, net.ParseIP("0.0.0.0"), nil),
		pfcpie.NewCreatePDR(
			pfcpie.NewPDRID(ulPDRID),
			pfcpie.NewPrecedence(100),
			pfcpie.NewPDI(
				pfcpie.NewSourceInterface(pfcpie.SrcInterfaceAccess),
				pfcpie.NewFTEID(0x01, sess.ULTEID, n3, nil, 0),
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
				pfcpie.NewFTEID(0x01, n9DLTEID, n9, nil, 0),
			),
			pfcpie.NewOuterHeaderRemoval(0, 0),
			pfcpie.NewFARID(dlFARID),
			pfcpie.NewURRID(usageReportingURRID),
			pfcpie.NewQERID(sessionAMBRQERID),
			pfcpie.NewQERID(defaultFlowQERID),
		),
		pfcpie.NewCreateFAR(
			pfcpie.NewFARID(dlFARID),
			pfcpie.NewApplyAction(0x02), // FORW (OHC to the gNB is added by the UP activation)
			pfcpie.NewForwardingParameters(pfcpie.NewDestinationInterface(pfcpie.DstInterfaceAccess)),
			pfcpie.NewBARID(defaultBARID),
		),
		pfcpie.NewCreateFAR(
			pfcpie.NewFARID(ulFARID),
			pfcpie.NewApplyAction(0x02), // FORW
			pfcpie.NewForwardingParameters(pfcpie.NewDestinationInterface(pfcpie.DstInterfaceCore)),
		),
		pfcpie.NewCreateQER(pfcpie.NewQERID(sessionAMBRQERID), pfcpie.NewGateStatus(0, 0)),
		buildDefaultFlowCreateQER(),
		pfcpie.NewCreateURR(
			pfcpie.NewURRID(usageReportingURRID),
			pfcpie.NewMeasurementMethod(0, 1, 1),
			pfcpie.NewReportingTriggers(reportingTriggersPerioVolth),
			pfcpie.NewVolumeThreshold(volumeThresholdFlagTOVOL, s.cfg.N4.VolumeThresholdBytes, 0, 0),
			pfcpie.NewMeasurementPeriod(time.Duration(s.cfg.N4.MeasurementPeriodSeconds)*time.Second),
		),
		pfcpie.NewCreateBAR(pfcpie.NewBARID(defaultBARID)),
	), nil
}

// hrN9DLTEID returns the V-UPF DL N9 TEID of a V-SMF session, read under sessionMu.
func (s *Server) hrN9DLTEID(sess *Session) uint32 {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	return sess.HR.N9DLTEID
}

// buildVSMFULFAR is the Update FAR of step 13a: UL FAR 2, FORW, Destination Interface Core and
// Outer Header Creation GTP-U/UDP/IPv4 to hcnTunnelInfo (the H-UPF N9 endpoint).
// Ref: TS 29.244 §7.5.4.3, §8.2.56.
func buildVSMFULFAR(peer HRTunnel) *pfcpie.IE {
	return pfcpie.NewUpdateFAR(
		pfcpie.NewFARID(ulFARID),
		pfcpie.NewApplyAction(0x02), // FORW
		pfcpie.NewUpdateForwardingParameters(
			pfcpie.NewDestinationInterface(pfcpie.DstInterfaceCore),
			pfcpie.NewOuterHeaderCreation(ohcGTPUUDPIPv4, peer.TEID, peer.IP.String(), "", 0, 0, 0),
		),
	)
}

// vsmfUpdateULFAR sends the V-UPF Session Modification of step 13a and waits for the answer.
// Ref: TS 23.502 §4.3.2.2.2 step 13a; TS 29.244 §7.5.4, §7.5.5.
func (s *Server) vsmfUpdateULFAR(ctx context.Context, log *slog.Logger, sess *Session) error {
	if s.skipN4ForReleasing(sess, "HomeRoutedULFAR") {
		return errSessionReleasing
	}
	ctx, cancel := context.WithTimeout(ctx, hrN4Timeout)
	defer cancel()
	nlog := log.With("interface", "N4", "seid", sess.SEID)
	s.sessionMu.Lock()
	peer := sess.HR.PeerTunnel
	s.sessionMu.Unlock()
	req := pfcpmsg.NewSessionModificationRequest(0, 0, sess.SEID, s.nextPFCPSeq(), 0, buildVSMFULFAR(peer))
	nlog.InfoContext(ctx, "PFCP Session Modification Request sent (V-UPF UL FAR OHC)", "direction", "OUT",
		"message_type", "PFCPSessionModificationRequest", "far_id", ulFARID, "hcn_ip", peer.IP.String(),
		"hcn_teid", peer.TEID, "seq", req.Sequence(), "spec_ref", "TS 23.502 §4.3.2.2.2 step 13a; TS 29.244 §7.5.4.3")
	start := time.Now()
	msg, err := s.pfcpTransact(ctx, s.logger, req, pfcpmsg.MsgTypeSessionModificationResponse)
	if err != nil {
		nlog.WarnContext(ctx, "PFCP Session Modification Response not received (V-UPF)", "direction", "IN", "result", "FAILURE",
			"error", err, "duration_ms", time.Since(start).Milliseconds(), "spec_ref", "TS 29.244 §7.5.5")
		return fmt.Errorf("smf: vsmf n4 modification: %w", err)
	}
	rsp, ok := msg.(*pfcpmsg.SessionModificationResponse)
	if !ok || rsp.Cause == nil {
		return fmt.Errorf("smf: vsmf n4 modification: %w", errPFCPCauseMissing)
	}
	if c, _ := rsp.Cause.Cause(); c != pfcpie.CauseRequestAccepted {
		nlog.WarnContext(ctx, "PFCP Session Modification rejected by V-UPF", "direction", "IN", "result", "REJECT",
			"pfcp_cause", c, "spec_ref", "TS 29.244 §7.5.5")
		return fmt.Errorf("smf: vsmf n4 modification: %w: cause %d", errPFCPRejected, c)
	}
	nlog.InfoContext(ctx, "PFCP Session Modification Response received (V-UPF)", "direction", "IN", "result", "OK",
		"duration_ms", time.Since(start).Milliseconds(), "spec_ref", "TS 29.244 §7.5.5")
	return nil
}

// vsmfDeleteN4 deletes the V-UPF N4 session, detached from the caller's cancellation under its own
// hrN4Timeout. A transport failure, a missing Cause or a Cause other than Request accepted is logged
// (WARN, result FAILURE/REJECT) and returned as an error; callers decide what it changes.
// Ref: TS 23.502 §4.3.4.3; TS 29.244 §7.5.6, §7.5.7.
func (s *Server) vsmfDeleteN4(ctx context.Context, log *slog.Logger, sess *Session) error {
	ctx, cancel := detachedTimeout(ctx, hrN4Timeout)
	defer cancel()
	nlog := log.With("interface", "N4", "seid", sess.SEID)
	req := pfcpmsg.NewSessionDeletionRequest(0, 0, sess.SEID, s.nextPFCPSeq(), 0)
	nlog.InfoContext(ctx, "PFCP Session Deletion Request sent (V-UPF)", "direction", "OUT",
		"message_type", "PFCPSessionDeletionRequest", "spec_ref", "TS 23.502 §4.3.4.3; TS 29.244 §7.5.6")
	msg, err := s.pfcpTransact(ctx, s.logger, req, pfcpmsg.MsgTypeSessionDeletionResponse)
	if err != nil {
		nlog.WarnContext(ctx, "PFCP Session Deletion Response not received (V-UPF)", "direction", "IN", "result", "FAILURE",
			"error", err, "spec_ref", "TS 29.244 §7.5.7")
		return fmt.Errorf("smf: vsmf n4 deletion: %w", err)
	}
	rsp, ok := msg.(*pfcpmsg.SessionDeletionResponse)
	if !ok || rsp.Cause == nil {
		nlog.WarnContext(ctx, "PFCP Session Deletion Response without Cause (V-UPF)", "direction", "IN", "result", "FAILURE",
			"spec_ref", "TS 29.244 §7.5.7")
		return fmt.Errorf("smf: vsmf n4 deletion: %w", errPFCPCauseMissing)
	}
	if c, _ := rsp.Cause.Cause(); c != pfcpie.CauseRequestAccepted {
		nlog.WarnContext(ctx, "PFCP Session Deletion rejected by V-UPF", "direction", "IN", "result", "REJECT",
			"pfcp_cause", c, "spec_ref", "TS 29.244 §7.5.7")
		return fmt.Errorf("smf: vsmf n4 deletion: %w: cause %d", errPFCPRejected, c)
	}
	nlog.InfoContext(ctx, "PFCP Session Deletion Response received (V-UPF)", "direction", "IN", "result", "OK",
		"spec_ref", "TS 29.244 §7.5.7")
	return nil
}

// vsmfN16Release sends ReleasePduSession ({ref}/release, ReleaseData) through the local SEPP and
// expects 204 (TS 29.502 §5.2.2.9). It returns whether the H-SMF confirmed; every failure is logged
// (WARN hsmf_release_failed) and nothing is retried (§5.2.2.9 defines no retry). relCause may be "".
//
// afterUnknownUpdate is true when an earlier N16 Update of the UE-initiated release got no usable answer
// (HR.N16UpdateUnknown): a 404 CONTEXT_NOT_FOUND then means the H-SMF already released the session, which
// counts as released (INFO, OK). A 404 on a first-time release stays a failure.
func (s *Server) vsmfN16Release(ctx context.Context, log *slog.Logger, ref, relCause string, afterUnknownUpdate bool) bool {
	ctx, cancel := detachedTimeout(ctx, s.n16TimeoutFor(hrN16ReleaseTimeout))
	defer cancel()
	nlog := log.With("interface", "N16", "pdu_session_ref", ref)
	u, err := url.Parse(ref)
	if err != nil || u.Host == "" {
		nlog.WarnContext(ctx, "hsmf_release_failed", "direction", "OUT", "result", "FAILURE",
			"error", fmt.Sprintf("bad pduSessionRef %q", ref), "spec_ref", "TS 29.502 §5.2.2.9")
		return false
	}
	apiRoot := u.Scheme + "://" + u.Host
	body, err := json.Marshal(ReleaseData{Cause: relCause})
	if err != nil {
		nlog.WarnContext(ctx, "hsmf_release_failed", "direction", "OUT", "result", "FAILURE",
			"error", fmt.Errorf("smf: encode ReleaseData: %w", err), "spec_ref", "TS 29.502 §5.2.2.9")
		return false
	}
	nlog.InfoContext(ctx, "Nsmf_PDUSession_Release (ReleasePduSession) sent via SEPP", "direction", "OUT",
		"message_type", "ReleaseData", "via_sepp", s.cfg.Peers.SEPP, "target_api_root", apiRoot,
		"spec_ref", "TS 23.502 §4.3.4.3 step 4; TS 29.502 §5.2.2.9; TS 29.500 §6.1.4.3")
	start := time.Now()
	status, _, rspBody, err := s.n16Request(ctx, http.MethodPost, apiRoot, strings.TrimSuffix(u.Path, "/")+"/release", mediaTypeJSON, body)
	switch {
	case err != nil:
		nlog.WarnContext(ctx, "hsmf_release_failed", "direction", "IN", "result", "FAILURE", "error", err,
			"duration_ms", time.Since(start).Milliseconds(), "spec_ref", "TS 29.502 §5.2.2.9")
		return false
	case afterUnknownUpdate && status == http.StatusNotFound && n16ProblemCause(rspBody) == causeContextNotFound:
		nlog.InfoContext(ctx, "N16 ReleasePduSession: H-SMF context already gone after an unanswered Update, counted as released",
			"direction", "IN", "result", "OK", "http_status", status, "cause", causeContextNotFound,
			"duration_ms", time.Since(start).Milliseconds(), "spec_ref", "TS 29.502 §5.2.2.9")
		return true
	case status != http.StatusNoContent && status != http.StatusOK:
		nlog.WarnContext(ctx, "hsmf_release_failed", "direction", "IN", "result", "FAILURE", "http_status", status,
			"duration_ms", time.Since(start).Milliseconds(), "spec_ref", "TS 29.502 §5.2.2.9")
		return false
	}
	nlog.InfoContext(ctx, "N16 ReleasePduSession answered", "direction", "IN", "result", "OK", "http_status", status,
		"duration_ms", time.Since(start).Milliseconds(), "spec_ref", "TS 29.502 §5.2.2.9")
	return true
}

// vsmfReleaseHome is the serving-network release of a home-routed session: N16 release towards the
// H-SMF, then the V-UPF N4 deletion, each leg only when it is not yet done (HR.HomeN16Done /
// HR.VUPFDeleted: a UE-initiated release may have completed one or both). The V-SMF-side cleanup
// proceeds even when N16 fails; the caller (releaseSessionLocal) already freed the local state.
// Ref: TS 23.502 §4.3.4.3 steps 4-6; HomeRoutedPduSession.md §5 "Release towards H-SMF fails".
func (s *Server) vsmfReleaseHome(ctx context.Context, sess *Session, n4Stale bool) {
	s.vsmfReleaseHomeLegs(ctx, sess, n4Stale, hrLegBudgets{})
}

// hrLegBudgets gives each release leg its own sub-deadline (0 = no extra bound beyond the leg's own
// timeout), so a hung leg cannot starve the next one. Implementation guard, not a 3GPP timer.
type hrLegBudgets struct{ drop, n16, n4 time.Duration }

// hrReleaseResult is the outcome of vsmfReleaseHomeLegs: which legs ran and failed.
type hrReleaseResult struct {
	DropFailed, N16Failed, N4Failed bool
}

// Failed reports whether a leg that mattered (N16 or V-UPF deletion) failed; a failed UL DROP alone is
// only logged, as in the UE-initiated release.
func (r hrReleaseResult) Failed() bool { return r.N16Failed || r.N4Failed }

// FailedLegs lists the failed legs for logging.
func (r hrReleaseResult) FailedLegs() []string {
	var l []string
	if r.DropFailed {
		l = append(l, "ul_far_drop")
	}
	if r.N16Failed {
		l = append(l, "n16_release")
	}
	if r.N4Failed {
		l = append(l, "vupf_deletion")
	}
	return l
}

// legCtx derives a sub-deadline for one leg; the leg's detachedTimeout honours it.
func legCtx(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if d <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, d)
}

// vsmfReleaseHomeLegs is vsmfReleaseHome with per-leg sub-budgets and the outcome returned.
func (s *Server) vsmfReleaseHomeLegs(ctx context.Context, sess *Session, n4Stale bool, bud hrLegBudgets) hrReleaseResult {
	var res hrReleaseResult
	log := s.hrLoggerRole(ctx, hrVSMFRole).With("supi", sess.SUPI, "pdu_session_id", sess.PDUSessionID) // no "interface"
	result := "OK"
	s.sessionMu.Lock()
	hRef := sess.HR.HSmfPduSessionRef
	needN16 := hRef != "" && !sess.HR.HomeN16Done
	needN4 := !n4Stale && !sess.HR.VUPFDeleted
	afterUnknown := sess.HR.N16UpdateUnknown
	s.sessionMu.Unlock()
	if !needN16 && !needN4 {
		return res // every leg was done by the UE-initiated release
	}
	// Stop UL forwarding first (V-UPF Update FAR DROP) so no UL packet reaches the H-UPF while the
	// home network releases; a failure is logged and the release continues (finding #13).
	if needN4 {
		dctx, dc := legCtx(ctx, bud.drop)
		res.DropFailed = s.vsmfDropULFAR(dctx, log, sess) != nil
		dc()
	}
	if needN16 {
		nctx, nc := legCtx(ctx, bud.n16)
		if s.vsmfN16Release(nctx, log, hRef, "", afterUnknown) {
			s.sessionMu.Lock()
			sess.HR.HomeN16Done = true
			s.sessionMu.Unlock()
		} else {
			result = "FAILURE"
			res.N16Failed = true
		}
		nc()
	}
	if needN4 {
		// Own sub-budget derived from ctx (not from the N16 leg), so the deletion keeps its reserve.
		pctx, pc := legCtx(ctx, bud.n4)
		if err := s.vsmfDeleteN4(pctx, log, sess); err != nil {
			result = "FAILURE"
			res.N4Failed = true
		} else {
			s.sessionMu.Lock()
			sess.HR.VUPFDeleted = true
			s.sessionMu.Unlock()
		}
		pc()
	}
	metrics.ProcedureTotal.WithLabelValues("SMF", hrProcedure+"Release", result).Inc()
	lvl := slog.LevelInfo
	if result != "OK" {
		lvl = slog.LevelWarn // H-SMF release or V-UPF deletion failed; the local state is freed regardless
	}
	log.Log(ctx, lvl, "home-routed PDU session released (V-SMF)", "interface", "Nsmf", "direction", "OUT", "result", result,
		"seid", sess.SEID, "spec_ref", "TS 23.502 §4.3.4.3 steps 4-6")
	return res
}

// vsmfDropULFAR sends the V-UPF Session Modification that stops UL forwarding: Update FAR ulFARID
// with Apply Action DROP (the UL leg of the N9 tunnel), then waits for the answer. A failure is
// logged (WARN) and returned; every caller continues the release regardless.
// Ref: TS 23.502 §4.3.4.3 step 1a; TS 29.244 §7.5.4.3, §8.2.26 (Apply Action DROP).
func (s *Server) vsmfDropULFAR(ctx context.Context, log *slog.Logger, sess *Session) error {
	if s.skipN4ForReleasing(sess, "HomeRoutedULFARDrop") {
		return errSessionReleasing
	}
	ctx, cancel := detachedTimeout(ctx, hrN4Timeout)
	defer cancel()
	nlog := log.With("interface", "N4", "seid", sess.SEID)
	req := pfcpmsg.NewSessionModificationRequest(0, 0, sess.SEID, s.nextPFCPSeq(), 0,
		pfcpie.NewUpdateFAR(pfcpie.NewFARID(ulFARID), pfcpie.NewApplyAction(applyActionDROP)))
	nlog.InfoContext(ctx, "PFCP Session Modification Request sent (V-UPF UL FAR DROP)", "direction", "OUT",
		"message_type", "PFCPSessionModificationRequest", "far_id", ulFARID, "apply_action", "DROP",
		"seq", req.Sequence(), "spec_ref", "TS 23.502 §4.3.4.3 step 1a; TS 29.244 §7.5.4.3")
	start := time.Now()
	msg, err := s.pfcpTransact(ctx, s.logger, req, pfcpmsg.MsgTypeSessionModificationResponse)
	if err != nil {
		nlog.WarnContext(ctx, "PFCP Session Modification Response not received (V-UPF UL FAR DROP)", "direction", "IN",
			"result", "FAILURE", "error", err, "duration_ms", time.Since(start).Milliseconds(), "spec_ref", "TS 29.244 §7.5.5")
		return fmt.Errorf("smf: vsmf n4 ul drop: %w", err)
	}
	rsp, ok := msg.(*pfcpmsg.SessionModificationResponse)
	if !ok || rsp.Cause == nil {
		nlog.WarnContext(ctx, "PFCP Session Modification Response without Cause (V-UPF UL FAR DROP)", "direction", "IN",
			"result", "FAILURE", "spec_ref", "TS 29.244 §7.5.5")
		return fmt.Errorf("smf: vsmf n4 ul drop: %w", errPFCPCauseMissing)
	}
	if c, _ := rsp.Cause.Cause(); c != pfcpie.CauseRequestAccepted {
		nlog.WarnContext(ctx, "PFCP Session Modification rejected by V-UPF (UL FAR DROP)", "direction", "IN",
			"result", "REJECT", "pfcp_cause", c, "spec_ref", "TS 29.244 §7.5.5")
		return fmt.Errorf("smf: vsmf n4 ul drop: %w: cause %d", errPFCPRejected, c)
	}
	nlog.InfoContext(ctx, "PFCP Session Modification Response received (V-UPF UL FAR DROP)", "direction", "IN",
		"result", "OK", "duration_ms", time.Since(start).Milliseconds(), "spec_ref", "TS 29.244 §7.5.5")
	return nil
}

// detachedTimeout returns a context detached from ctx's cancellation (a cancelled request must not skip a
// release leg) with a timeout of d, shortened to ctx's own deadline when that is sooner: the leg budget
// of the UE-initiated release (hrUEReleaseBudget) therefore still bounds every leg.
func detachedTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if dl, ok := ctx.Deadline(); ok {
		if rem := time.Until(dl); rem < d {
			d = rem
		}
	}
	return context.WithTimeout(context.WithoutCancel(ctx), d)
}

// UE-initiated release time budget (implementation guards, not 3GPP timers). The AMF waits
// releaseSMContextTimeout (10 s) for the UpdateSMContext answer, so the V-SMF bounds the whole
// handling to hrUEReleaseBudget (< 10 s) with the three legs sharing that one deadline; a leg that
// times out counts as not done and is retried at DeleteSMContext.
const (
	hrUEReleaseBudget  = 7 * time.Second
	hrUEReleaseN4Leg   = 2 * time.Second
	hrUEReleaseN16Leg  = 3 * time.Second
	hrN16CauseLogLimit = 128
)

// n16ProblemCause extracts the application error cause from a ProblemDetails or HsmfUpdateError body
// for logging only; "" when the body is not parsable. Ref: TS 29.571 §5.2.4.1; TS 29.502 §6.1.6.2.
func n16ProblemCause(body []byte) string {
	var b struct {
		Cause string `json:"cause"`
		Error *struct {
			Cause string `json:"cause"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &b) != nil {
		return ""
	}
	c := b.Cause
	if c == "" && b.Error != nil {
		c = b.Error.Cause
	}
	return sanitizeLogValue(c)
}

// hrN16UpdateTimeout bounds the N16 Update (UE requested release) call; the UE-visible release does
// not wait longer for the home network. Implementation guard, not a 3GPP timer.
const hrN16UpdateTimeout = 5 * time.Second

// vsmfN16UpdateRelease sends Nsmf_PDUSession_Update (POST {pduSessionRef}/modify) with
// HsmfUpdateData{requestIndication=UE_REQ_PDU_SES_REL, pti} through the local SEPP and expects 200 or
// 204. Only the JSON part is sent: the optional n1SmInfoFromUe multipart of the request IEs is not
// forwarded (the H-SMF releases without it). Any failure is logged (WARN hsmf_update_failed), never
// retried, and returned as false. Ref: TS 29.502 §5.2.2.8.2.3 step 1; TS 23.502 §4.3.4.3 step 2.
func (s *Server) vsmfN16UpdateRelease(ctx context.Context, log *slog.Logger, ref string, pti uint8) bool {
	ctx, cancel := detachedTimeout(ctx, s.n16TimeoutFor(hrN16UpdateTimeout))
	defer cancel()
	nlog := log.With("interface", "N16", "pdu_session_ref", ref)
	u, err := url.Parse(ref)
	if err != nil || u.Host == "" {
		nlog.WarnContext(ctx, "hsmf_update_failed", "direction", "OUT", "result", "FAILURE",
			"error", fmt.Sprintf("bad pduSessionRef %q", ref), "spec_ref", "TS 29.502 §5.2.2.8.2.3")
		return false
	}
	apiRoot := u.Scheme + "://" + u.Host
	body, err := json.Marshal(HsmfUpdateData{RequestIndication: requestIndicationUEReqPduSesRel, PTI: &pti})
	if err != nil {
		nlog.WarnContext(ctx, "hsmf_update_failed", "direction", "OUT", "result", "FAILURE",
			"error", fmt.Errorf("smf: encode HsmfUpdateData: %w", err), "spec_ref", "TS 29.502 §5.2.2.8.2.3")
		return false
	}
	nlog.InfoContext(ctx, "Nsmf_PDUSession_Update (UE_REQ_PDU_SES_REL) sent via SEPP", "direction", "OUT",
		"message_type", "HsmfUpdateData", "request_indication", requestIndicationUEReqPduSesRel, "pti", pti,
		"via_sepp", s.cfg.Peers.SEPP, "target_api_root", apiRoot,
		"spec_ref", "TS 23.502 §4.3.4.3 step 2; TS 29.502 §5.2.2.8.2.3; TS 29.500 §6.1.4.3")
	start := time.Now()
	status, _, rspBody, err := s.n16Request(ctx, http.MethodPost, apiRoot, strings.TrimSuffix(u.Path, "/")+"/modify", mediaTypeJSON, body)
	switch {
	case err != nil:
		nlog.WarnContext(ctx, "hsmf_update_failed", "direction", "IN", "result", "FAILURE", "error", err,
			"duration_ms", time.Since(start).Milliseconds(), "spec_ref", "TS 29.502 §5.2.2.8.2.3")
		return false
	case status != http.StatusNoContent && status != http.StatusOK:
		nlog.WarnContext(ctx, "hsmf_update_failed", "direction", "IN", "result", "FAILURE", "http_status", status,
			"cause", n16ProblemCause(rspBody), "duration_ms", time.Since(start).Milliseconds(), "spec_ref", "TS 29.502 §5.2.2.8.2.3")
		return false
	}
	nlog.InfoContext(ctx, "N16 Nsmf_PDUSession_Update (UE_REQ_PDU_SES_REL) answered", "direction", "IN", "result", "OK",
		"http_status", status, "duration_ms", time.Since(start).Milliseconds(), "spec_ref", "TS 29.502 §5.2.2.8.2.3 step 2a")
	return true
}

// handleVSMFUEReleaseRequest serves the PDU SESSION RELEASE REQUEST (0xD1) of a home-routed session
// relayed by the AMF in Nsmf_PDUSession_UpdateSMContext. It returns false, having written nothing, when
// the request is not that case (no n1SmMsg, another 5GSM message type, unknown ref, or a session that
// is not a V-SMF home-routed one), so every other path is unchanged. Sequence (TS 23.502 §4.3.4.3):
// UL FAR DROP on the V-UPF (1a), N16 Update UE_REQ_PDU_SES_REL (2), V-UPF N4 deletion (4a-4b), then
// 200 with the PDU SESSION RELEASE COMMAND (#36). The SM context is kept until the AMF's DeleteSMContext
// (TS 29.502 §5.2.2.8.3.3 NOTE); HR.HomeReleased makes that delete local only. A UE-requested release is
// never refused: an H-SMF failure leaves a logged H-SMF orphan. Steps 3a/14/16a (H-SMF Update towards the
// V-SMF, StatusNotify) are not implemented. Ref: TS 24.501 §8.3.12, §8.3.14.
func (s *Server) handleVSMFUEReleaseRequest(w http.ResponseWriter, r *http.Request, ref string, body map[string]interface{}) bool {
	b64, _ := body["n1SmMsg"].(string)
	if b64 == "" {
		return false
	}
	corrID := r.Header.Get("X-Correlation-Id")
	ctx := logging.WithCorrelationID(r.Context(), corrID)
	n1, err := base64.StdEncoding.DecodeString(b64)
	reason := ""
	switch {
	case err != nil:
		reason = "n1SmMsg is not valid base64"
	case len(n1) < nas5GSMHeaderLen:
		reason = "n1SmMsg shorter than the 5GSM header"
	case nas.MessageType(n1[3]) != nas.MsgTypePDUSessionReleaseRequest:
		return false // another 5GSM message: the normal UpdateSMContext path, not an anomaly
	}
	if reason != "" {
		s.hrLoggerRole(ctx, hrVSMFRole).WarnContext(ctx, "n1SmMsg not usable as PDU SESSION RELEASE REQUEST, legacy handling",
			"interface", "Nsmf", "direction", "IN", "result", "REJECT", "reason", reason, "smContextRef", ref,
			"spec_ref", "TS 24.501 §8.3.12; TS 29.502 §6.1.6.2.4")
		return false
	}
	s.sessionMu.Lock()
	sess := s.sessions[ref]
	vsmfHR := sess != nil && sess.HR != nil && sess.HR.Role == HRRoleVSMF
	s.sessionMu.Unlock()
	if !vsmfHR {
		return false // unknown ref and non-HR sessions keep their pre-existing behaviour
	}

	base := s.hrLoggerRole(ctx, hrVSMFRole)
	if s.rejectIfReleasing(w, base, sess, "UE-initiated HR release", false) { // adds supi / pdu_session_id itself
		return true
	}
	log := base.With("supi", sess.SUPI, "pdu_session_id", sess.PDUSessionID, "smContextRef", ref)
	pti := n1[2]
	log.InfoContext(ctx, "PDU SESSION RELEASE REQUEST received (home-routed)", "interface", "Nsmf", "direction", "IN",
		"message_type", "PDUSessionReleaseRequest", "pti", pti,
		"spec_ref", "TS 23.502 §4.3.4.3 step 1; TS 24.501 §8.3.12")

	// Claim the release under the lock. A request while the first one is running gets 409
	// PDU_SESSION_RELEASING (no early Release Command while the legs are unfinished; the AMF retries or
	// the DELETE follows); after completion the same Release Command is answered again (idempotent).
	s.sessionMu.Lock()
	inProgress, done, prevResult := sess.HR.UEReleaseInProgress, sess.HR.UEReleaseDone, sess.HR.UEReleaseResult
	if !inProgress && !done {
		sess.HR.UEReleaseInProgress = true
	}
	hRef := sess.HR.HSmfPduSessionRef
	n4Stale := sess.N4Stale
	s.sessionMu.Unlock()

	deferred := false
	switch {
	case inProgress:
		log.WarnContext(ctx, "UE-initiated HR release already in progress, retransmission refused", "interface", "Nsmf",
			"direction", "OUT", "result", "REJECT", "cause", causeSessionReleasing,
			"spec_ref", "TS 23.502 §4.3.4.3; TS 29.502 §5.2.2.3")
		problem(w, http.StatusConflict, causeSessionReleasing, "PDU session release is in progress")
		return true
	case done:
		// Retransmitted request: answer again, the result label reflects the earlier real outcome.
		if prevResult != "OK" {
			// The first attempt failed (residual H-SMF / V-UPF state); the UE is told "released" again.
			log.WarnContext(ctx, "UE-initiated HR release retransmitted after a failed release, answering again", "interface", "Nsmf",
				"direction", "OUT", "result", prevResult, "spec_ref", "TS 23.502 §4.3.4.3 step 5")
			metrics.ProcedureTotal.WithLabelValues("SMF", hrProcedure+"UeRelease", hrResultRetxAfterFailure).Inc()
		} else {
			log.InfoContext(ctx, "UE-initiated HR release already performed, answering again", "interface", "Nsmf",
				"direction", "OUT", "result", prevResult, "spec_ref", "TS 23.502 §4.3.4.3 step 5")
		}
	default:
		deferred = s.runVSMFUERelease(ctx, log, sess, hRef, pti, n4Stale)
	}

	cmd := nas.WrapPDUSessionReleaseCommandBody(sess.PDUSessionID, pti, nas.Cause5GSMRegularDeactivation)
	w.Header().Set("Content-Type", mediaTypeJSON)
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]string{"n1SmMsg": base64.StdEncoding.EncodeToString(cmd)}); err != nil {
		log.WarnContext(ctx, "release command response not written", "interface", "Nsmf", "direction", "OUT",
			"result", "FAILURE", "error", err, "spec_ref", "TS 29.502 §5.2.2.8.3.3")
	}
	if deferred { // the DeleteSMContext that arrived meanwhile: finish its legs only now (AMF already answered)
		s.finishDeferredHomeRelease(ctx, sess, n4Stale)
	}
	return true
}

// hrResultRetxAfterFailure is the ProcedureTotal result label of a 0xD1 retransmission answered from
// the cached result of a failed release.
const hrResultRetxAfterFailure = "RETX_AFTER_FAILURE"

// runVSMFUERelease performs the three legs of a UE-initiated HR release under one hrUEReleaseBudget
// deadline (each leg capped by its own hrUEReleaseN4Leg / hrUEReleaseN16Leg) and records the per-leg
// outcome on the session: HomeN16Done / VUPFDeleted are set only on real success. A DeleteSMContext that
// arrived meanwhile (DeleteDeferred) is reported through the return value: the caller finishes the
// missing legs after the Release Command is written (finishDeferredHomeRelease), so the AMF is not kept
// waiting. A panic in a leg still clears UEReleaseInProgress (deferred) so the session is not stuck.
// Ref: TS 23.502 §4.3.4.3 steps 1a-5.
func (s *Server) runVSMFUERelease(ctx context.Context, log *slog.Logger, sess *Session, hRef string, pti uint8, n4Stale bool) (deferred bool) {
	completed := false
	defer func() {
		if !completed { // a leg panicked: never leave the in-progress flag set (the panic keeps propagating)
			s.sessionMu.Lock()
			sess.HR.UEReleaseInProgress = false
			sess.HR.DeleteDeferred = false
			s.sessionMu.Unlock()
		}
	}()
	ctx, cancel := detachedTimeout(ctx, hrUEReleaseBudget)
	defer cancel()
	leg := func(d time.Duration) (context.Context, context.CancelFunc) { return context.WithTimeout(ctx, d) }

	if !n4Stale {
		c, done := leg(hrUEReleaseN4Leg)
		_ = s.vsmfDropULFAR(c, log, sess) // WARN logged, release continues
		done()
	}
	n16OK := hRef == ""
	if hRef != "" {
		c, done := leg(hrUEReleaseN16Leg)
		n16OK = s.vsmfN16UpdateRelease(c, log, hRef, pti) // hsmf_update_failed logged on failure
		done()
	}
	n4OK := n4Stale
	if !n4Stale {
		c, done := leg(hrUEReleaseN4Leg)
		n4OK = s.vsmfDeleteN4(c, log, sess) == nil
		done()
	}
	result := "OK"
	if !n16OK || !n4OK {
		result = "FAILURE" // residual H-SMF orphan / V-UPF session until DELETE retries; the UE is released regardless
	}
	s.sessionMu.Lock()
	sess.HR.HomeN16Done = sess.HR.HomeN16Done || n16OK
	sess.HR.VUPFDeleted = sess.HR.VUPFDeleted || n4OK
	if hRef != "" && !n16OK {
		sess.HR.N16UpdateUnknown = true // the Update may have been applied by the H-SMF (answer lost)
	}
	sess.HR.UEReleaseInProgress = false
	sess.HR.UEReleaseDone = true
	sess.HR.UEReleaseResult = result
	deferred = sess.HR.DeleteDeferred
	sess.HR.DeleteDeferred = false
	completed = true
	s.sessionMu.Unlock()

	metrics.ProcedureTotal.WithLabelValues("SMF", hrProcedure+"UeRelease", result).Inc()
	lvl := slog.LevelInfo
	if result != "OK" {
		lvl = slog.LevelWarn
	}
	log.Log(ctx, lvl, "home-routed PDU session released on UE request (V-SMF), PDU SESSION RELEASE COMMAND returned",
		"interface", "Nsmf", "direction", "OUT", "result", result, "seid", sess.SEID, "pti", pti,
		"n16_done", n16OK, "vupf_deleted", n4OK,
		"cause_5gsm", nas.Cause5GSMRegularDeactivation, "spec_ref", "TS 23.502 §4.3.4.3 steps 4-5")
	return deferred
}

// hrDeferredCleanupBudget bounds the detached finishing of a DeleteSMContext that arrived during a
// UE-initiated release (it runs after the Release Command was written). Implementation guard.
const hrDeferredCleanupBudget = 10 * time.Second

// finishDeferredHomeRelease runs vsmfReleaseHome for the legs a deferred DeleteSMContext still needs, on
// a goroutine tracked by hrWG (waited for at shutdown) under its own hrDeferredCleanupBudget deadline.
func (s *Server) finishDeferredHomeRelease(ctx context.Context, sess *Session, n4Stale bool) {
	bg := context.WithoutCancel(ctx)
	s.hrWG.Add(1)
	go func() {
		defer s.hrWG.Done()
		c, cancel := context.WithTimeout(bg, hrDeferredCleanupBudget)
		defer cancel()
		s.vsmfReleaseHome(c, sess, n4Stale)
	}()
}

// WaitHRCleanup blocks until every deferred home-routed release cleanup goroutine has finished.
func (s *Server) WaitHRCleanup() { s.hrWG.Wait() }
