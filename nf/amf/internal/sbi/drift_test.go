package sbi

// drift_test.go - drift-amf regression tests: the Namf producer types and
// operations against TS29518_Namf_Communication.yaml / TS29518_Namf_Location.yaml
// (Rel-17 and Rel-19) and TS 29.518 / TS 29.500. rel19 is spec-literal; rel17
// (and no profile) stays the frozen legacy wire (decision D1), which the
// golden_*_test.go files pin byte for byte.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/ngap"
	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/nas"
	sharedsbi "github.com/francurieses/claudia-5gc/shared/sbi"
)

const driftSUPI = "imsi-001010000000001"

// driftProfiles are the three wire profiles: no profile and rel17 are the
// frozen baseline, rel19 is spec-literal.
func driftProfiles(t *testing.T) map[string]*capability.Profile {
	t.Helper()
	return map[string]*capability.Profile{"none": nil, "rel17": profileNamed(t, "rel17"), "rel19": profileNamed(t, "rel19")}
}

// driftServer is a server under profile p with one registered UE.
func driftServer(t *testing.T, p *capability.Profile) (*Server, *amfctx.UEContext) {
	t.Helper()
	srv, mgr := newTestServer(t)
	if p != nil {
		srv.SetProfile(p)
	}
	return srv, seedRegisteredUE(mgr, driftSUPI)
}

// send posts body with content type ct (none when ct is "") to path.
func send(t *testing.T, srv *Server, path, ct string, body []byte) (*http.Response, []byte) {
	t.Helper()
	ts := httptest.NewServer(srv.httpSrv.Handler)
	defer ts.Close()
	req, _ := http.NewRequest(http.MethodPost, ts.URL+path, bytes.NewReader(body))
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	return resp, buf.Bytes()
}

// serveCtx runs one request through the handler with ctx (deterministic
// timeouts: the handler sees the deadline, the recorder keeps the answer).
func serveCtx(ctx context.Context, srv *Server, path string, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body)).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.httpSrv.Handler.ServeHTTP(rec, req)
	return rec
}

func problemOf(t *testing.T, raw []byte) ProblemDetails {
	t.Helper()
	var pd ProblemDetails
	if err := json.Unmarshal(raw, &pd); err != nil {
		t.Fatalf("not a ProblemDetails: %v (%s)", err, raw)
	}
	return pd
}

const (
	transferPath = "/namf-comm/v1/ue-contexts/" + driftSUPI + "/transfer"
	n1n2Path     = "/namf-comm/v1/ue-contexts/" + driftSUPI + "/n1-n2-messages"
	locPath      = "/namf-loc/v1/ue-contexts/" + driftSUPI + "/provide-loc-info"
)

// Rel-19-shaped request bodies: every Rel-19 attribute the AMF does not model,
// plus members unknown to any release, must be tolerated (TS 29.500 §5.2.7.2,
// §6.6.2). The minimal bodies carry only the mandatory attributes.
const (
	transferRel19Body = `{"reason":"MOBI_REG","accessType":"3GPP_ACCESS",` +
		`"plmnId":{"mcc":"001","mnc":"01","nid":"0123456789a"},` +
		`"regRequest":{"n1MessageClass":"5GMM","n1MessageContent":{"contentId":"n1msg"},"nfId":"0f3c2a6e-8a1b-4c11-9d0e-5a2b7c9d1e44","serviceInstanceId":"s1"},` +
		`"supportedFeatures":"0","rel20Ext":{"x":[1,2]}}`
	transferMinimalBody = `{"reason":"MOBI_REG","accessType":"3GPP_ACCESS"}`
	n1n2Rel19Body       = `{"n1MessageContainer":{"n1MessageClass":"SM","n1MessageContent":{"contentId":"n1"}},` +
		`"n2InfoContainer":{"n2InformationClass":"SM","smInfo":{"pduSessionId":1,"n2InfoContent":{"ngapIeType":"PDU_RES_SETUP_REQ","ngapData":{"contentId":"n2"}}}},` +
		`"pduSessionId":1,"ppi":3,"arp":{"priorityLevel":8,"preemptCap":"NOT_PREEMPT","preemptVuln":"NOT_PREEMPTABLE"},` +
		`"5qi":9,"pduSessionPrio":1,"pruInd":true,"servingLMFIdentification":"lmf-1","targetAccess":"3GPP_ACCESS","rel20Ext":true}`
	n1n2MinimalBody = `{}`
	locRel19Body    = `{"req5gsLoc":true,"reqCurrentLoc":true,"reqRatType":true,"reqTimeZone":true,` +
		`"supportedFeatures":"0","oldGuami":{"plmnId":{"mcc":"001","mnc":"01"},"amfId":"cafe00"},"rel20Ext":"x"}`
	locMinimalBody = `{"req5gsLoc":true}`
)

func okLocator() *fakeLocator {
	return &fakeLocator{result: ngap.LocationResult{NRCellID: "000000042", TAI: &ngap.TAI{MCC: "001", MNC: "01", TAC: 1}}}
}

// TestDrift_RequestPayloads: Rel-19-shaped payloads with unknown members and
// minimal mandatory-only payloads are accepted under every profile.
func TestDrift_RequestPayloads(t *testing.T) {
	tests := []struct {
		name, path, body string
		idle             bool
		want             int
	}{
		{"UEContextTransfer rel19-shaped", transferPath, transferRel19Body, false, http.StatusOK},
		{"UEContextTransfer minimal", transferPath, transferMinimalBody, false, http.StatusOK},
		{"N1N2MessageTransfer rel19-shaped CM-IDLE", n1n2Path, n1n2Rel19Body, true, http.StatusAccepted},
		{"N1N2MessageTransfer minimal CM-CONNECTED", n1n2Path, n1n2MinimalBody, false, http.StatusOK},
		{"ProvideLocationInfo rel19-shaped", locPath, locRel19Body, false, http.StatusOK},
		{"ProvideLocationInfo minimal", locPath, locMinimalBody, false, http.StatusOK},
	}
	for prof, p := range driftProfiles(t) {
		for _, tc := range tests {
			t.Run(prof+"/"+tc.name, func(t *testing.T) {
				srv, ue := driftServer(t, p)
				srv.SetPager(&fakePager{})
				srv.SetLocator(okLocator())
				ue.CMState = amfctx.CMConnected
				if tc.idle {
					ue.CMState = amfctx.CMIdle
				}
				resp, raw := send(t, srv, tc.path, mediaTypeJSON, []byte(tc.body))
				if resp.StatusCode != tc.want {
					t.Fatalf("status = %d, want %d: %s", resp.StatusCode, tc.want, raw)
				}
			})
		}
	}
}

// TestDrift_PlmnIdNid: plmnId is PlmnIdNid since Rel-18; nid is kept, a
// Rel-17 PlmnId decodes unchanged. Ref: TS 29.518 Table 6.1.6.2.23-1.
func TestDrift_PlmnIdNid(t *testing.T) {
	var r19, r17 UeContextTransferReqData
	if err := json.Unmarshal([]byte(transferRel19Body), &r19); err != nil {
		t.Fatal(err)
	}
	if r19.PlmnID == nil || r19.PlmnID.Nid != "0123456789a" || r19.PlmnID.MCC != "001" {
		t.Errorf("rel19 plmnId = %+v", r19.PlmnID)
	}
	if err := json.Unmarshal([]byte(`{"reason":"INIT_REG","accessType":"3GPP_ACCESS","plmnId":{"mcc":"001","mnc":"01"}}`), &r17); err != nil {
		t.Fatal(err)
	}
	if r17.PlmnID == nil || r17.PlmnID.MNC != "01" || r17.PlmnID.Nid != "" {
		t.Errorf("rel17 plmnId = %+v", r17.PlmnID)
	}
}

// seedDriftUE adds the values the rel19 transfer rules act on: a zero NAS
// downlink count, the raw UE security capability and 5GMM capability, a UE
// policy association and a second PDU session without an SM context ref.
func seedDriftUE(ue *amfctx.UEContext) {
	ue.SecurityCtx.DownlinkCount = 0
	ue.RawUESecCap = []byte{0xF0, 0xF0}
	ue.Capability5GMM = &nas.FiveGMMCapability{Raw: []byte{0x07}}
	ue.PolicyAssociationID = "polasso-1"
	ue.PDUSessions[2] = &amfctx.PDUSession{PDUSessionID: 2, DNN: "ims", SNSSAI: amfctx.SNSSAISubscribed{SST: 1}}
}

func transfer(t *testing.T, p *capability.Profile, reason string) map[string]any {
	t.Helper()
	srv, ue := driftServer(t, p)
	seedDriftUE(ue)
	body, _ := json.Marshal(UeContextTransferReqData{Reason: reason, AccessType: AccessType3GPP})
	resp, raw := send(t, srv, transferPath, mediaTypeJSON, body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d: %s", resp.StatusCode, raw)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m["ueContext"].(map[string]any)
}

func b64(b ...byte) string { return base64.StdEncoding.EncodeToString(b) }

// TestDrift_TransferRel19Shape pins the TS 29.518 rules the rel19 answer
// follows (Table 6.1.6.2.25-1 / -34-1 / -37-1, §6.1.6.3.2, §5.2.2.2.1) and that
// rel17 keeps every legacy value.
func TestDrift_TransferRel19Shape(t *testing.T) {
	uc := transfer(t, profileNamed(t, "rel19"), ReasonMobiReg)
	if v, ok := uc["supiUnauthInd"].(bool); !ok || v {
		t.Errorf("supiUnauthInd = %v (present %v), want false present with the SUPI", uc["supiUnauthInd"], ok)
	}
	if got := uc["5gMmCapability"]; got != b64(0x10, 0x01, 0x07) {
		t.Errorf("5gMmCapability = %v, want IE from octet 1 %s", got, b64(0x10, 0x01, 0x07))
	}
	if _, ok := uc["pcfId"]; ok {
		t.Errorf("pcfId must not carry the policy association id: %v", uc["pcfId"])
	}
	mm := uc["mmContextList"].([]any)[0].(map[string]any)
	if v, ok := mm["nasDownlinkCount"].(float64); !ok || v != 0 {
		t.Errorf("nasDownlinkCount = %v (present %v), want 0 present", mm["nasDownlinkCount"], ok)
	}
	if got := mm["ueSecurityCapability"]; got != b64(0x2E, 0x02, 0xF0, 0xF0) {
		t.Errorf("ueSecurityCapability = %v, want IE from octet 1 %s", got, b64(0x2E, 0x02, 0xF0, 0xF0))
	}
	if _, ok := uc["seafData"]; !ok {
		t.Error("MOBI_REG keeps seafData")
	}
	sessions := uc["sessionContextList"].([]any)
	if len(sessions) != 1 {
		t.Fatalf("sessionContextList = %v, want only the session with an SM context ref", sessions)
	}
	if s := sessions[0].(map[string]any); s["hsmfId"] != nil || s["smContextRef"] != "smf-ctx-ref-1" {
		t.Errorf("session = %v", s)
	}

	// INIT_REG: no PDU session contexts of the requested access type.
	if uc := transfer(t, profileNamed(t, "rel19"), ReasonInitReg); uc["sessionContextList"] != nil {
		t.Errorf("INIT_REG sessionContextList = %v, want absent", uc["sessionContextList"])
	}
	// MOBI_REG_UE_VALIDATED: no seafData, PDU session contexts kept.
	uc = transfer(t, profileNamed(t, "rel19"), ReasonMobiRegUEValidated)
	if _, ok := uc["seafData"]; ok || uc["sessionContextList"] == nil {
		t.Errorf("MOBI_REG_UE_VALIDATED: seafData %v, sessions %v", uc["seafData"], uc["sessionContextList"])
	}

	// rel17 / no profile: the frozen legacy values.
	for _, p := range []*capability.Profile{nil, profileNamed(t, "rel17")} {
		uc := transfer(t, p, ReasonInitReg)
		for _, absent := range []string{"supiUnauthInd", "5gMmCapability", "seafData"} {
			if _, ok := uc[absent]; ok {
				t.Errorf("legacy body carries %s", absent)
			}
		}
		if uc["pcfId"] != "polasso-1" {
			t.Errorf("legacy pcfId = %v", uc["pcfId"])
		}
		mm := uc["mmContextList"].([]any)[0].(map[string]any)
		if _, ok := mm["nasDownlinkCount"]; ok {
			t.Error("legacy body sends a zero nasDownlinkCount")
		}
		if mm["ueSecurityCapability"] != b64(0xF0, 0xF0) || mm["kamf"] == nil {
			t.Errorf("legacy mmContext = %v", mm)
		}
		if n := len(uc["sessionContextList"].([]any)); n != 2 {
			t.Errorf("legacy sessionContextList has %d entries, want 2 (INIT_REG not filtered)", n)
		}
	}
}

// TestDrift_TransferValidation: reason and accessType are mandatory (TS 29.518
// Table 6.1.6.2.23-1); rel19 names the IE in invalidParams (TS 29.500 Table
// 5.2.7.2-1 NOTE 1), rel17 keeps the frozen answers.
func TestDrift_TransferValidation(t *testing.T) {
	tests := []struct {
		name, body       string
		status19         int
		cause19, param19 string
		status17         int
		cause17          string
	}{
		{"missing reason", `{"accessType":"3GPP_ACCESS"}`, 400, CauseMandatoryIEMissing, paramReason, 400, CauseMandatoryIEMissing},
		{"missing accessType", `{"reason":"MOBI_REG"}`, 400, CauseMandatoryIEMissing, paramAccessType, 200, ""},
		{"accessType outside the enum", `{"reason":"MOBI_REG","accessType":"WLAN"}`, 400, CauseMandatoryIEIncorrect, paramAccessType, 200, ""},
		{"unknown reason is tolerated (extensible enum)", `{"reason":"FUTURE_REASON","accessType":"3GPP_ACCESS"}`, 200, "", "", 200, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := driftServer(t, profileNamed(t, "rel19"))
			resp, raw := send(t, srv, transferPath, mediaTypeJSON, []byte(tc.body))
			if resp.StatusCode != tc.status19 {
				t.Fatalf("rel19 status = %d, want %d: %s", resp.StatusCode, tc.status19, raw)
			}
			if tc.cause19 != "" {
				pd := problemOf(t, raw)
				if pd.Cause != tc.cause19 || len(pd.InvalidParams) != 1 || pd.InvalidParams[0].Param != tc.param19 {
					t.Errorf("rel19 problem = %+v", pd)
				}
			}
			srv17, _ := driftServer(t, profileNamed(t, "rel17"))
			resp, raw = send(t, srv17, transferPath, mediaTypeJSON, []byte(tc.body))
			if resp.StatusCode != tc.status17 {
				t.Fatalf("rel17 status = %d, want %d: %s", resp.StatusCode, tc.status17, raw)
			}
			if tc.cause17 != "" {
				if pd := problemOf(t, raw); pd.Cause != tc.cause17 || len(pd.InvalidParams) != 0 {
					t.Errorf("rel17 problem = %+v", pd)
				}
			}
		})
	}
}

// TestDrift_MalformedBody: an unparsable body is "invalid format" under rel19
// (INVALID_MSG_FORMAT, TS 29.500 Table 5.2.7.2-1), the frozen
// MANDATORY_IE_MISSING under rel17.
func TestDrift_MalformedBody(t *testing.T) {
	for _, path := range []string{transferPath, n1n2Path, locPath} {
		for prof, want := range map[string]string{"rel17": CauseMandatoryIEMissing, "rel19": CauseInvalidMsgFormat} {
			t.Run(prof+path, func(t *testing.T) {
				srv, _ := driftServer(t, profileNamed(t, prof))
				resp, raw := send(t, srv, path, mediaTypeJSON, []byte(`{"reason":`))
				if resp.StatusCode != http.StatusBadRequest {
					t.Fatalf("status = %d: %s", resp.StatusCode, raw)
				}
				if pd := problemOf(t, raw); pd.Cause != want {
					t.Errorf("cause = %q, want %q", pd.Cause, want)
				}
			})
		}
	}
}

func related(t *testing.T, root string) (string, []byte) {
	t.Helper()
	ct, body, err := sharedsbi.EncodeRelated("", []sharedsbi.RelatedPart{
		{ContentType: mediaTypeJSON, Body: []byte(root)},
		{ContentType: "application/vnd.3gpp.5gnas", ContentID: "n1msg", Body: []byte{0x7e, 0x00, 0x41}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return ct, body
}

// TestDrift_ContentTypes: under rel19 the request content types of the YAML
// apply - multipart/related (JSON root part) for UEContextTransfer and
// N1N2MessageTransfer, JSON only for ProvideLocationInfo, 415 otherwise
// (TS 29.500 §5.2.7.2). rel17 decodes JSON whatever the header (frozen).
func TestDrift_ContentTypes(t *testing.T) {
	type req struct {
		name, path, ct string
		body           []byte
	}
	mpTransferCT, mpTransfer := related(t, `{"reason":"MOBI_REG","accessType":"3GPP_ACCESS","regRequest":{"n1MessageClass":"5GMM","n1MessageContent":{"contentId":"n1msg"}}}`)
	mpN1N2CT, mpN1N2 := related(t, `{"n1MessageContainer":{"n1MessageClass":"SM","n1MessageContent":{"contentId":"n1msg"}},"pduSessionId":1}`)
	mpLocCT, mpLoc := related(t, locMinimalBody)
	tests := []struct {
		r          req
		want19     int
		want17     int
		wantCause7 string
	}{
		{req{"transfer multipart", transferPath, mpTransferCT, mpTransfer}, http.StatusOK, http.StatusBadRequest, CauseMandatoryIEMissing},
		{req{"n1n2 multipart", n1n2Path, mpN1N2CT, mpN1N2}, http.StatusOK, http.StatusBadRequest, CauseMandatoryIEMissing},
		{req{"provide-loc-info multipart", locPath, mpLocCT, mpLoc}, http.StatusUnsupportedMediaType, http.StatusBadRequest, CauseMandatoryIEMissing},
		{req{"transfer text/plain", transferPath, "text/plain", []byte(transferMinimalBody)}, http.StatusUnsupportedMediaType, http.StatusOK, ""},
		{req{"n1n2 text/plain", n1n2Path, "text/plain", []byte(n1n2MinimalBody)}, http.StatusUnsupportedMediaType, http.StatusOK, ""},
		{req{"provide-loc-info text/plain", locPath, "text/plain", []byte(locMinimalBody)}, http.StatusUnsupportedMediaType, http.StatusOK, ""},
		{req{"transfer without Content-Type", transferPath, "", []byte(transferMinimalBody)}, http.StatusOK, http.StatusOK, ""},
		{req{"transfer JSON with charset", transferPath, "application/json; charset=utf-8", []byte(transferMinimalBody)}, http.StatusOK, http.StatusOK, ""},
		{req{"multipart without JSON root", transferPath, "multipart/related; boundary=b", []byte("--b\r\nContent-Type: text/plain\r\n\r\nx\r\n--b--\r\n")}, http.StatusBadRequest, http.StatusBadRequest, CauseMandatoryIEMissing},
	}
	for _, tc := range tests {
		for prof, want := range map[string]int{"rel19": tc.want19, "rel17": tc.want17} {
			t.Run(prof+"/"+tc.r.name, func(t *testing.T) {
				srv, ue := driftServer(t, profileNamed(t, prof))
				ue.CMState = amfctx.CMConnected
				srv.SetLocator(okLocator())
				resp, raw := send(t, srv, tc.r.path, tc.r.ct, tc.r.body)
				if resp.StatusCode != want {
					t.Fatalf("status = %d, want %d: %s", resp.StatusCode, want, raw)
				}
				if prof == "rel19" && want == http.StatusUnsupportedMediaType {
					if pd := problemOf(t, raw); pd.Status != http.StatusUnsupportedMediaType || pd.Cause != "" {
						t.Errorf("415 problem = %+v", pd)
					}
				}
				if prof == "rel17" && tc.wantCause7 != "" {
					if pd := problemOf(t, raw); pd.Cause != tc.wantCause7 {
						t.Errorf("rel17 cause = %q, want %q", pd.Cause, tc.wantCause7)
					}
				}
			})
		}
	}
}

// TestDrift_N1N2AcceptedLocation: the 202 answer carries the mandatory Location
// of the n1N2Message resource under rel19 (TS 29.518 Table 6.1.3.5.3.1-3); the
// 200 answer and the rel17 202 carry none.
func TestDrift_N1N2AcceptedLocation(t *testing.T) {
	loc := regexp.MustCompile(`^http://127\.0\.0\.1:\d+/namf-comm/v1/ue-contexts/` + driftSUPI + `/n1-n2-messages/[0-9a-f-]{36}$`)
	for prof, p := range driftProfiles(t) {
		for _, idle := range []bool{true, false} {
			srv, ue := driftServer(t, p)
			srv.SetPager(&fakePager{})
			ue.CMState = amfctx.CMConnected
			if idle {
				ue.CMState = amfctx.CMIdle
			}
			resp, raw := send(t, srv, n1n2Path, mediaTypeJSON, []byte(`{"pduSessionId":1}`))
			got := resp.Header.Get("Location")
			switch {
			case idle && prof == "rel19":
				if resp.StatusCode != http.StatusAccepted || !loc.MatchString(got) {
					t.Errorf("%s 202 Location = %q (status %d: %s)", prof, got, resp.StatusCode, raw)
				}
			case got != "":
				t.Errorf("%s idle=%v: unexpected Location %q", prof, idle, got)
			}
		}
	}
}

type errPager struct{}

func (errPager) SendPaging(*amfctx.UEContext) error { return errors.New("no gNB connected") }

// TestDrift_ProvideLocCauses: rel19 failures use Namf_Location application
// errors (TS 29.518 Table 6.4.7.3-1) or common ones (TS 29.500 Table
// 5.2.7.2-1); rel17 keeps LOCATION_FAILURE / UE_NOT_REACHABLE (frozen).
func TestDrift_ProvideLocCauses(t *testing.T) {
	tests := []struct {
		name        string
		idle        bool
		pager       Pager
		locator     Locator
		timeout     bool
		status19    int
		cause19     string
		status17    int
		cause17     string
		deadlineCtx bool
	}{
		{"no pager for a CM-IDLE UE", true, nil, okLocator(), false, 500, CauseSystemFailure, 503, CauseLocationFailure, false},
		{"paging send failure", true, errPager{}, okLocator(), false, 504, CauseUnreachableUser, 504, CauseLocationFailure, false},
		{"paging timeout", true, &fakePager{}, okLocator(), true, 504, CauseUnreachableUser, 504, CauseUENotReachable, true},
		{"no locator", false, nil, nil, false, 500, CauseSystemFailure, 503, CauseLocationFailure, false},
		{"LocationReportingControl send failure", false, nil, &fakeLocator{sendErr: errors.New("no gNB for UE")}, false, 504, CauseUnreachableUser, 504, CauseLocationFailure, false},
		{"NG-RAN does not report", false, nil, &fakeLocator{noSend: true}, true, 504, CausePeerNotResponding, 504, CauseLocationFailure, true},
	}
	for _, tc := range tests {
		for _, prof := range []string{"rel19", "rel17"} {
			t.Run(prof+"/"+tc.name, func(t *testing.T) {
				srv, ue := driftServer(t, profileNamed(t, prof))
				ue.CMState = amfctx.CMConnected
				if tc.idle {
					ue.CMState = amfctx.CMIdle
				}
				if tc.pager != nil {
					srv.SetPager(tc.pager)
				}
				if tc.locator != nil {
					srv.SetLocator(tc.locator)
				}
				ctx := context.Background()
				if tc.deadlineCtx {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(ctx, 100*time.Millisecond)
					defer cancel()
				}
				rec := serveCtx(ctx, srv, locPath, []byte(locMinimalBody))
				status, cause := tc.status19, tc.cause19
				if prof == "rel17" {
					status, cause = tc.status17, tc.cause17
				}
				if rec.Code != status {
					t.Fatalf("status = %d, want %d: %s", rec.Code, status, rec.Body.Bytes())
				}
				if pd := problemOf(t, rec.Body.Bytes()); pd.Cause != cause {
					t.Errorf("cause = %q, want %q", pd.Cause, cause)
				}
			})
		}
	}
}

// TestDrift_ProvideLocWithoutLocation: req5gsLoc is conditional (TS 29.518
// Table 6.4.6.2.5-1). rel19 answers the requested NPLI without paging or NG-RAN
// signalling (ratType when requested, never currentLoc/locationAge); rel17
// keeps the frozen 400.
func TestDrift_ProvideLocWithoutLocation(t *testing.T) {
	for _, tc := range []struct{ body, want string }{
		{`{"reqRatType":true}`, `{"ratType":"NR"}`},
		{`{}`, `{}`},
		{`{"req5gsLoc":false,"reqTimeZone":true}`, `{}`},
	} {
		srv, ue := driftServer(t, profileNamed(t, "rel19"))
		ue.CMState = amfctx.CMIdle
		fp, fl := &fakePager{}, okLocator()
		srv.SetPager(fp)
		srv.SetLocator(fl)
		resp, raw := send(t, srv, locPath, mediaTypeJSON, []byte(tc.body))
		if resp.StatusCode != http.StatusOK || strings.TrimSpace(string(raw)) != tc.want {
			t.Errorf("%s: %d %s, want 200 %s", tc.body, resp.StatusCode, raw, tc.want)
		}
		if fp.paged != 0 || fl.called != 0 {
			t.Errorf("%s: paged %d, located %d, want neither", tc.body, fp.paged, fl.called)
		}
	}
	// Unknown UE: still 404.
	srv, _ := driftServer(t, profileNamed(t, "rel19"))
	resp, raw := send(t, srv, "/namf-loc/v1/ue-contexts/imsi-999999999999999/provide-loc-info", mediaTypeJSON, []byte(`{"reqRatType":true}`))
	if resp.StatusCode != http.StatusNotFound || problemOf(t, raw).Cause != "CONTEXT_NOT_FOUND" {
		t.Errorf("unknown UE: %d %s", resp.StatusCode, raw)
	}
	// rel17: frozen rejection.
	srv17, _ := driftServer(t, profileNamed(t, "rel17"))
	resp, raw = send(t, srv17, locPath, mediaTypeJSON, []byte(`{"reqRatType":true}`))
	if resp.StatusCode != http.StatusBadRequest || problemOf(t, raw).Cause != CauseMandatoryIEMissing {
		t.Errorf("rel17: %d %s", resp.StatusCode, raw)
	}
}
