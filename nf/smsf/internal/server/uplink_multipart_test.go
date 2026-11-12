package server_test

// uplink_multipart_test.go - UplinkSMS request shapes (REL19-3.5 slice C): the
// SMSF accepts both the legacy JSON body and the spec-literal multipart/related
// (JSON root part + application/vnd.3gpp.sms part), whatever its profile.
// Ref: TS 29.540 §5.2.4, §6.1.6.2.3; TS 29.500 §5.4, §5.2.7.2

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/francurieses/claudia-5gc/shared/sbi"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

func uplinkMultipart(t *testing.T, root string, parts ...sbi.RelatedPart) (string, []byte) {
	t.Helper()
	return uplinkMultipartCT(t, "application/json", root, parts...)
}

func uplinkMultipartCT(t *testing.T, rootCT, root string, parts ...sbi.RelatedPart) (string, []byte) {
	t.Helper()
	all := append([]sbi.RelatedPart{{ContentType: rootCT, Body: []byte(root)}}, parts...)
	ct, body, err := sbi.EncodeRelated("TESTBOUNDARY", all)
	if err != nil {
		t.Fatal(err)
	}
	return ct, body
}

func TestUplinkSMS_RequestShapes(t *testing.T) {
	bin := []byte{1, 2, 3, 4} // base64 AQIDBA==, hex 01020304
	okRoot := `{"smsRecordId":"rec-1","smsPayload":{"contentId":"sms1"}}`
	smsPart := sbi.RelatedPart{ContentType: "application/vnd.3gpp.sms", ContentID: "sms1", Body: bin}

	type tc struct {
		name      string
		ct        string
		body      []byte
		wantCode  int
		wantMT    bool
		cause     string
		wantParam string
	}
	var cases []tc
	jb, err := json.Marshal(map[string]string{"smsPayload": "AQIDBA==", "smsRecordId": "rec-1"})
	if err != nil {
		t.Fatal(err)
	}
	cases = append(cases, tc{name: "legacy json", ct: "application/json", body: jb, wantCode: http.StatusOK, wantMT: true})
	ct, b := uplinkMultipart(t, okRoot, smsPart)
	cases = append(cases, tc{name: "multipart", ct: ct, body: b, wantCode: http.StatusOK, wantMT: true})
	// start parameter (RFC 2387 §3.2): the root is the second part.
	ct2, b2, err := sbi.EncodeRelated("TESTBOUNDARY", []sbi.RelatedPart{
		{ContentType: "application/octet-stream", ContentID: "decoy", Body: []byte("x")},
		{ContentType: "application/json", ContentID: "root", Body: []byte(okRoot)},
		smsPart,
	})
	if err != nil {
		t.Fatal(err)
	}
	cases = append(cases, tc{name: "multipart start param", ct: ct2 + `; start="<root>"`, body: b2, wantCode: http.StatusOK, wantMT: true})
	cases = append(cases, tc{name: "multipart start param not found", ct: ct2 + `; start="<nope>"`, body: b2,
		wantCode: http.StatusBadRequest, cause: "INVALID_MSG_FORMAT"})
	cases = append(cases, tc{name: "multipart without start takes first part (decoy)", ct: ct2, body: b2,
		wantCode: http.StatusBadRequest, cause: "INVALID_MSG_FORMAT"})

	ct, b = uplinkMultipart(t, okRoot, sbi.RelatedPart{ContentType: "application/vnd.3gpp.sms", ContentID: "other", Body: bin})
	cases = append(cases, tc{name: "multipart unmatched contentId", ct: ct, body: b, wantCode: http.StatusBadRequest,
		cause: "MANDATORY_IE_INCORRECT", wantParam: "/smsPayload/contentId"})
	ct, b = uplinkMultipart(t, okRoot)
	cases = append(cases, tc{name: "multipart no binary part", ct: ct, body: b, wantCode: http.StatusBadRequest,
		cause: "MANDATORY_IE_INCORRECT", wantParam: "/smsPayload/contentId"})
	ct, b = uplinkMultipart(t, okRoot, sbi.RelatedPart{ContentType: "application/vnd.3gpp.sms", ContentID: "sms1"})
	cases = append(cases, tc{name: "multipart empty binary part", ct: ct, body: b, wantCode: http.StatusBadRequest,
		cause: "MANDATORY_IE_INCORRECT", wantParam: "/smsPayload/contentId"})
	ct, b = uplinkMultipart(t, `{"smsRecordId":"rec-1","smsPayload":{"contentId":""}}`, smsPart)
	cases = append(cases, tc{name: "multipart empty contentId", ct: ct, body: b, wantCode: http.StatusBadRequest,
		cause: "MANDATORY_IE_MISSING", wantParam: "/smsPayload/contentId"})
	ct, b = uplinkMultipart(t, `{"smsRecordId":"rec-1"}`, smsPart)
	cases = append(cases, tc{name: "multipart absent smsPayload", ct: ct, body: b, wantCode: http.StatusBadRequest,
		cause: "MANDATORY_IE_MISSING", wantParam: "/smsPayload/contentId"})
	ct, b = uplinkMultipart(t, `{"smsRecordId":"rec-1","smsPayload":"AQIDBA=="}`, smsPart)
	cases = append(cases, tc{name: "multipart legacy string payload", ct: ct, body: b, wantCode: http.StatusBadRequest, cause: "INVALID_MSG_FORMAT"})
	ct, b = uplinkMultipart(t, `{not json`, smsPart)
	cases = append(cases, tc{name: "multipart bad JSON root", ct: ct, body: b, wantCode: http.StatusBadRequest, cause: "INVALID_MSG_FORMAT"})
	ct, b = uplinkMultipartCT(t, "text/plain", okRoot, smsPart)
	cases = append(cases, tc{name: "multipart non-JSON root", ct: ct, body: b, wantCode: http.StatusBadRequest, cause: "INVALID_MSG_FORMAT"})
	cases = append(cases, tc{name: "multipart garbage", ct: "multipart/related; boundary=X", body: []byte("not multipart"),
		wantCode: http.StatusBadRequest, cause: "INVALID_MSG_FORMAT"})
	cases = append(cases, tc{name: "multipart without boundary", ct: "multipart/related", body: b,
		wantCode: http.StatusBadRequest, cause: "INVALID_MSG_FORMAT"})

	// 413: body over features.MaxRequestBodyBytes, multipart and JSON.
	big := bytes.Repeat([]byte{'A'}, features.MaxRequestBodyBytes+1)
	ct, b = uplinkMultipart(t, okRoot, sbi.RelatedPart{ContentType: "application/vnd.3gpp.sms", ContentID: "sms1", Body: big})
	cases = append(cases, tc{name: "multipart too large", ct: ct, body: b, wantCode: http.StatusRequestEntityTooLarge})
	bigJSON, err := json.Marshal(map[string]string{"smsPayload": string(big), "smsRecordId": "rec-1"})
	if err != nil {
		t.Fatal(err)
	}
	cases = append(cases, tc{name: "json too large", ct: "application/json", body: bigJSON, wantCode: http.StatusRequestEntityTooLarge})

	for _, prof := range []string{"rel17", "rel19"} {
		for _, c := range cases {
			t.Run(prof+"/"+c.name, func(t *testing.T) {
				mock := newMockAMF(t)
				ts, srv := newTestServer(t, mock)
				srv.SetProfile(profileNamed(t, prof))
				supi := "imsi-001010000000001"
				cb := mock.srv.URL + "/namf-comm/v1/ue-contexts/" + supi + "/n1-n2-messages"
				ar := putJSON(t, ts.Client(), ts.URL+"/nsmsf-sms/v2/ue-contexts/"+supi,
					activateBody(supi, "3GPP_ACCESS", "amf-001", cb))
				ar.Body.Close()
				assertStatus(t, ar, http.StatusCreated)

				req, err := http.NewRequest(http.MethodPost, ts.URL+"/nsmsf-sms/v2/ue-contexts/"+supi+"/sendsms", bytes.NewReader(c.body))
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Content-Type", c.ct)
				resp, err := ts.Client().Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				assertStatus(t, resp, c.wantCode)
				if c.cause != "" || c.wantParam != "" {
					prob := parseProblem(t, resp)
					if c.cause != "" && prob["cause"] != c.cause {
						t.Errorf("cause = %v, want %s", prob["cause"], c.cause)
					}
					if c.wantParam != "" {
						ip, _ := prob["invalidParams"].([]any)
						if len(ip) != 1 {
							t.Fatalf("invalidParams = %v, want one entry", prob["invalidParams"])
						}
						if got := ip[0].(map[string]any)["param"]; got != c.wantParam {
							t.Errorf("invalidParams[0].param = %v, want %s", got, c.wantParam)
						}
					}
				}
				if c.wantCode == http.StatusRequestEntityTooLarge {
					if cause, ok := parseProblem(t, resp)["cause"]; ok && cause != nil {
						t.Errorf("413 carries cause %v, want none", cause)
					}
				}
				if c.wantMT {
					if !mock.waitForCall(2 * time.Second) {
						t.Fatal("no MT echo")
					}
					// The mock AMF client hex-encodes the payload: 01020304 is
					// exactly the decoded base64 AQIDBA== (stored/echoed bytes).
					if got := mock.callsReceived()[0].Body["smsPayload"]; got != "01020304" {
						t.Errorf("MT echo smsPayload = %v, want exactly 01020304", got)
					}
				} else {
					time.Sleep(50 * time.Millisecond)
					if n := len(mock.callsReceived()); n != 0 {
						t.Errorf("rejected request produced %d MT echo(es)", n)
					}
				}
			})
		}
	}
}
