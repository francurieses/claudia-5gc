package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// suciUDM records the identifier forwarded to the UDM and optionally fails.
type suciUDM struct {
	fixedUDM
	calls int
	gotID string
	err   error
}

func (m *suciUDM) GenerateAuthData(ctx context.Context, id string, req *UDMAuthDataRequest) (*UDMAuthDataResponse, error) {
	m.calls++
	m.gotID = id
	if m.err != nil {
		return nil, m.err
	}
	return m.fixedUDM.GenerateAuthData(ctx, id, req)
}

func postInitAuth(t *testing.T, srv *Server, id string) (int, string) {
	t.Helper()
	body := `{"supiOrSuci":"` + id + `","servingNetworkName":"5G:mnc001.mcc001.3gppnetwork.org"}`
	r := httptest.NewRequest(http.MethodPost, "/nausf-auth/v1/ue-authentications", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	raw, _ := io.ReadAll(w.Result().Body)
	return w.Code, string(raw)
}

// TestInitAuth_SUCIForms: standard SUCI strings (TS 29.571 §5.3.2) are
// forwarded verbatim to the UDM; the old private form and malformed ones
// are rejected 400 MANDATORY_IE_INCORRECT without calling the UDM.
func TestInitAuth_SUCIForms(t *testing.T) {
	eph := strings.Repeat("ab", 32)
	body := strings.Repeat("cd", 20)
	tests := []struct {
		name, id string
		want     int
	}{
		{"null", "suci-0-001-01-0000-0-0-0000000001", http.StatusCreated},
		{"profile A", "suci-0-001-01-0-1-1-" + eph + body, http.StatusCreated},
		{"profile B", "suci-0-001-01-0-2-2-" + "02" + eph + body, http.StatusCreated},
		{"supi passthrough", "imsi-001010000000001", http.StatusCreated},
		{"old private format", "suci-00101-0000-0-0-0000000001", http.StatusBadRequest},
		{"truncated", "suci-0-001-01", http.StatusBadRequest},
		{"bad scheme output", "suci-0-001-01-0-1-1-zz", http.StatusBadRequest},
		{"oversized", "suci-0-001-01-0-1-1-" + strings.Repeat("ab", 3000), http.StatusBadRequest},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			udm := &suciUDM{}
			code, resp := postInitAuth(t, newGoldenAuthServer(t, udm), tc.id)
			if code != tc.want {
				t.Fatalf("status = %d, want %d (%s)", code, tc.want, resp)
			}
			if tc.want == http.StatusCreated {
				if udm.calls != 1 || udm.gotID != tc.id {
					t.Fatalf("udm calls=%d id=%q, want 1 verbatim %q", udm.calls, udm.gotID, tc.id)
				}
				return
			}
			if udm.calls != 0 {
				t.Fatalf("UDM called %d times for a malformed SUCI", udm.calls)
			}
			if !strings.Contains(resp, "MANDATORY_IE_INCORRECT") || !strings.Contains(resp, "/supiOrSuci") {
				t.Fatalf("body = %s", resp)
			}
			if strings.Contains(resp, tc.id) || strings.Contains(resp, "0000000001") {
				t.Fatalf("body leaks the SUCI: %s", resp)
			}
		})
	}
}

// TestInitAuth_UDMErrorMapping: 400/403/404/501 UDM answers are propagated
// with their cause; other failures stay 500 NF_FAILURE (TS 29.509 §6.1.7.3).
func TestInitAuth_UDMErrorMapping(t *testing.T) {
	const id = "suci-0-001-01-0000-0-0-0000000001"
	tests := []struct {
		name   string
		err    error
		status int
		cause  string
	}{
		{"403 invalid key id", &UDMError{Status: 403, Cause: "INVALID_HN_PUBLIC_KEY_IDENTIFIER"}, 403, "INVALID_HN_PUBLIC_KEY_IDENTIFIER"},
		{"403 invalid output", &UDMError{Status: 403, Cause: "INVALID_SCHEME_OUTPUT"}, 403, "INVALID_SCHEME_OUTPUT"},
		{"501 scheme", &UDMError{Status: 501, Cause: "UNSUPPORTED_PROTECTION_SCHEME"}, 501, "UNSUPPORTED_PROTECTION_SCHEME"},
		{"404", &UDMError{Status: 404, Cause: "USER_NOT_FOUND"}, 404, "USER_NOT_FOUND"},
		{"400", &UDMError{Status: 400, Cause: "MANDATORY_IE_INCORRECT"}, 400, "MANDATORY_IE_INCORRECT"},
		{"503", &UDMError{Status: 503, Cause: "X"}, 500, "NF_FAILURE"},
		{"transport", io.ErrUnexpectedEOF, 500, "NF_FAILURE"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, resp := postInitAuth(t, newGoldenAuthServer(t, &suciUDM{err: tc.err}), id)
			if code != tc.status || !strings.Contains(resp, `"`+tc.cause+`"`) {
				t.Fatalf("got %d %s, want %d %s", code, resp, tc.status, tc.cause)
			}
		})
	}
}

// TestInitAuth_UDM400RelaysInvalidParams: the UDM's invalidParams travel
// through UDMError; a 400 without them gets the supiOrSuci default (TS 29.500
// Table 5.2.7.2-1 NOTE 1); non-400 answers carry none.
func TestInitAuth_UDM400RelaysInvalidParams(t *testing.T) {
	const id = "suci-0-001-01-0000-0-0-0000000001"
	tests := []struct {
		name   string
		err    *UDMError
		status int
		param  string
	}{
		{"relayed", &UDMError{Status: 400, Cause: "MANDATORY_IE_INCORRECT", InvalidParams: []map[string]string{{"param": "supiOrSuci"}}}, 400, "supiOrSuci"},
		{"default", &UDMError{Status: 400, Cause: "MANDATORY_IE_INCORRECT"}, 400, "supiOrSuci"},
		{"403 none", &UDMError{Status: 403, Cause: "INVALID_SCHEME_OUTPUT"}, 403, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, resp := postInitAuth(t, newGoldenAuthServer(t, &suciUDM{err: tc.err}), id)
			if code != tc.status {
				t.Fatalf("status = %d: %s", code, resp)
			}
			if has := strings.Contains(resp, `"param":"`+tc.param+`"`); tc.param != "" && !has {
				t.Fatalf("no invalidParams %q: %s", tc.param, resp)
			}
			if tc.param == "" && strings.Contains(resp, "invalidParams") {
				t.Fatalf("unexpected invalidParams: %s", resp)
			}
		})
	}
}
