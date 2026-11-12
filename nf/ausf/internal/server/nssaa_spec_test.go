package server

// nssaa_spec_test.go - TS 29.526 Nnssaaf_NSSAA resource served by the AUSF.
// Ref: TS 29.526 §5.2.2.2, §5.2.2.3

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/crypto/eap"
)

func profileSrv(t *testing.T, name string) *Server {
	t.Helper()
	srv := newGoldenAuthServer(t, &fixedUDM{})
	if name != "" {
		p, err := capability.NewProfile(capability.ReleaseConfig{Profile: name}, func(string) string { return "" })
		if err != nil {
			t.Fatal(err)
		}
		srv.SetProfile(p)
	}
	return srv
}

func doJSON(srv *Server, method, path, body string) *http.Response {
	r := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	return w.Result()
}

func createBody(identity string) string {
	return `{"gpsi":"msisdn-12025550100","snssai":{"sst":1,"sd":"000003"},"eapIdRsp":"` +
		base64.StdEncoding.EncodeToString(eap.BuildIdentityResponse(7, identity)) + `"}`
}

func decodeCtx(t *testing.T, resp *http.Response) (sliceAuthContext, []byte) {
	t.Helper()
	raw, _ := io.ReadAll(resp.Body)
	var c sliceAuthContext
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
	eapPkt, _ := base64.StdEncoding.DecodeString(c.EAPMessage)
	return c, eapPkt
}

func TestSliceAuthCreate_BothProfiles(t *testing.T) {
	for _, prof := range []string{"", "rel17", "rel19"} {
		t.Run("profile="+prof, func(t *testing.T) {
			srv := profileSrv(t, prof)
			resp := doJSON(srv, "POST", nssaaCtxPath, createBody("alice@nssaa.example.com"))
			if resp.StatusCode != http.StatusCreated {
				t.Fatalf("status %d", resp.StatusCode)
			}
			c, pkt := decodeCtx(t, resp)
			if code, _ := eap.Code(pkt); code != eap.CodeSuccess {
				t.Fatalf("EAP code %d, want Success", code)
			}
			if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "http://example.com"+nssaaCtxPath+"/") || !strings.HasSuffix(loc, c.AuthCtxID) {
				t.Fatalf("Location %q", loc)
			}
			if c.GPSI != "msisdn-12025550100" || c.SNSSAI.SST != 1 || c.SNSSAI.SD != "000003" {
				t.Fatalf("ctx %+v", c)
			}
			// legacy route still served
			if got := nssaaLegacySnapshot(t, srv, "alice@x"); !strings.Contains(got, "EAP_SUCCESS") {
				t.Fatalf("legacy: %s", got)
			}
		})
	}
}

// TS 29.526 §5.2.2.2.1 step 3b: an AAA-S reject in the first round is a 403
// SLICE_AUTH_REJECTED ProblemDetails and no context is stored.
func TestSliceAuthCreate_RejectIs403(t *testing.T) {
	for _, prof := range []string{"", "rel17", "rel19"} {
		srv := profileSrv(t, prof)
		resp := doJSON(srv, "POST", nssaaCtxPath, createBody("mallory@reject.example.com"))
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("profile %q status %d, want 403", prof, resp.StatusCode)
		}
		var p struct{ Cause string }
		_ = json.NewDecoder(resp.Body).Decode(&p)
		if p.Cause != causeSliceAuthRejected || resp.Header.Get("Location") != "" {
			t.Fatalf("cause %q location %q", p.Cause, resp.Header.Get("Location"))
		}
		if n := len(srv.nssaaStoreOrNew().m); n != 0 {
			t.Fatalf("%d contexts stored after a reject", n)
		}
	}
}

func TestSliceAuthCreate_NullEapIdRsp(t *testing.T) {
	srv := profileSrv(t, "rel19")
	body := `{"gpsi":"msisdn-12025550100","snssai":{"sst":1,"sd":"000003"},"eapIdRsp":null}`
	resp := doJSON(srv, "POST", nssaaCtxPath, body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status %d", resp.StatusCode)
	}
	c, pkt := decodeCtx(t, resp)
	if code, _ := eap.Code(pkt); code != eap.CodeRequest {
		t.Fatalf("EAP code %d, want Request/Identity", code)
	}
	if typ, _ := eap.Type(pkt); typ != eap.TypeIdentity {
		t.Fatalf("EAP type %d", typ)
	}
	// The UE's identity answer completes the exchange.
	put := `{"gpsi":"msisdn-12025550100","snssai":{"sst":1,"sd":"000003"},"eapMessage":"` +
		base64.StdEncoding.EncodeToString(eap.BuildIdentityResponse(pkt[1], "u@x")) + `"}`
	resp = doJSON(srv, "PUT", nssaaCtxPath+"/"+c.AuthCtxID, put)
	var out sliceAuthConfirmationResponse
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode != http.StatusOK || out.AuthResult != authResultSuccess {
		t.Fatalf("PUT status %d result %q", resp.StatusCode, out.AuthResult)
	}
	// An absent eapIdRsp stays a missing mandatory attribute.
	resp = doJSON(srv, "POST", nssaaCtxPath, `{"gpsi":"msisdn-1","snssai":{"sst":1}}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("absent eapIdRsp status %d", resp.StatusCode)
	}
}

func TestSliceAuthCreate_NonIdentityResponseIs400(t *testing.T) {
	pkt := []byte{eap.CodeResponse, 1, 0, 6, eapTypeMD5Challenge, 1}
	body := `{"gpsi":"msisdn-1","snssai":{"sst":1},"eapIdRsp":"` + base64.StdEncoding.EncodeToString(pkt) + `"}`
	resp := doJSON(profileSrv(t, "rel19"), "POST", nssaaCtxPath, body)
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(raw), "/eapIdRsp") {
		t.Fatalf("status %d body %s", resp.StatusCode, raw)
	}
	succ := base64.StdEncoding.EncodeToString(eap.BuildSuccess(1))
	body = `{"gpsi":"msisdn-1","snssai":{"sst":1},"eapIdRsp":"` + succ + `"}`
	if resp = doJSON(profileSrv(t, "rel19"), "POST", nssaaCtxPath, body); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("EAP-Success as eapIdRsp status %d", resp.StatusCode)
	}
}

func TestSliceAuthConfirm_MismatchKeepsContext(t *testing.T) {
	srv := profileSrv(t, "rel19")
	c, pkt := decodeCtx(t, doJSON(srv, "POST", nssaaCtxPath, createBody("bob@challenge.example.com")))
	path := nssaaCtxPath + "/" + c.AuthCtxID
	eapMsg := base64.StdEncoding.EncodeToString([]byte{eap.CodeResponse, pkt[1], 0, 6, eapTypeMD5Challenge, 1})
	for name, body := range map[string]string{
		"gpsi":   `{"gpsi":"msisdn-999","snssai":{"sst":1,"sd":"000003"},"eapMessage":"` + eapMsg + `"}`,
		"snssai": `{"gpsi":"msisdn-12025550100","snssai":{"sst":2,"sd":"000003"},"eapMessage":"` + eapMsg + `"}`,
	} {
		if resp := doJSON(srv, "PUT", path, body); resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("%s mismatch status %d, want 400", name, resp.StatusCode)
		}
	}
	// The context survived: the matching PUT still completes.
	if resp := doJSON(srv, "PUT", path, confirmBody(pkt[1], eap.CodeResponse)); resp.StatusCode != http.StatusOK {
		t.Fatalf("matching PUT status %d, want 200", resp.StatusCode)
	}
}

func TestSliceAuthConfirm_Oversize413(t *testing.T) {
	big := `{"gpsi":"` + strings.Repeat("a", 2<<20) + `"}`
	if resp := doJSON(profileSrv(t, ""), "PUT", nssaaCtxPath+"/x", big); resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("PUT oversize status %d", resp.StatusCode)
	}
}

func TestSliceAuthCreate_FixedBadBodyDetail(t *testing.T) {
	resp := doJSON(profileSrv(t, ""), "POST", nssaaCtxPath, `{"gpsi": SECRET-TOKEN`)
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadRequest || strings.Contains(string(raw), "SECRET") ||
		!strings.Contains(string(raw), nssaaBadBodyDetail) {
		t.Fatalf("status %d body %s", resp.StatusCode, raw)
	}
}

func TestSliceAuthCreate_LocationAuthority(t *testing.T) {
	cases := []struct {
		name, authority, sbiAddr, host, want string
	}{
		{"configured wins", "ausf.5gc.local:8002", "0.0.0.0:8002", "evil.example", "ausf.5gc.local:8002"},
		{"routable sbi address", "", "10.0.0.5:8002", "evil.example", "10.0.0.5:8002"},
		{"wildcard falls back to host", "", "0.0.0.0:8002", "example.com", "example.com"},
		{"invalid host dropped", "", "0.0.0.0:8002", "a b/c", ""},
		{"invalid configured ignored", "x/y", "0.0.0.0:8002", "example.com", "example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := profileSrv(t, "rel19")
			srv.cfg.SBIAuthority, srv.cfg.SBIAddress = tc.authority, tc.sbiAddr
			r := httptest.NewRequest("POST", nssaaCtxPath, bytes.NewBufferString(createBody("a@b")))
			r.Host = tc.host
			w := httptest.NewRecorder()
			srv.Handler().ServeHTTP(w, r)
			loc := w.Result().Header.Get("Location")
			want := nssaaCtxPath + "/"
			if tc.want != "" {
				want = "http://" + tc.want + want
			}
			if !strings.HasPrefix(loc, want) {
				t.Fatalf("Location %q, want prefix %q", loc, want)
			}
		})
	}
}

func TestNSSAAStore_ConcurrentPutTake(t *testing.T) {
	st := newNSSAAStore()
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				id := st.put(&nssaaCtx{gpsi: "g"})
				st.takeIfMatch(id, func(c *nssaaCtx) bool { return c.gpsi == "g" })
				if c, found, _ := st.takeIfMatch(id, func(*nssaaCtx) bool { return true }); found || c != nil {
					t.Error("context consumed twice")
				}
			}
		}()
	}
	wg.Wait()
}

func TestSliceAuthCreate_Validation(t *testing.T) {
	good := base64.StdEncoding.EncodeToString(eap.BuildIdentityResponse(1, "a"))
	cases := []struct {
		name, body string
		params     []string
	}{
		{"all missing", `{}`, []string{"/gpsi", "/snssai", "/eapIdRsp"}},
		{"no gpsi", `{"snssai":{"sst":1},"eapIdRsp":"` + good + `"}`, []string{"/gpsi"}},
		{"no snssai", `{"gpsi":"msisdn-1","eapIdRsp":"` + good + `"}`, []string{"/snssai"}},
		{"bad base64", `{"gpsi":"msisdn-1","snssai":{"sst":1},"eapIdRsp":"!!"}`, []string{"/eapIdRsp"}},
		{"bad eap len", `{"gpsi":"msisdn-1","snssai":{"sst":1},"eapIdRsp":"AgEABQ=="}`, []string{"/eapIdRsp"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := doJSON(profileSrv(t, "rel19"), "POST", nssaaCtxPath, tc.body)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status %d", resp.StatusCode)
			}
			var p struct {
				InvalidParams []struct{ Param string } `json:"invalidParams"`
			}
			raw, _ := io.ReadAll(resp.Body)
			if err := json.Unmarshal(raw, &p); err != nil || len(p.InvalidParams) != len(tc.params) {
				t.Fatalf("body %s", raw)
			}
			for i, w := range tc.params {
				if p.InvalidParams[i].Param != w {
					t.Fatalf("param[%d] = %s, want %s", i, p.InvalidParams[i].Param, w)
				}
			}
		})
	}
	if resp := doJSON(profileSrv(t, ""), "POST", nssaaCtxPath, `{bad`); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed JSON status %d", resp.StatusCode)
	}
	big := `{"gpsi":"` + strings.Repeat("a", 2<<20) + `"}`
	if resp := doJSON(profileSrv(t, ""), "POST", nssaaCtxPath, big); resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize status %d", resp.StatusCode)
	}
}

func confirmBody(id byte, code byte) string {
	pkt := []byte{code, id, 0, 6, eapTypeMD5Challenge, 0x01}
	return `{"gpsi":"msisdn-12025550100","snssai":{"sst":1,"sd":"000003"},"eapMessage":"` +
		base64.StdEncoding.EncodeToString(pkt) + `"}`
}

func TestSliceAuthConfirm_TwoRound(t *testing.T) {
	for _, prof := range []string{"rel17", "rel19"} {
		t.Run(prof, func(t *testing.T) {
			srv := profileSrv(t, prof)
			resp := doJSON(srv, "POST", nssaaCtxPath, createBody("bob@challenge.example.com"))
			c, pkt := decodeCtx(t, resp)
			if code, _ := eap.Code(pkt); code != eap.CodeRequest {
				t.Fatalf("round 1 EAP code %d, want Request", code)
			}
			path := nssaaCtxPath + "/" + c.AuthCtxID
			resp = doJSON(srv, "PUT", path, confirmBody(pkt[1], eap.CodeResponse))
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("PUT status %d", resp.StatusCode)
			}
			var out sliceAuthConfirmationResponse
			if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
				t.Fatal(err)
			}
			if out.AuthResult != authResultSuccess {
				t.Fatalf("authResult %q", out.AuthResult)
			}
			// terminal result deletes the context
			if resp = doJSON(srv, "PUT", path, confirmBody(pkt[1], eap.CodeResponse)); resp.StatusCode != http.StatusNotFound {
				t.Fatalf("second PUT status %d, want 404", resp.StatusCode)
			}
		})
	}
}

func TestSliceAuthConfirm_WrongIdentifierFails(t *testing.T) {
	srv := profileSrv(t, "rel19")
	c, pkt := decodeCtx(t, doJSON(srv, "POST", nssaaCtxPath, createBody("bob@challenge.example.com")))
	resp := doJSON(srv, "PUT", nssaaCtxPath+"/"+c.AuthCtxID, confirmBody(pkt[1]+1, eap.CodeResponse))
	var out sliceAuthConfirmationResponse
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode != http.StatusOK || out.AuthResult != authResultFailure {
		t.Fatalf("status %d result %q", resp.StatusCode, out.AuthResult)
	}
}

func TestSliceAuthConfirm_Errors(t *testing.T) {
	srv := profileSrv(t, "rel19")
	if resp := doJSON(srv, "PUT", nssaaCtxPath+"/unknown", confirmBody(1, eap.CodeResponse)); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown ctx status %d", resp.StatusCode)
	}
	if resp := doJSON(srv, "PUT", nssaaCtxPath+"/unknown", `{}`); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing attrs status %d", resp.StatusCode)
	}
}

func TestNSSAAStore_TTLAndBound(t *testing.T) {
	st := newNSSAAStore()
	now := time.Now()
	st.now = func() time.Time { return now }
	id := st.put(&nssaaCtx{})
	now = now.Add(nssaaCtxTTL + time.Second)
	if st.take(id) != nil {
		t.Fatal("expired context returned")
	}
	now = time.Now()
	for i := 0; i < nssaaMaxContexts+10; i++ {
		now = now.Add(time.Millisecond)
		st.put(&nssaaCtx{})
	}
	if len(st.m) > nssaaMaxContexts {
		t.Fatalf("store size %d exceeds bound", len(st.m))
	}
}
