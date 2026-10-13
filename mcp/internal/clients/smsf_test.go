package clients

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSMSFSendMT(t *testing.T) {
	var method, path, body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		method, path, body = r.Method, r.URL.Path, string(b)
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"cause":"CONTEXT_NOT_FOUND"}`))
	}))
	defer srv.Close()
	status, raw, err := NewSMSF(srv.URL+"/", srv.Client()).SendMT(context.Background(), "imsi-001010000000001", "AQIDBA==")
	if err != nil || status != 404 {
		t.Fatalf("send: %d %v", status, err)
	}
	if method != "POST" || path != "/nsmsf-sms-internal/v1/ue-contexts/imsi-001010000000001/mt-sms" || body != `{"smsPayload":"AQIDBA=="}` {
		t.Errorf("request: %s %s %s", method, path, body)
	}
	if string(raw) != `{"cause":"CONTEXT_NOT_FOUND"}` {
		t.Errorf("raw: %s", raw)
	}
}

func TestAMFANReleaseAndPortalHelpers(t *testing.T) {
	var calls []string
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		calls = append(calls, r.Method+" "+r.URL.Path)
		bodies = append(bodies, string(b))
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	ctx := context.Background()
	if s, _, err := NewAMF(srv.URL, srv.Client()).ANRelease(ctx, "imsi-001010000000001"); err != nil || s != 200 {
		t.Fatalf("an-release: %d %v", s, err)
	}
	p := NewPortal(srv.URL, srv.Client())
	if _, err := p.UELocation(ctx, "imsi-001010000000001"); err != nil {
		t.Fatalf("location: %v", err)
	}
	if _, s, err := p.PWSResend(ctx, 4370, 16384); err != nil || s != 200 {
		t.Fatalf("resend: %d %v", s, err)
	}
	want := []string{
		"POST /amf/v1/ue-contexts/imsi-001010000000001/an-release",
		"GET /api/v1/location/ue/imsi-001010000000001",
		"POST /api/v1/pws/resend",
	}
	for i, w := range want {
		if calls[i] != w {
			t.Errorf("call %d: %s want %s", i, calls[i], w)
		}
	}
	if bodies[2] != `{"messageIdentifier":4370,"serialNumber":16384}` {
		t.Errorf("resend body: %s", bodies[2])
	}
}
