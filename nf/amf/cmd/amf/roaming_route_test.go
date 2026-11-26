package main

// roaming_route_test.go - ROAM-001 consumer side: a route on the context sends
// Nausf/Nudm requests to the SEPP with 3gpp-Sbi-Target-apiRoot; without a route
// (roaming off, or a non-roaming UE with roaming on) the requests are
// byte-identical to the legacy ones and carry no such header.
// Ref: TS 29.500 §6.1.4.3; TS 23.502 §4.2.2.2.2

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/francurieses/claudia-5gc/nf/amf/internal/procedures"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/roaming"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

const (
	testHomeAUSF = "https://ausf.5gc.mnc002.mcc001.3gppnetwork.org:8002"
	testHomeUDM  = "https://udm.5gc.mnc002.mcc001.3gppnetwork.org:8003"
	roamSUCI     = "suci-0-001-02-0-0-0-0000000001"
	roamSUPI     = "imsi-001020000000001"
)

type seen struct {
	req       capturedReq
	apiRoot   string
	hasHdr    bool
	origin    string
	hasOrigin bool
	count     int
}

func seppServer(t *testing.T, status int, answer, loc string) (addr string, got *seen, hc *http.Client) {
	t.Helper()
	got = new(seen)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		got.count++
		got.req = capturedReq{r.Method, r.URL.RequestURI(), r.Header.Get("Content-Type"), string(raw)}
		got.apiRoot = r.Header.Get(roaming.TargetAPIRootHeader)
		_, got.hasHdr = r.Header[http.CanonicalHeaderKey(roaming.TargetAPIRootHeader)]
		got.origin = r.Header.Get(roaming.OriginatingNetworkIDHeader)
		_, got.hasOrigin = r.Header[http.CanonicalHeaderKey(roaming.OriginatingNetworkIDHeader)]
		w.Header().Set("Content-Type", "application/json")
		if loc != "" {
			w.Header().Set("Location", loc)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(answer))
	}))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "https://"), got, srv.Client()
}

// hostRecorder records the host of every request the client attempts, so a test
// can prove a roaming request never targets the local AUSF/UDM.
type hostRecorder struct {
	next  http.RoundTripper
	mu    sync.Mutex
	hosts []string
}

func (h *hostRecorder) RoundTrip(r *http.Request) (*http.Response, error) {
	h.mu.Lock()
	h.hosts = append(h.hosts, r.URL.Host)
	h.mu.Unlock()
	return h.next.RoundTrip(r)
}

func recorded(hc *http.Client) (*http.Client, *hostRecorder) {
	rec := &hostRecorder{next: hc.Transport}
	return &http.Client{Transport: rec}, rec
}

func testRoute(sepp string) *roaming.Route {
	return &roaming.Route{HomePLMN: roaming.PLMN{MCC: "001", MNC: "02"}, ServingPLMN: roaming.PLMN{MCC: "001", MNC: "01"},
		ViaSEPP: sepp, AUSFAPIRoot: testHomeAUSF, UDMAPIRoot: testHomeUDM}
}

const confirmOK = `{"authResult":"AUTHENTICATION_SUCCESS","kausf":"000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f","supi":"` + roamSUPI + `"}`

// wantRouted fails unless the last request reached the SEPP with the home
// apiRoot and the serving PLMN as originating network id (TS 29.500 §5.2.3.2.15).
func wantRouted(t *testing.T, name string, got *seen, apiRoot, method, uri string) {
	t.Helper()
	if got.apiRoot != apiRoot || got.req.method != method || got.req.uri != uri {
		t.Fatalf("%s: %+v", name, got)
	}
	if got.origin != "001-01" {
		t.Fatalf("%s: %s = %q, want 001-01", name, roaming.OriginatingNetworkIDHeader, got.origin)
	}
}

func TestRoamingAUSFRoutedViaSEPP(t *testing.T) {
	sepp, got, hc := seppServer(t, http.StatusCreated, goldenAuthAnswer, "https://x/nausf-auth/v1/ue-authentications/ctx-9")
	c := &HTTPAUSFClient{address: "local-ausf:1", client: hc}
	ctx := roaming.WithRoute(t.Context(), testRoute(sepp))

	if _, err := c.InitiateAuth(ctx, roamSUCI, goldenSN); err != nil {
		t.Fatal(err)
	}
	wantRouted(t, "authenticate", got, testHomeAUSF, "POST", "/nausf-auth/v1/ue-authentications")
	// servingNetworkName stays the visited PLMN (TS 33.501 §6.1.1.4).
	if !strings.Contains(got.req.body, `"servingNetworkName":"`+goldenSN+`"`) {
		t.Fatalf("body %s", got.req.body)
	}

	csepp, cgot, chc := seppServer(t, http.StatusOK, confirmOK, "")
	cc := &HTTPAUSFClient{address: "local-ausf:1", client: chc}
	cctx := roaming.WithRoute(t.Context(), testRoute(csepp))
	resp, err := cc.ConfirmAuth(cctx, "ctx-9", "00")
	if err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if resp.SUPI != roamSUPI {
		t.Fatalf("confirm supi %q", resp.SUPI)
	}
	wantRouted(t, "confirm", cgot, testHomeAUSF, "PUT", "/nausf-auth/v1/ue-authentications/ctx-9/5g-aka-confirmation")
}

func TestRoamingUDMRoutedViaSEPP(t *testing.T) {
	sepp, got, hc := seppServer(t, http.StatusCreated, ``, "https://x/nudm-sdm/v2/"+roamSUPI+"/sdm-subscriptions/sub-1")
	c := &HTTPUDMClient{address: "local-udm:1", client: hc}
	c.SetSelf("amf-1", "https://amf.test:8001", "001", "01", 2, 1, 1)
	ctx := roaming.WithRoute(t.Context(), testRoute(sepp))

	if err := c.RegisterAMF(ctx, roamSUPI, "amf-1", goldenSN); err != nil {
		t.Fatal(err)
	}
	wantRouted(t, "uecm", got, testHomeUDM, "PUT", "/nudm-uecm/v1/"+roamSUPI+"/registrations/amf-3gpp-access")
	if _, err := c.SubscribeAMData(ctx, roamSUPI); err != nil {
		t.Fatal(err)
	}
	wantRouted(t, "subscribe", got, testHomeUDM, "POST", "/nudm-sdm/v2/"+roamSUPI+"/sdm-subscriptions")
	dsepp, got, dhc := seppServer(t, http.StatusNoContent, ``, "")
	c = &HTTPUDMClient{address: "local-udm:1", client: dhc}
	ctx = roaming.WithRoute(t.Context(), testRoute(dsepp))
	if err := c.UnsubscribeSDM(ctx, roamSUPI, "sub-1"); err != nil {
		t.Fatal(err)
	}
	wantRouted(t, "unsubscribe", got, testHomeUDM, "DELETE", "/nudm-sdm/v2/"+roamSUPI+"/sdm-subscriptions/sub-1")
	if err := c.DeregisterUECM(ctx, roamSUPI); err != nil {
		t.Fatal(err)
	}
	wantRouted(t, "deregister", got, testHomeUDM, "DELETE", "/nudm-uecm/v1/"+roamSUPI+"/registrations/amf-3gpp-access")

	gsepp, ggot, ghc := seppServer(t, http.StatusOK, goldenAMAnswer, "")
	gc := &HTTPUDMClient{address: "local-udm:1", client: ghc}
	if _, err := gc.GetAMSubscriptionData(roaming.WithRoute(t.Context(), testRoute(gsepp)), roamSUPI); err != nil {
		t.Fatalf("sdm get: %v", err)
	}
	wantRouted(t, "sdm get", ggot, testHomeUDM, "GET", "/nudm-sdm/v2/"+roamSUPI+"/am-data")
}

func testRouter(t *testing.T) *roaming.Router {
	t.Helper()
	router, err := roaming.New(roaming.Config{Enabled: true, SEPPAddress: "sepp:8014", HomePLMNs: []roaming.HomePLMN{{
		PLMN: roaming.PLMN{MCC: "001", MNC: "02"}, AUSFAPIRoot: testHomeAUSF, UDMAPIRoot: testHomeUDM}}}, "001", "01")
	if err != nil {
		t.Fatal(err)
	}
	return router
}

// SUPI-only deregistration calls follow the route remembered for the SUPI.
func TestRoamingDeregistrationFollowsRememberedRoute(t *testing.T) {
	sepp, got, hc := seppServer(t, http.StatusNoContent, ``, "")
	rc, rec := recorded(hc)
	router := testRouter(t)
	c := &HTTPUDMClient{address: "local-udm:1", client: rc, router: router}
	router.Remember(roamSUPI, testRoute(sepp))

	if err := c.DeregisterUECM(t.Context(), roamSUPI); err != nil {
		t.Fatal(err)
	}
	wantRouted(t, "deregister", got, testHomeUDM, "DELETE", "/nudm-uecm/v1/"+roamSUPI+"/registrations/amf-3gpp-access")
	if len(rec.hosts) != 1 || rec.hosts[0] != sepp {
		t.Fatalf("request hosts %v, want only the SEPP %s", rec.hosts, sepp)
	}
	if router.ForSUPI(roamSUPI) != nil {
		t.Fatal("route must be forgotten after deregistration")
	}

	// Negative: an unknown (non-roaming) SUPI goes to the local UDM, no roaming headers.
	rec.hosts = nil
	got.hasHdr, got.hasOrigin, got.count = false, false, 0
	_ = c.DeregisterUECM(t.Context(), "imsi-001010000000009")
	if len(rec.hosts) != 1 || rec.hosts[0] != "local-udm:1" || got.count != 0 {
		t.Fatalf("non-roaming SUPI: hosts %v, SEPP hits %d", rec.hosts, got.count)
	}
}

// A UE known to be roaming without a resolvable route fails; it never goes local.
func TestRoamingRequiredWithoutRouteFails(t *testing.T) {
	_, got, hc := seppServer(t, http.StatusNoContent, ``, "")
	rc, rec := recorded(hc)
	c := &HTTPUDMClient{address: "local-udm:1", client: rc, router: testRouter(t)}
	a := &HTTPAUSFClient{address: "local-ausf:1", client: rc}
	ctx := roaming.WithRoamingRequired(t.Context())

	checks := map[string]error{
		"deregister":  c.DeregisterUECM(ctx, roamSUPI),
		"unsubscribe": c.UnsubscribeSDM(ctx, roamSUPI, "sub-1"),
		"register":    c.RegisterAMF(ctx, roamSUPI, "amf-1", goldenSN),
	}
	_, checks["authenticate"] = a.InitiateAuth(ctx, roamSUCI, goldenSN)
	_, checks["confirm"] = a.ConfirmAuth(ctx, "ctx-1", "00")
	for name, err := range checks {
		if !errors.Is(err, roaming.ErrNoRoute) {
			t.Errorf("%s: err = %v, want ErrNoRoute", name, err)
		}
	}
	if len(rec.hosts) != 0 || got.count != 0 {
		t.Fatalf("requests were sent: %v / %d", rec.hosts, got.count)
	}
}

// A SEPP transport error or 5xx fails the request; the local AUSF/UDM is never tried.
func TestRoamingSEPPFailureNeverFallsBackLocal(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int // 0 = SEPP unreachable (transport error)
	}{{"transport error", 0}, {"5xx", http.StatusBadGateway}} {
		t.Run(tc.name, func(t *testing.T) {
			var sepp string
			var hc *http.Client
			if tc.status == 0 {
				srv := httptest.NewTLSServer(http.NotFoundHandler())
				hc = srv.Client()
				sepp = strings.TrimPrefix(srv.URL, "https://")
				srv.Close() // nothing listens any more
			} else {
				sepp, _, hc = seppServer(t, tc.status, `{"cause":"TARGET_NF_NOT_REACHABLE"}`, "")
			}
			rc, rec := recorded(hc)
			ctx := roaming.WithRoamingRequired(roaming.WithRoute(t.Context(), testRoute(sepp)))
			a := &HTTPAUSFClient{address: "local-ausf:1", client: rc}
			u := &HTTPUDMClient{address: "local-udm:1", client: rc}

			if _, err := a.InitiateAuth(ctx, roamSUCI, goldenSN); err == nil {
				t.Error("authenticate: want error")
			}
			if _, err := a.ConfirmAuth(ctx, "ctx-1", "00"); err == nil {
				t.Error("confirm: want error")
			}
			if err := u.RegisterAMF(ctx, roamSUPI, "amf-1", goldenSN); err == nil {
				t.Error("uecm: want error")
			}
			if _, err := u.GetAMSubscriptionData(ctx, roamSUPI); err == nil {
				t.Error("sdm get: want error")
			}
			if len(rec.hosts) == 0 {
				t.Fatal("no request attempted")
			}
			for _, h := range rec.hosts {
				if h != sepp {
					t.Errorf("request to %s, want only the SEPP %s", h, sepp)
				}
			}
		})
	}
}

// A UDM 403 ROAMING_NOT_ALLOWED relayed by the SEPP is a typed error mapped to #11.
func TestRoamingUDM403RoamingNotAllowedTyped(t *testing.T) {
	sepp, _, hc := seppServer(t, http.StatusForbidden, `{"cause":"`+procedures.UDMCauseRoamingNotAllowed+`"}`, "")
	c := &HTTPUDMClient{address: "local-udm:1", client: hc}
	err := c.RegisterAMF(roaming.WithRoute(t.Context(), testRoute(sepp)), roamSUPI, "amf-1", goldenSN)
	var ue *procedures.UDMError
	if !errors.As(err, &ue) || ue.Status != http.StatusForbidden || ue.Cause != procedures.UDMCauseRoamingNotAllowed {
		t.Fatalf("err = %v, want UDMError 403 ROAMING_NOT_ALLOWED", err)
	}
	if cause, _ := procedures.RejectCauseForUDMError(err); cause != nas.CausePLMNNotAllowed {
		t.Fatalf("reject cause %d, want #11", cause)
	}
}

// Golden: with roaming enabled a non-roaming request (no route) is byte-identical
// to the roaming-disabled one and carries no 3gpp-Sbi-Target-apiRoot header.
func TestNonRoamingBytesIdenticalWithRoamingEnabled(t *testing.T) {
	router := testRouter(t)
	for _, mode := range goldenModes(t) {
		run := func(r *roaming.Router) (auth, reg, get, dereg seen) {
			addr, g, hc := seppServer(t, http.StatusCreated, goldenAuthAnswer, "https://x/nausf-auth/v1/ue-authentications/ctx-1")
			a := newAUSFClient(addr, hc, mode)
			if _, err := a.InitiateAuth(t.Context(), goldenSUCI, goldenSN); err != nil {
				t.Fatal(err)
			}
			auth = *g
			uaddr, ug, uhc := seppServer(t, http.StatusCreated, goldenAMAnswer, "")
			u := newUDMClient(uaddr, uhc, mode)
			u.router = r
			u.SetSelf("amf-test-1", "https://amf.test:8001", "001", "01", 2, 1, 1)
			if err := u.RegisterAMF(t.Context(), goldenSUPI, "amf-test-1", goldenSN); err != nil {
				t.Fatal(err)
			}
			reg = *ug
			if _, err := u.GetAMSubscriptionData(t.Context(), goldenSUPI); err != nil {
				t.Fatal(err)
			}
			get = *ug
			daddr, dg, dhc := seppServer(t, http.StatusNoContent, ``, "")
			d := newUDMClient(daddr, dhc, mode)
			d.router = r
			if err := d.DeregisterUECM(t.Context(), goldenSUPI); err != nil {
				t.Fatal(err)
			}
			dereg = *dg
			return
		}
		a1, r1, g1, d1 := run(nil)
		a2, r2, g2, d2 := run(router)
		for i, p := range [][2]seen{{a1, a2}, {r1, r2}, {g1, g2}, {d1, d2}} {
			if p[0].req != p[1].req {
				t.Errorf("%s/%d: request differs with roaming enabled:\n off %s\n on  %s", mode.name, i, p[0].req, p[1].req)
			}
			if p[1].hasHdr || p[1].hasOrigin {
				t.Errorf("%s/%d: non-roaming request carries %s / %s", mode.name, i,
					roaming.TargetAPIRootHeader, roaming.OriginatingNetworkIDHeader)
			}
		}
		if a2.req.String() != "POST /nausf-auth/v1/ue-authentications [application/json] "+goldenAuthBody {
			t.Errorf("%s: authenticate bytes changed: %s", mode.name, a2.req)
		}
	}
}

func TestRoamingAUSFTypedErrors(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		body       string
		confirm    bool
		wantStatus int
		wantCause  string
	}{
		{"authenticate 403 SNNA", 403, `{"cause":"SERVING_NETWORK_NOT_AUTHORIZED"}`, false, 403, procedures.AUSFCauseServingNetworkNotAuthorized},
		{"authenticate SEPP 504", 504, `{"cause":"TARGET_NF_NOT_REACHABLE"}`, false, 504, "TARGET_NF_NOT_REACHABLE"},
		{"confirm SEPP 504", 504, `{"cause":"TARGET_NF_NOT_REACHABLE"}`, true, 504, "TARGET_NF_NOT_REACHABLE"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sepp, _, hc := seppServer(t, tc.status, tc.body, "")
			c := &HTTPAUSFClient{address: "local-ausf:1", client: hc}
			ctx := roaming.WithRoute(t.Context(), testRoute(sepp))
			var err error
			if tc.confirm {
				_, err = c.ConfirmAuth(ctx, "ctx-1", "00")
			} else {
				_, err = c.InitiateAuth(ctx, roamSUCI, goldenSN)
			}
			var ae *procedures.AUSFError
			if !errors.As(err, &ae) || ae.Status != tc.wantStatus || ae.Cause != tc.wantCause {
				t.Fatalf("err = %v, want AUSFError %d %s", err, tc.wantStatus, tc.wantCause)
			}
		})
	}
}
