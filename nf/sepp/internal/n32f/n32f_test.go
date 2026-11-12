package n32f

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/francurieses/claudia-5gc/nf/sepp/internal/n32c"
)

const (
	localFQDN  = "sepp.5gc.mnc001.mcc001.3gppnetwork.org"
	remoteSEPP = "sepp.5gc.mnc002.mcc001.3gppnetwork.org"
	remoteNF   = "nudm.5gc.mnc002.mcc001.3gppnetwork.org"
	localNF    = "nudm.5gc.mnc001.mcc001.3gppnetwork.org"
)

var (
	localPLMN  = n32c.PlmnId{Mcc: "001", Mnc: "001"}
	remotePLMN = n32c.PlmnId{Mcc: "001", Mnc: "002"}
)

type stubResolver struct {
	u   *url.URL
	err error
}

func (s stubResolver) Resolve(context.Context, string, string) (*url.URL, error) { return s.u, s.err }

type fixture struct {
	f     *Forwarder
	store *n32c.Store
	peer  *httptest.Server
}

type opts struct {
	peerHandler http.Handler
	ctx         *n32c.Context // nil: default TLS context without header model
	noCtx       bool
	hide        bool
	localHeader bool
	timeout     time.Duration
	maxInflight int
	local       *url.URL
	resolveErr  error
}

func newFixture(t *testing.T, o opts) *fixture {
	t.Helper()
	if o.peerHandler == nil {
		o.peerHandler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })
	}
	peer := httptest.NewUnstartedServer(o.peerHandler)
	peer.EnableHTTP2 = true
	peer.StartTLS()
	t.Cleanup(peer.Close)
	pool := x509.NewCertPool()
	pool.AddCert(peer.Certificate())
	tr, err := NewN32Transport(&tls.Config{RootCAs: pool, Certificates: peer.TLS.Certificates})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tr.CloseIdleConnections)

	store := n32c.NewStore(nil)
	if !o.noCtx {
		c := n32c.Context{RemotePLMN: remotePLMN, SecCapability: n32c.CapTLS, PeerFQDN: "example.com"}
		if o.ctx != nil {
			c = *o.ctx
			c.RemotePLMN = remotePLMN
			if c.PeerFQDN == "" {
				c.PeerFQDN = "example.com"
			}
		}
		store.Replace(c)
	}
	local := o.local
	if local == nil {
		local = &url.URL{Scheme: "http", Host: "127.0.0.1:1"}
	}
	f, err := New(Config{
		LocalPLMN: localPLMN, SEPPFQDN: localFQDN, Store: store,
		TargetAPIRootSupported: o.localHeader, TopologyHiding: o.hide,
		Transport: tr, LocalTransport: http.DefaultTransport.(*http.Transport).Clone(),
		Resolver: stubResolver{u: local, err: o.resolveErr},
		PeerIdentity: func(*http.Request) (n32c.PeerIdentity, error) {
			return n32c.PeerIdentity{FQDN: remoteSEPP, PLMN: remotePLMN}, nil
		},
		PeerAddr:       func(n32c.Context) string { return peer.Listener.Addr().String() },
		RequestTimeout: o.timeout, MaxInflight: o.maxInflight,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{f: f, store: store, peer: peer}
}

func do(h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func problem(t *testing.T, rec *httptest.ResponseRecorder) n32c.ProblemDetails {
	t.Helper()
	var pd n32c.ProblemDetails
	if err := json.Unmarshal(rec.Body.Bytes(), &pd); err != nil {
		t.Fatalf("problem body %q: %v", rec.Body.String(), err)
	}
	return pd
}

type seen struct {
	mu   sync.Mutex
	req  *http.Request
	body []byte
}

func (s *seen) handler(status int, hdr map[string]string, resp string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.req, s.body = r, b
		s.mu.Unlock()
		for k, v := range hdr {
			w.Header().Set(k, v)
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, resp)
	})
}

func TestOutboundForwardOKTelescopicModel(t *testing.T) {
	var s seen
	fx := newFixture(t, opts{peerHandler: s.handler(200, map[string]string{"Content-Type": "application/json"}, `{"ok":true}`)})
	body := `{"supi":"imsi-001010000000001","n":1.0}`
	req := httptest.NewRequest("POST", "https://"+remoteNF+":8000/nudm-sdm/v2/x?a=b", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(HeaderCorrelationID, "01CORR")
	rec := do(fx.f.Outbound(), req)
	if rec.Code != 200 || rec.Body.String() != `{"ok":true}` {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get(HeaderCorrelationID); got != "01CORR" {
		t.Fatalf("correlation id not preserved: %q", got)
	}
	if s.req.ProtoMajor != 2 {
		t.Fatalf("N32-f must be HTTP/2, got %s", s.req.Proto)
	}
	if s.req.Host != remoteNF+":8000" || s.req.URL.RequestURI() != "/nudm-sdm/v2/x?a=b" {
		t.Fatalf("authority/path: %q %q", s.req.Host, s.req.URL.RequestURI())
	}
	if s.req.Header.Get(HeaderTargetAPIRoot) != "" {
		t.Fatal("header must not be sent when the model is not negotiated")
	}
	if string(s.body) != body {
		t.Fatalf("body altered: %q", s.body)
	}
	if s.req.Header.Get(HeaderCorrelationID) != "01CORR" || !strings.Contains(s.req.Header.Get("Via"), "SEPP-"+localFQDN) {
		t.Fatalf("headers: %v", s.req.Header)
	}
}

func TestOutboundHeaderModel(t *testing.T) {
	for _, tc := range []struct {
		name string
		host string
		hdr  string
		want string
	}{
		{"header forwarded unmodified", localFQDN + ":8014", "https://" + remoteNF + ":8000", "https://" + remoteNF + ":8000"},
		{"header inserted for plain request", remoteNF + ":8000", "", "https://" + remoteNF + ":8000"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var s seen
			fx := newFixture(t, opts{peerHandler: s.handler(204, nil, ""), localHeader: true,
				ctx: &n32c.Context{SecCapability: n32c.CapTLS, TargetAPIRootHeader: true}})
			req := httptest.NewRequest("GET", "https://"+tc.host+"/nudm-sdm/v2/x", nil)
			if tc.hdr != "" {
				req.Header.Set(HeaderTargetAPIRoot, tc.hdr)
			}
			if rec := do(fx.f.Outbound(), req); rec.Code != 204 {
				t.Fatalf("got %d %s", rec.Code, rec.Body)
			}
			if got := s.req.Header.Get(HeaderTargetAPIRoot); got != tc.want {
				t.Fatalf("header = %q want %q", got, tc.want)
			}
			if s.req.Host != fx.peer.Listener.Addr().String() {
				t.Fatalf("authority must be the receiving SEPP, got %q", s.req.Host)
			}
		})
	}
}

func TestOutboundHeaderIgnoredWhenNotNegotiated(t *testing.T) {
	var s seen
	fx := newFixture(t, opts{peerHandler: s.handler(204, nil, "")}) // context without header model
	req := httptest.NewRequest("GET", "https://"+localFQDN+"/nudm-sdm/v2/x", nil)
	req.Header.Set(HeaderTargetAPIRoot, "https://"+remoteNF)
	if rec := do(fx.f.Outbound(), req); rec.Code != 204 {
		t.Fatalf("got %d", rec.Code)
	}
	// TS 29.500 §6.1.4.3.4: header removed, request-URI apiRoot := target apiRoot.
	if s.req.Host != remoteNF || s.req.Header.Get(HeaderTargetAPIRoot) != "" {
		t.Fatalf("host=%q hdr=%q", s.req.Host, s.req.Header.Get(HeaderTargetAPIRoot))
	}
}

func TestOutboundTelescopicAuthorityDecoded(t *testing.T) {
	var s seen
	fx := newFixture(t, opts{peerHandler: s.handler(204, nil, ""), hide: true})
	tele, err := fx.f.tele.Encode(remoteNF)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "https://"+tele+"/nudm-sdm/v2/x", nil)
	// A malicious header next to a telescopic FQDN must be ignored (TS 29.500 §6.1.4.3.3 NOTE 1).
	req.Header.Set(HeaderTargetAPIRoot, "https://evil.5gc.mnc009.mcc009.3gppnetwork.org")
	if rec := do(fx.f.Outbound(), req); rec.Code != 204 {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
	if s.req.Host != remoteNF || s.req.Header.Get(HeaderTargetAPIRoot) != "" {
		t.Fatalf("host=%q hdr=%q", s.req.Host, s.req.Header.Get(HeaderTargetAPIRoot))
	}
}

func TestOutboundResponseHiding(t *testing.T) {
	resp := `{"nfInstances":[{"fqdn":"` + remoteNF + `","nfServices":[{"apiPrefix":"https://` + remoteNF + `:8000/p"}]}],"validityPeriod":3600,"keep":"https://` + localNF + `/x"}`
	hdr := map[string]string{"Content-Type": "application/json", "Location": "https://" + remoteNF + ":8000/nudm-uecm/v1/ue/1"}
	t.Run("telescopic model hides", func(t *testing.T) {
		var s seen
		fx := newFixture(t, opts{peerHandler: s.handler(200, hdr, resp), hide: true})
		rec := do(fx.f.Outbound(), httptest.NewRequest("GET", "https://"+remoteNF+"/nnrf-disc/v1/nf-instances", nil))
		tele, _ := fx.f.tele.Encode(remoteNF)
		if got := rec.Header().Get("Location"); got != "https://"+tele+":8000/nudm-uecm/v1/ue/1" {
			t.Fatalf("Location = %q", got)
		}
		var doc map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		p := doc["nfInstances"].([]any)[0].(map[string]any)
		if p["fqdn"] != tele || p["nfServices"].([]any)[0].(map[string]any)["apiPrefix"] != "https://"+tele+":8000/p" {
			t.Fatalf("not hidden: %s", rec.Body)
		}
		if doc["keep"] != "https://"+localNF+"/x" || doc["validityPeriod"].(float64) != 3600 {
			t.Fatalf("local host/number altered: %s", rec.Body)
		}
		if rec.Header().Get("Content-Length") != "" && rec.Header().Get("Content-Length") != fmtInt(rec.Body.Len()) {
			t.Fatalf("content-length %q vs %d", rec.Header().Get("Content-Length"), rec.Body.Len())
		}
	})
	t.Run("header request is not rewritten", func(t *testing.T) {
		var s seen
		fx := newFixture(t, opts{peerHandler: s.handler(200, hdr, resp), hide: true})
		req := httptest.NewRequest("GET", "https://"+localFQDN+"/nnrf-disc/v1/nf-instances", nil)
		req.Header.Set(HeaderTargetAPIRoot, "https://"+remoteNF)
		rec := do(fx.f.Outbound(), req)
		if rec.Body.String() != resp || rec.Header().Get("Location") != hdr["Location"] {
			t.Fatalf("must be untouched (TS 29.500 §6.1.4.3.1): %s", rec.Body)
		}
	})
	t.Run("hiding disabled keeps body", func(t *testing.T) {
		var s seen
		fx := newFixture(t, opts{peerHandler: s.handler(200, hdr, resp)})
		rec := do(fx.f.Outbound(), httptest.NewRequest("GET", "https://"+remoteNF+"/x", nil))
		if rec.Body.String() != resp {
			t.Fatalf("body altered: %s", rec.Body)
		}
	})
}

func fmtInt(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

func TestInboundForwardAndCallbackRewrite(t *testing.T) {
	var s seen
	localSrv := httptest.NewServer(s.handler(201, map[string]string{"Location": "https://" + localNF + "/r/1"}, "done"))
	t.Cleanup(localSrv.Close)
	lu, _ := url.Parse(localSrv.URL)
	cb := `{"callbackUri":"https://` + remoteNF + `:9000/cb/1","dnn":"internet"}`

	t.Run("callback hidden with own domain", func(t *testing.T) {
		fx := newFixture(t, opts{hide: true, local: lu})
		req := httptest.NewRequest("POST", "https://"+localNF+"/nudm-sdm/v2/subs", strings.NewReader(cb))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(HeaderCorrelationID, "01IN")
		rec := do(fx.f.Inbound(), req)
		if rec.Code != 201 || rec.Body.String() != "done" || rec.Header().Get(HeaderCorrelationID) != "01IN" {
			t.Fatalf("got %d %q", rec.Code, rec.Body)
		}
		tele, _ := fx.f.tele.Encode(remoteNF)
		var got map[string]string
		if err := json.Unmarshal(s.body, &got); err != nil {
			t.Fatal(err)
		}
		if got["callbackUri"] != "https://"+tele+":9000/cb/1" || got["dnn"] != "internet" {
			t.Fatalf("body = %s", s.body)
		}
		if s.req.Host != strings.TrimPrefix(localSrv.URL, "http://") {
			t.Fatalf("host = %q", s.req.Host)
		}
		// Location of the response is passed as is (only the hSEPP-side view is rewritten).
		if rec.Header().Get("Location") != "https://"+localNF+"/r/1" {
			t.Fatalf("Location = %q", rec.Header().Get("Location"))
		}
	})
	t.Run("hiding off leaves body untouched", func(t *testing.T) {
		fx := newFixture(t, opts{local: lu})
		req := httptest.NewRequest("POST", "https://"+localNF+"/nudm-sdm/v2/subs", strings.NewReader(cb))
		req.Header.Set("Content-Type", "application/json")
		do(fx.f.Inbound(), req)
		if string(s.body) != cb {
			t.Fatalf("body = %s", s.body)
		}
	})
	t.Run("header model: header consumed, target from header", func(t *testing.T) {
		fx := newFixture(t, opts{local: lu, localHeader: true, hide: true,
			ctx: &n32c.Context{SecCapability: n32c.CapTLS, TargetAPIRootHeader: true}})
		req := httptest.NewRequest("POST", "https://"+remoteSEPP+"/nudm-sdm/v2/subs", strings.NewReader(cb))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(HeaderTargetAPIRoot, "https://"+localNF)
		if rec := do(fx.f.Inbound(), req); rec.Code != 201 {
			t.Fatalf("got %d %s", rec.Code, rec.Body)
		}
		if s.req.Header.Get(HeaderTargetAPIRoot) != "" || string(s.body) != cb {
			t.Fatalf("header=%q body=%s", s.req.Header.Get(HeaderTargetAPIRoot), s.body)
		}
	})
	t.Run("header not negotiated is rejected", func(t *testing.T) {
		fx := newFixture(t, opts{local: lu})
		req := httptest.NewRequest("GET", "https://"+remoteSEPP+"/nudm-sdm/v2/x", nil)
		req.Header.Set(HeaderTargetAPIRoot, "https://"+localNF)
		rec := do(fx.f.Inbound(), req)
		if rec.Code != 400 || problem(t, rec).Cause != causeInvalidMsgFormat {
			t.Fatalf("got %d %s", rec.Code, rec.Body)
		}
	})
	t.Run("target outside local PLMN is rejected", func(t *testing.T) {
		fx := newFixture(t, opts{local: lu})
		rec := do(fx.f.Inbound(), httptest.NewRequest("GET", "https://"+remoteNF+"/nudm-sdm/v2/x", nil))
		if rec.Code != 400 {
			t.Fatalf("got %d", rec.Code)
		}
	})
	t.Run("NRF cannot resolve the NF", func(t *testing.T) {
		fx := newFixture(t, opts{local: lu, resolveErr: ErrTargetNotFound})
		rec := do(fx.f.Inbound(), httptest.NewRequest("GET", "https://"+localNF+"/nudm-sdm/v2/x", nil))
		if rec.Code != 504 || problem(t, rec).Cause != causeTargetUnreachable {
			t.Fatalf("got %d %s", rec.Code, rec.Body)
		}
	})
}

func TestNoContextAndNonTLSContextRejected(t *testing.T) {
	cases := map[string]opts{
		"no context":       {noCtx: true},
		"PRINS context":    {ctx: &n32c.Context{SecCapability: n32c.CapPRINS}},
		"NONE (torn down)": {ctx: &n32c.Context{SecCapability: n32c.CapNone}},
	}
	for name, o := range cases {
		t.Run(name, func(t *testing.T) {
			fx := newFixture(t, o)
			for dir, h := range map[string]http.Handler{"out": fx.f.Outbound(), "in": fx.f.Inbound()} {
				host := remoteNF
				if dir == "in" {
					host = localNF
				}
				rec := do(h, httptest.NewRequest("GET", "https://"+host+"/nudm-sdm/v2/x", nil))
				pd := problem(t, rec)
				if rec.Code != 403 || pd.Cause != causeContextNotFound || pd.Status != 403 {
					t.Fatalf("%s: got %d %+v", dir, rec.Code, pd)
				}
				if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
					t.Fatalf("content-type %q", ct)
				}
			}
		})
	}
}

func TestOutboundRejectsBadTargets(t *testing.T) {
	fx := newFixture(t, opts{})
	for name, host := range map[string]string{
		"no PLMN in FQDN": "nudm.example.com",
		"local PLMN":      localNF,
	} {
		t.Run(name, func(t *testing.T) {
			rec := do(fx.f.Outbound(), httptest.NewRequest("GET", "https://"+host+"/x", nil))
			if rec.Code != 400 || len(problem(t, rec).InvalidParams) != 1 {
				t.Fatalf("got %d %s", rec.Code, rec.Body)
			}
		})
	}
}

func TestLoopPreventionAndHopByHop(t *testing.T) {
	var s seen
	fx := newFixture(t, opts{peerHandler: s.handler(204, nil, "")})
	t.Run("own Via is a loop", func(t *testing.T) {
		req := httptest.NewRequest("GET", "https://"+remoteNF+"/x", nil)
		req.Header.Add("Via", "2.0 SEPP-other.example, 2.0 SEPP-"+strings.ToUpper(localFQDN))
		rec := do(fx.f.Outbound(), req)
		if rec.Code != 400 || problem(t, rec).Cause != causeMsgLoopDetected {
			t.Fatalf("got %d %s", rec.Code, rec.Body)
		}
		if rec.Header().Get("Server") != "SEPP-"+localFQDN || rec.Header().Get("Via") != "" {
			t.Fatalf("self-generated error needs Server and no Via (TS 29.500 §6.10.8.2): %v", rec.Header())
		}
		rec = do(fx.f.Inbound(), func() *http.Request {
			r := httptest.NewRequest("GET", "https://"+localNF+"/x", nil)
			r.Header.Add("Via", "2.0 SEPP-"+localFQDN)
			return r
		}())
		if rec.Code != 400 {
			t.Fatalf("inbound loop: %d", rec.Code)
		}
	})
	t.Run("foreign Via is kept and ours appended", func(t *testing.T) {
		req := httptest.NewRequest("GET", "https://"+remoteNF+"/x", nil)
		req.Header.Add("Via", "2.0 SEPP-"+remoteSEPP)
		if rec := do(fx.f.Outbound(), req); rec.Code != 204 {
			t.Fatalf("got %d", rec.Code)
		}
		if v := strings.Join(s.req.Header.Values("Via"), ","); !strings.Contains(v, remoteSEPP) || !strings.Contains(v, localFQDN) {
			t.Fatalf("Via = %q", v)
		}
	})
	t.Run("hop-by-hop headers are not forwarded", func(t *testing.T) {
		req := httptest.NewRequest("GET", "https://"+remoteNF+"/x", nil)
		req.Header.Set("Connection", "X-Secret")
		req.Header.Set("X-Secret", "1")
		req.Header.Set("Keep-Alive", "timeout=5")
		req.Header.Set("Proxy-Authorization", "x")
		req.Header.Set("X-End2End", "yes")
		if rec := do(fx.f.Outbound(), req); rec.Code != 204 {
			t.Fatalf("got %d", rec.Code)
		}
		for _, h := range []string{"X-Secret", "Keep-Alive", "Proxy-Authorization"} {
			if s.req.Header.Get(h) != "" {
				t.Fatalf("%s leaked", h)
			}
		}
		if s.req.Header.Get("X-End2End") != "yes" {
			t.Fatal("end-to-end header lost")
		}
	})
}

func TestContextTimeout(t *testing.T) {
	block := make(chan struct{})
	fx := newFixture(t, opts{timeout: 100 * time.Millisecond, peerHandler: http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-block:
		case <-r.Context().Done():
		}
	})})
	defer close(block)
	start := time.Now()
	rec := do(fx.f.Outbound(), httptest.NewRequest("GET", "https://"+remoteNF+"/x", nil))
	if rec.Code != 504 || problem(t, rec).Cause != causeTargetUnreachable {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("deadline not honoured")
	}
}

func TestPeerUnreachable(t *testing.T) {
	fx := newFixture(t, opts{})
	fx.peer.Close()
	rec := do(fx.f.Outbound(), httptest.NewRequest("GET", "https://"+remoteNF+"/x", nil))
	if rec.Code != 504 {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
}

func TestBoundedConcurrency(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	fx := newFixture(t, opts{maxInflight: 1, peerHandler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		entered <- struct{}{}
		<-release
		w.WriteHeader(204)
	})})
	done := make(chan int, 1)
	go func() { done <- do(fx.f.Outbound(), httptest.NewRequest("GET", "https://"+remoteNF+"/x", nil)).Code }()
	<-entered
	rec := do(fx.f.Outbound(), httptest.NewRequest("GET", "https://"+remoteNF+"/y", nil))
	if rec.Code != 503 || rec.Header().Get("Retry-After") == "" || problem(t, rec).Cause != "NF_CONGESTION" {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
	close(release)
	if c := <-done; c != 204 {
		t.Fatalf("first request: %d", c)
	}
}

func TestBodyTooLargeRewrite(t *testing.T) {
	fx := newFixture(t, opts{hide: true, local: &url.URL{Scheme: "http", Host: "127.0.0.1:1"}})
	fx.f.cfg.MaxBodyBytes = 16
	req := httptest.NewRequest("POST", "https://"+localNF+"/nudm-sdm/v2/x", strings.NewReader(`{"a":"`+strings.Repeat("x", 64)+`"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := do(fx.f.Inbound(), req)
	if rec.Code != 413 || problem(t, rec).Cause != "" {
		t.Fatalf("got %d %s (413 carries no cause, TS 29.500 §5.2.7.4)", rec.Code, rec.Body)
	}
}

func TestNewValidationAndTransport(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("empty config must fail")
	}
	if _, err := NewN32Transport(&tls.Config{}); err == nil {
		t.Fatal("transport without client certificate must fail (mTLS always)")
	}
	if _, err := NewN32Transport(&tls.Config{Certificates: fx0().TLS.Certificates}); err == nil {
		t.Fatal("transport without RootCAs must fail")
	}
	if _, err := NewN32Transport(&tls.Config{Certificates: fx0().TLS.Certificates, RootCAs: x509.NewCertPool(), InsecureSkipVerify: true}); err == nil {
		t.Fatal("InsecureSkipVerify must be refused")
	}
	if _, err := NewN32Transport(nil); err == nil {
		t.Fatal("nil tls config must fail")
	}
	// A request that carries no N32 context must never be dialled.
	fx := newFixture(t, opts{})
	req, _ := http.NewRequest("GET", "https://"+remoteNF+"/x", nil)
	if resp, err := fx.f.cfg.Transport.RoundTrip(req); err == nil {
		_ = resp.Body.Close()
		t.Fatal("dial without peer context must fail")
	}
}

func TestTelescopic(t *testing.T) {
	tl := NewTelescopic(localFQDN)
	for _, fqdn := range []string{remoteNF, "nrf-1.5gc.mnc002.mcc001.3gppnetwork.org", "a--b.c.mnc002.mcc001.3gppnetwork.org"} {
		enc, err := tl.Encode(fqdn)
		if err != nil {
			t.Fatal(err)
		}
		label, ok := tl.label(enc)
		if !ok || strings.Contains(label, ".") || !strings.HasSuffix(enc, "."+localFQDN) {
			t.Fatalf("not a single label: %q", enc)
		}
		if dec, err := tl.Decode(enc); err != nil || dec != fqdn {
			t.Fatalf("round trip %q -> %q -> %q (%v)", fqdn, enc, dec, err)
		}
		if again, _ := tl.Encode(enc); again != enc {
			t.Fatal("encode must be idempotent")
		}
	}
	long := strings.Repeat("a", 30) + "." + strings.Repeat("b", 30) + ".5gc.mnc002.mcc001.3gppnetwork.org"
	enc, err := tl.Encode(long)
	if err != nil {
		t.Fatal(err)
	}
	if l, _ := tl.label(enc); len(l) > maxDNSLabel {
		t.Fatalf("label too long: %d", len(l))
	}
	if dec, err := tl.Decode(enc); err != nil || dec != long {
		t.Fatalf("long round trip: %q %v", dec, err)
	}
	if _, err := NewTelescopic(localFQDN).Decode(enc); !errors.Is(err, ErrUnknownLabel) {
		t.Fatalf("fresh table must not know the label: %v", err)
	}
	for _, bad := range []string{"x.y." + localFQDN, "other.example", localFQDN} {
		if tl.Is(bad) {
			t.Fatalf("%q must not be telescopic", bad)
		}
		if _, err := tl.Decode(bad); err == nil {
			t.Fatalf("decode %q must fail", bad)
		}
	}
}

func TestTelescopicTableBounded(t *testing.T) {
	tl := NewTelescopic(localFQDN)
	for i := 0; i < MaxMappings+10; i++ {
		_, _ = tl.Encode(strings.Repeat("a", 70) + "." + fmtInt(i) + ".mnc002.mcc001.3gppnetwork.org")
	}
	if len(tl.table) > MaxMappings {
		t.Fatalf("table = %d", len(tl.table))
	}
}

func TestRewriteJSONUntouchedWhenNothingChanges(t *testing.T) {
	in := []byte(`{ "a" : 1.50, "u":"/relative", "ip":"https://10.0.0.1/x" }`)
	out, changed, err := rewriteJSON(in, func(h string) (string, error) { return "x." + h, nil })
	if err != nil || changed || string(out) != string(in) {
		t.Fatalf("%v %v %s", err, changed, out)
	}
}

func fx0() *httptest.Server {
	s := httptest.NewUnstartedServer(http.NotFoundHandler())
	s.EnableHTTP2 = true
	s.StartTLS()
	s.Close()
	return s
}

// The upstream NF echoes its own X-Correlation-Id; the client must still see exactly one value.
func TestOutboundCorrelationIDNotDuplicated(t *testing.T) {
	var s seen
	fx := newFixture(t, opts{peerHandler: s.handler(200, map[string]string{HeaderCorrelationID: "01CORR"}, `{}`)})
	req := httptest.NewRequest("GET", "https://"+remoteNF+":8000/nudm-sdm/v2/x", nil)
	req.Header.Set(HeaderCorrelationID, "01CORR")
	rec := do(fx.f.Outbound(), req)
	if got := rec.Header().Values(HeaderCorrelationID); len(got) != 1 || got[0] != "01CORR" {
		t.Fatalf("X-Correlation-Id values = %q, want exactly [01CORR]", got)
	}
}

// A PLMN-less apiRoot header is the offending input: the 400 must point at it, not at :authority.
func TestOutboundPLMNlessHeaderPointsAtHeader(t *testing.T) {
	fx := newFixture(t, opts{localHeader: true, ctx: &n32c.Context{SecCapability: n32c.CapTLS, TargetAPIRootHeader: true}})
	req := httptest.NewRequest("GET", "https://"+localFQDN+":8014/nnrf-disc/v1/nf-instances", nil)
	req.Header.Set(HeaderTargetAPIRoot, "https://hnrf:8000")
	rec := do(fx.f.Outbound(), req)
	if rec.Code != 400 {
		t.Fatalf("got %d, want 400", rec.Code)
	}
	pd := problem(t, rec)
	if len(pd.InvalidParams) != 1 || pd.InvalidParams[0].Param != HeaderTargetAPIRoot {
		t.Fatalf("invalidParams = %+v, want the %s header", pd.InvalidParams, HeaderTargetAPIRoot)
	}
}
