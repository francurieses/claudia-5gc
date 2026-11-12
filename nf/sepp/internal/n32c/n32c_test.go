package n32c

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/francurieses/claudia-5gc/shared/capability"
)

const (
	localFQDN = "sepp.5gc.mnc002.mcc001.3gppnetwork.org"
	peer1FQDN = "sepp.5gc.mnc001.mcc001.3gppnetwork.org"
	peer3FQDN = "sepp.5gc.mnc003.mcc001.3gppnetwork.org"
	route     = "/n32c-handshake/v1/exchange-capability"
)

var (
	plmnLocal = PlmnId{"001", "02"}
	plmn1     = PlmnId{"001", "01"}
	plmn3     = PlmnId{"001", "03"}
)

type fixture struct {
	svc     *Service
	events  []StoreEvent
	logBuf  *bytes.Buffer
	termMu  sync.Mutex
	termLog []string
}

func newFixture(t *testing.T, profile string, mut ...func(*Config)) *fixture {
	t.Helper()
	p, err := capability.NewProfile(capability.ReleaseConfig{Profile: profile}, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{logBuf: &bytes.Buffer{}}
	cfg := Config{
		LocalPLMN: plmnLocal, LocalFQDN: localFQDN,
		Partners: []PlmnId{plmn1, plmn3}, Profile: p, TargetAPIRootSupported: true,
		Logger: slog.New(slog.NewJSONHandler(f.logBuf, nil)),
		Store:  NewStore(func(e StoreEvent) { f.events = append(f.events, e) }),
		PeerIdentity: func(r *http.Request) (PeerIdentity, error) {
			fq := r.Header.Get("X-Test-Peer")
			pl, err := ParsePLMNFromFQDN(fq)
			if err != nil {
				return PeerIdentity{}, err
			}
			return PeerIdentity{FQDN: fq, PLMN: pl}, nil
		},
		ResponderIdentity: func(*http.Response) (PeerIdentity, error) {
			return PeerIdentity{FQDN: peer1FQDN, PLMN: plmn1}, nil
		},
		Terminator: func(_ context.Context, r PlmnId, reason string) {
			f.termMu.Lock()
			defer f.termMu.Unlock()
			f.termLog = append(f.termLog, reason+":"+r.Key())
		},
	}
	for _, m := range mut {
		m(&cfg)
	}
	f.svc, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) do(t *testing.T, peer, ctype, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, route, strings.NewReader(body))
	if ctype != "" {
		r.Header.Set("Content-Type", ctype)
	}
	r.Header.Set("X-Test-Peer", peer)
	w := httptest.NewRecorder()
	f.svc.Handler().ServeHTTP(w, r)
	return w
}

func (f *fixture) send(t *testing.T, peer, body string) *httptest.ResponseRecorder {
	return f.do(t, peer, "application/json", body)
}

func decode[T any](t *testing.T, w *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode %q: %v", w.Body.String(), err)
	}
	return v
}

func validBody(extra string) string {
	return `{"sender":"` + peer1FQDN + `","supportedSecCapabilityList":["TLS"]` + extra + `}`
}

func TestHappyPathPerProfile(t *testing.T) {
	for _, tc := range []struct {
		profile  string
		features string // expected raw supportedFeatures in the response
	}{{"rel17", ""}, {"rel19", "0"}} {
		t.Run(tc.profile, func(t *testing.T) {
			f := newFixture(t, tc.profile)
			w := f.send(t, peer1FQDN, `{"sender":"`+peer1FQDN+`","supportedSecCapabilityList":["TLS"],
				"3GppSbiTargetApiRootSupported":true,"plmnIdList":[{"mcc":"001","mnc":"01"}],
				"targetPlmnId":{"mcc":"001","mnc":"02"}}`)
			if w.Code != 200 {
				t.Fatalf("status %d %s", w.Code, w.Body)
			}
			rsp := decode[SecNegotiateRspData](t, w)
			if rsp.SelectedSecCapability != CapTLS || rsp.Sender != localFQDN || !rsp.TargetAPIRootSupported ||
				len(rsp.PlmnIDList) != 1 || rsp.PlmnIDList[0] != plmnLocal || rsp.SupportedFeatures != tc.features {
				t.Fatalf("bad rsp %+v", rsp)
			}
			var raw map[string]json.RawMessage
			_ = json.Unmarshal(w.Body.Bytes(), &raw)
			_, has := raw["supportedFeatures"]
			if has != (tc.features != "") {
				t.Fatalf("supportedFeatures presence = %v", has)
			}
			c, ok := f.svc.Store().Get(plmn1)
			if !ok || c.SecCapability != CapTLS || !c.TargetAPIRootHeader || c.PeerFQDN != peer1FQDN {
				t.Fatalf("bad ctx %+v ok=%v", c, ok)
			}
			if !strings.Contains(f.logBuf.String(), `"procedure":"N32cSecurityCapabilityNegotiation"`) ||
				!strings.Contains(f.logBuf.String(), `"result":"OK"`) || !strings.Contains(f.logBuf.String(), `"interface":"N32c"`) {
				t.Fatalf("log missing fields: %s", f.logBuf)
			}
		})
	}
}

func TestTargetAPIRootHeaderMode(t *testing.T) {
	for _, tc := range []struct {
		name, extra string
		local, want bool
	}{
		{"both", `,"3GppSbiTargetApiRootSupported":true`, true, true},
		{"peer false", `,"3GppSbiTargetApiRootSupported":false`, true, false},
		{"peer absent", ``, true, false},
		{"local off", `,"3GppSbiTargetApiRootSupported":true`, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, "rel17", func(c *Config) { c.TargetAPIRootSupported = tc.local })
			w := f.send(t, peer1FQDN, validBody(tc.extra))
			if w.Code != 200 {
				t.Fatal(w.Code)
			}
			if got := decode[SecNegotiateRspData](t, w).TargetAPIRootSupported; got != tc.want {
				t.Fatalf("rsp flag %v", got)
			}
			if c, _ := f.svc.Store().Get(plmn1); c.TargetAPIRootHeader != tc.want {
				t.Fatalf("ctx flag %v", c.TargetAPIRootHeader)
			}
		})
	}
}

func TestUnknownCapabilityAndKeyTolerated(t *testing.T) {
	f := newFixture(t, "rel17")
	w := f.send(t, peer1FQDN, `{"sender":"`+peer1FQDN+`","supportedSecCapabilityList":["FUTURE_CAP","TLS"],"x-future":{"a":1}}`)
	if w.Code != 200 || decode[SecNegotiateRspData](t, w).SelectedSecCapability != CapTLS {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

func TestReplaceDeletesBeforeCreate(t *testing.T) {
	f := newFixture(t, "rel17")
	for i := 0; i < 2; i++ {
		if w := f.send(t, peer1FQDN, validBody("")); w.Code != 200 {
			t.Fatal(w.Code)
		}
	}
	if f.svc.Store().Len() != 1 {
		t.Fatalf("len %d", f.svc.Store().Len())
	}
	var ops []string
	for _, e := range f.events {
		ops = append(ops, e.Op)
	}
	if got := strings.Join(ops, ","); got != "create,delete,create" {
		t.Fatalf("ops %s", got)
	}
	if len(f.termLog) != 1 || f.termLog[0] != "replace:001-001" {
		t.Fatalf("terminator %v", f.termLog)
	}
}

func TestNoneTeardown(t *testing.T) {
	for _, profile := range []string{"rel17", "rel19"} {
		t.Run(profile+" with NFTLST", func(t *testing.T) {
			f := newFixture(t, profile)
			if w := f.send(t, peer1FQDN, validBody(`,"supportedFeatures":"1"`)); w.Code != 200 {
				t.Fatal(w.Code, w.Body)
			}
			if c, _ := f.svc.Store().Get(plmn1); !c.NFTLST {
				t.Fatal("NFTLST not negotiated")
			}
			w := f.send(t, peer1FQDN, `{"sender":"`+peer1FQDN+`","supportedSecCapabilityList":["NONE"]}`)
			if w.Code != 200 || decode[SecNegotiateRspData](t, w).SelectedSecCapability != CapNone {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
			if _, ok := f.svc.Store().Get(plmn1); ok {
				t.Fatal("context not deleted")
			}
			if got := f.termLog[len(f.termLog)-1]; got != "teardown:001-001" {
				t.Fatalf("terminator %v", f.termLog)
			}
		})
	}
	none := `{"sender":"` + peer1FQDN + `","supportedSecCapabilityList":["NONE"]}`
	t.Run("without NFTLST", func(t *testing.T) {
		f := newFixture(t, "rel19")
		f.send(t, peer1FQDN, validBody(""))
		w := f.send(t, peer1FQDN, none)
		if w.Code != 403 || decode[ProblemDetails](t, w).Cause != CauseNegotiationNotAllowed {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
		if _, ok := f.svc.Store().Get(plmn1); !ok {
			t.Fatal("context must survive a rejected NONE")
		}
	})
	t.Run("without context", func(t *testing.T) {
		f := newFixture(t, "rel17")
		if w := f.send(t, peer1FQDN, none); w.Code != 403 {
			t.Fatal(w.Code)
		}
	})
}

func TestRel17NeverEmitsRel19IEs(t *testing.T) {
	f := newFixture(t, "rel17")
	w := f.send(t, peer1FQDN, validBody(`,"n32HandshakeId":"0123456789abcdef","senderN32fFqdn":"n32f.example.org","senderN32fPortList":[8443],"n32KeepaliveTimer":30`))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	for _, k := range []string{"n32HandshakeId", "senderN32fFqdn", "senderN32fPort", "n32KeepaliveTimer", "supportedFeatures"} {
		if strings.Contains(w.Body.String(), k) {
			t.Fatalf("rel17 response contains %s: %s", k, w.Body)
		}
	}
	// Rel-19 IEs are never stored: Context has no field for them (compile-time) and the id is not echoed on rel19 either.
	f19 := newFixture(t, "rel19")
	w = f19.send(t, peer1FQDN, validBody(`,"n32HandshakeId":"0123456789abcdef"`))
	if w.Code != 200 || strings.Contains(w.Body.String(), "n32HandshakeId") {
		t.Fatalf("rel19 must not echo n32HandshakeId (unsupported): %s", w.Body)
	}
}

func TestRejections(t *testing.T) {
	sender := func(s string) string {
		return `"sender":"` + s + `","supportedSecCapabilityList":["TLS"]`
	}
	for _, tc := range []struct {
		name, peer, body, ctype string
		status                  int
		cause, logCause         string
	}{
		{name: "E1 PRINS only", peer: peer1FQDN, body: `{"sender":"` + peer1FQDN + `","supportedSecCapabilityList":["PRINS"]}`, status: 403, cause: CauseNegotiationNotAllowed},
		{name: "E1 unknown only", peer: peer1FQDN, body: `{"sender":"` + peer1FQDN + `","supportedSecCapabilityList":["PRINS","FUTURE_CAP"]}`, status: 403, cause: CauseNegotiationNotAllowed},
		{name: "E2 non partner", peer: "sepp.5gc.mnc099.mcc999.3gppnetwork.org", body: `{` + sender("sepp.5gc.mnc099.mcc999.3gppnetwork.org") + `,"plmnIdList":[{"mcc":"999","mnc":"99"}]}`, status: 403, logCause: "plmn_not_allowed"},
		{name: "E3 sender vs cert", peer: peer1FQDN, body: `{` + sender("sepp.5gc.mnc005.mcc001.3gppnetwork.org") + `,"plmnIdList":[{"mcc":"001","mnc":"05"}]}`, status: 403, logCause: "plmn_mismatch"},
		{name: "E3 plmnIdList vs cert", peer: peer1FQDN, body: `{` + sender(peer1FQDN) + `,"plmnIdList":[{"mcc":"001","mnc":"03"}]}`, status: 403, logCause: "plmn_mismatch"},
		{name: "E3 sender not a 3gpp domain", peer: peer1FQDN, body: `{` + sender("sepp.example.org") + `}`, status: 403, logCause: "plmn_mismatch"},
		{name: "E3 no usable cert", peer: "bogus.example.org", body: validBody(""), status: 403},
		{name: "E4 no sender", peer: peer1FQDN, body: `{"supportedSecCapabilityList":["TLS"]}`, status: 400, cause: CauseMandatoryIEMissing},
		{name: "E4 no list", peer: peer1FQDN, body: `{"sender":"` + peer1FQDN + `"}`, status: 400, cause: CauseMandatoryIEMissing},
		{name: "E4 empty list", peer: peer1FQDN, body: `{"sender":"` + peer1FQDN + `","supportedSecCapabilityList":[]}`, status: 400, cause: CauseMandatoryIEIncorrect},
		{name: "E4 not json", peer: peer1FQDN, body: `{not json`, status: 400, cause: CauseInvalidMsgFormat},
		{name: "E4 empty body", peer: peer1FQDN, body: ``, status: 400, cause: CauseInvalidMsgFormat},
		{name: "E4 bad features", peer: peer1FQDN, body: validBody(`,"supportedFeatures":"zz"`), status: 400, cause: CauseInvalidMsgFormat},
		{name: "415", peer: peer1FQDN, body: validBody(""), ctype: "text/plain", status: 415},
	} {
		for _, profile := range []string{"rel17", "rel19"} {
			t.Run(tc.name+"/"+profile, func(t *testing.T) {
				f := newFixture(t, profile)
				ct := tc.ctype
				if ct == "" {
					ct = "application/json"
				}
				w := f.do(t, tc.peer, ct, tc.body)
				if w.Code != tc.status {
					t.Fatalf("status %d %s", w.Code, w.Body)
				}
				if tc.cause != "" && decode[ProblemDetails](t, w).Cause != tc.cause {
					t.Fatalf("cause: %s", w.Body)
				}
				if f.svc.Store().Len() != 0 {
					t.Fatal("context must not exist after rejection")
				}
				if !strings.Contains(f.logBuf.String(), `"result":"REJECT"`) {
					t.Fatalf("no REJECT log: %s", f.logBuf)
				}
				if tc.logCause != "" && !strings.Contains(f.logBuf.String(), `"cause":"`+tc.logCause+`"`) {
					t.Fatalf("log cause %s missing: %s", tc.logCause, f.logBuf)
				}
				if profile == "rel17" && (w.Code == 307 || w.Code == 409) {
					t.Fatal("rel17 emitted a post-Rel-17 status")
				}
			})
		}
	}
}

func TestCollision(t *testing.T) {
	// Local FQDN is mnc002: it precedes mnc003 (reject incoming, keep own) and follows mnc001 (yield).
	run := func(t *testing.T, profile, peer string) (*fixture, *httptest.ResponseRecorder, context.Context) {
		f := newFixture(t, profile)
		ctx, cancel := context.WithCancelCause(context.Background())
		t.Cleanup(func() { cancel(nil) })
		pl, _ := ParsePLMNFromFQDN(peer)
		f.svc.registerInflight(pl, cancel)
		body := `{"sender":"` + peer + `","supportedSecCapabilityList":["TLS"]}`
		return f, f.send(t, peer, body), ctx
	}
	t.Run("rel19 local precedes: 409 and keeps own", func(t *testing.T) {
		f, w, ctx := run(t, "rel19", peer3FQDN)
		if w.Code != 409 || decode[ProblemDetails](t, w).Cause != CauseExchangeOngoing {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
		if ctx.Err() != nil || f.svc.Store().Len() != 0 {
			t.Fatal("own request must be kept and no context created")
		}
	})
	t.Run("rel19 peer precedes: abandon own, process incoming", func(t *testing.T) {
		f, w, ctx := run(t, "rel19", peer1FQDN)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body)
		}
		if !errors.Is(context.Cause(ctx), ErrAbandoned) {
			t.Fatalf("own request not abandoned: %v", ctx.Err())
		}
		if f.svc.Store().Len() != 1 {
			t.Fatal("incoming not processed")
		}
	})
	t.Run("rel17 has no collision handling", func(t *testing.T) {
		f, w, ctx := run(t, "rel17", peer3FQDN)
		if w.Code != 200 || ctx.Err() != nil || f.svc.Store().Len() != 1 {
			t.Fatalf("%d", w.Code)
		}
	})
}

// ---- client ----------------------------------------------------------------

func peerServer(t *testing.T, profile string) (*httptest.Server, *Service) {
	t.Helper()
	// The remote SEPP is a second Service (mnc001) with the local one as partner.
	p, _ := capability.NewProfile(capability.ReleaseConfig{Profile: profile}, func(string) string { return "" })
	remote, err := New(Config{
		LocalPLMN: plmn1, LocalFQDN: peer1FQDN, Partners: []PlmnId{plmnLocal}, Profile: p,
		TargetAPIRootSupported: true, Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)),
		PeerIdentity: func(*http.Request) (PeerIdentity, error) {
			return PeerIdentity{FQDN: localFQDN, PLMN: plmnLocal}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(remote.Handler())
	t.Cleanup(ts.Close)
	return ts, remote
}

func TestClientExchangeAndTeardown(t *testing.T) {
	for _, profile := range []string{"rel17", "rel19"} {
		t.Run(profile, func(t *testing.T) {
			ts, remote := peerServer(t, profile)
			f := newFixture(t, profile, func(c *Config) { c.HTTPClient = ts.Client() })
			c, err := f.svc.Exchange(context.Background(), ts.URL, plmn1)
			if err != nil {
				t.Fatal(err)
			}
			if c.SecCapability != CapTLS || !c.TargetAPIRootHeader || c.PeerFQDN != peer1FQDN {
				t.Fatalf("ctx %+v", c)
			}
			if !c.NFTLST {
				t.Fatal("NFTLST expected under both profiles (offered and answered)")
			}
			if _, ok := remote.Store().Get(plmnLocal); !ok {
				t.Fatal("responder has no context")
			}
			if len(f.svc.inflight) != 0 {
				t.Fatal("in-flight entry leaked")
			}
			err = f.svc.Teardown(context.Background(), ts.URL, plmn1)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := f.svc.Store().Get(plmn1); ok {
				t.Fatal("initiator context not deleted")
			}
			if _, ok := remote.Store().Get(plmnLocal); ok {
				t.Fatal("responder context not deleted")
			}
		})
	}
}

func TestClientErrors(t *testing.T) {
	serve := func(status int, body string) *httptest.Server {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
			_, _ = io.WriteString(w, body)
		}))
		t.Cleanup(ts.Close)
		return ts
	}
	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   error
	}{
		{"403 negotiation", 403, `{"status":403,"cause":"NEGOTIATION_NOT_ALLOWED"}`, ErrNegotiationNotAllowed},
		{"403 other", 403, `{"status":403}`, ErrForbidden},
		{"409", 409, `{"status":409,"cause":"N32C_EXCHANGE_CAPABILITY_ONGOING"}`, ErrCollision},
		{"500", 500, `{}`, ErrPeerStatus},
		{"selected PRINS", 200, `{"sender":"` + peer1FQDN + `","selectedSecCapability":"PRINS"}`, ErrInvalidSelected},
		{"selected unknown", 200, `{"sender":"` + peer1FQDN + `","selectedSecCapability":"FUTURE"}`, ErrInvalidSelected},
		{"selected NONE", 200, `{"sender":"` + peer1FQDN + `","selectedSecCapability":"NONE"}`, ErrInvalidSelected},
		{"missing selected", 200, `{"sender":"` + peer1FQDN + `"}`, ErrInvalidSelected},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts := serve(tc.status, tc.body)
			f := newFixture(t, "rel19", func(c *Config) { c.HTTPClient = ts.Client() })
			_, err := f.svc.Exchange(context.Background(), ts.URL, plmn1)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err %v, want %v", err, tc.want)
			}
			if f.svc.Store().Len() != 0 {
				t.Fatal("no context on failure")
			}
		})
	}
}

func TestClientAbandonedByIncomingCollision(t *testing.T) {
	release := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer ts.Close()
	defer close(release)
	f := newFixture(t, "rel19", func(c *Config) { c.HTTPClient = ts.Client() })
	errc := make(chan error, 1)
	go func() { _, err := f.svc.Exchange(context.Background(), ts.URL, plmn1); errc <- err }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, ok := f.svc.lookupInflight(plmn1); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("outgoing request never registered")
		}
		time.Sleep(time.Millisecond)
	}
	if w := f.send(t, peer1FQDN, validBody("")); w.Code != 200 { // peer1 precedes local: yield
		t.Fatalf("incoming %d %s", w.Code, w.Body)
	}
	select {
	case err := <-errc:
		if !errors.Is(err, ErrAbandoned) {
			t.Fatalf("err %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("exchange not abandoned")
	}
}

// ---- JSON fixtures ----------------------------------------------------------

func TestJSONRoundTrip(t *testing.T) {
	rel17Req := `{"sender":"a.mnc001.mcc001.3gppnetwork.org","supportedSecCapabilityList":["TLS"],"3GppSbiTargetApiRootSupported":true,"plmnIdList":[{"mcc":"001","mnc":"01"}],"targetPlmnId":{"mcc":"001","mnc":"02"},"intendedUsagePurpose":[{"usagePurpose":"ROAMING"}]}`
	rel19Req := `{"sender":"a.mnc001.mcc001.3gppnetwork.org","n32HandshakeId":"0123456789abcdef","supportedSecCapabilityList":["TLS","FUTURE"],"supportedFeatures":"1","senderN32fFqdn":"n32f.example.org","senderN32fPortList":[8443],"n32KeepaliveTimer":30}`
	rel17Rsp := `{"sender":"b.mnc002.mcc001.3gppnetwork.org","selectedSecCapability":"TLS","3GppSbiTargetApiRootSupported":true,"plmnIdList":[{"mcc":"001","mnc":"02"}],"allowedUsagePurpose":[{"usagePurpose":"ROAMING"}]}`
	rel19Rsp := `{"sender":"b.mnc002.mcc001.3gppnetwork.org","selectedSecCapability":"TLS","n32HandshakeId":"0123456789abcdef","supportedFeatures":"0","senderN32fFqdn":"n32f.example.org","senderN32fPort":8443,"n32KeepaliveTimer":30}`
	check := func(t *testing.T, in string, v any) {
		t.Helper()
		if err := json.Unmarshal([]byte(in), v); err != nil {
			t.Fatal(err)
		}
		out, _ := json.Marshal(v)
		var a, b any
		_ = json.Unmarshal([]byte(in), &a)
		_ = json.Unmarshal(out, &b)
		ab, _ := json.Marshal(a)
		bb, _ := json.Marshal(b)
		if string(ab) != string(bb) {
			t.Fatalf("round trip differs:\n in  %s\n out %s", ab, bb)
		}
	}
	t.Run("rel17 req", func(t *testing.T) { check(t, rel17Req, &SecNegotiateReqData{}) })
	t.Run("rel19 req", func(t *testing.T) { check(t, rel19Req, &SecNegotiateReqData{}) })
	t.Run("rel17 rsp", func(t *testing.T) { check(t, rel17Rsp, &SecNegotiateRspData{}) })
	t.Run("rel19 rsp", func(t *testing.T) { check(t, rel19Rsp, &SecNegotiateRspData{}) })
	t.Run("problem", func(t *testing.T) {
		check(t, `{"title":"Forbidden","status":403,"cause":"NEGOTIATION_NOT_ALLOWED"}`, &ProblemDetails{})
	})
}

func TestParsePLMNFromFQDN(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want PlmnId
		ok   bool
	}{
		{"sepp.5gc.mnc001.mcc001.3gppnetwork.org", PlmnId{"001", "001"}, true},
		{"SEPP.5gc.mnc01.mcc310.3gppnetwork.org.", PlmnId{"310", "01"}, true},
		{"mnc01.mcc001.3gppnetwork.org.evil.com", PlmnId{}, false},
		{"sepp.example.org", PlmnId{}, false},
		{"a.mncxx.mcc001.3gppnetwork.org", PlmnId{}, false},
	} {
		got, err := ParsePLMNFromFQDN(tc.in)
		if (err == nil) != tc.ok || (tc.ok && got != tc.want) {
			t.Errorf("%s: %+v %v", tc.in, got, err)
		}
	}
	if (PlmnId{"001", "01"}).Key() != (PlmnId{"001", "001"}).Key() {
		t.Error("2- and 3-digit MNC must canonicalise equal")
	}
}

// ---- rework pass ---------------------------------------------------------------

func TestClientSendsSupportedFeaturesUnderBothProfiles(t *testing.T) {
	for _, profile := range []string{"rel17", "rel19"} {
		t.Run(profile, func(t *testing.T) {
			var bodies []SecNegotiateReqData
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req SecNegotiateReqData
				_ = json.NewDecoder(r.Body).Decode(&req)
				bodies = append(bodies, req)
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"sender":"`+peer1FQDN+`","selectedSecCapability":"`+string(req.SupportedSecCapabilityList[0])+`"}`)
			}))
			defer ts.Close()
			f := newFixture(t, profile, func(c *Config) { c.HTTPClient = ts.Client() })
			if _, err := f.svc.Exchange(context.Background(), ts.URL, plmn1); err != nil {
				t.Fatal(err)
			}
			if err := f.svc.Teardown(context.Background(), ts.URL, plmn1); err == nil {
				t.Fatal("peer answered no features, NFTLST not negotiated: teardown must be refused")
			} else if !errors.Is(err, ErrTeardownNotAllowed) {
				t.Fatal(err)
			}
			if len(bodies) != 1 || bodies[0].SupportedFeatures != "1" {
				t.Fatalf("request features %+v", bodies)
			}
		})
	}
}

func TestTeardownRequestCarriesFeatures(t *testing.T) {
	ts, _ := peerServer(t, "rel17")
	var got []string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var req SecNegotiateReqData
		_ = json.Unmarshal(b, &req)
		got = append(got, req.SupportedFeatures)
		r.Body = io.NopCloser(bytes.NewReader(b))
		pr, _ := http.NewRequest(http.MethodPost, ts.URL+r.URL.Path, bytes.NewReader(b))
		pr.Header = r.Header.Clone()
		resp, err := http.DefaultClient.Do(pr)
		if err != nil {
			w.WriteHeader(502)
			return
		}
		defer resp.Body.Close()
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	defer proxy.Close()
	f := newFixture(t, "rel17", func(c *Config) { c.HTTPClient = proxy.Client() })
	if _, err := f.svc.Exchange(context.Background(), proxy.URL, plmn1); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Teardown(context.Background(), proxy.URL, plmn1); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "1" || got[1] != "1" {
		t.Fatalf("features in requests: %v", got)
	}
}

func TestErrorResponsesLogStep2b(t *testing.T) {
	f := newFixture(t, "rel17")
	f.send(t, peer1FQDN, `{not json`)
	if !strings.Contains(f.logBuf.String(), `"spec_ref":"TS 29.573 §5.2.2 step 2b"`) {
		t.Fatalf("log: %s", f.logBuf)
	}
}

// flushRec records the order of write, flush and terminator calls.
type flushRec struct {
	*httptest.ResponseRecorder
	order *[]string
}

func (r flushRec) Write(b []byte) (int, error) {
	*r.order = append(*r.order, "write")
	return r.ResponseRecorder.Write(b)
}
func (r flushRec) Flush() { *r.order = append(*r.order, "flush"); r.ResponseRecorder.Flush() }

func TestTerminatorRunsAfterFlushedResponse(t *testing.T) {
	var order []string
	f := newFixture(t, "rel17", func(c *Config) {
		c.Terminator = func(context.Context, PlmnId, string) { order = append(order, "term") }
	})
	do := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, route, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Test-Peer", peer1FQDN)
		w := flushRec{httptest.NewRecorder(), &order}
		f.svc.Handler().ServeHTTP(w, r)
		return w.ResponseRecorder
	}
	do(validBody(`,"supportedFeatures":"1"`))
	order = nil
	do(validBody(""))                                                          // replace: terminator for the old N32-f
	do(`{"sender":"` + peer1FQDN + `","supportedSecCapabilityList":["NONE"]}`) // 403: no NFTLST in replaced ctx
	if got := strings.Join(order, ","); !strings.HasPrefix(got, "write,flush,term") {
		t.Fatalf("order %s", got)
	}
	order = nil
	do(validBody(`,"supportedFeatures":"1"`))
	do(`{"sender":"` + peer1FQDN + `","supportedSecCapabilityList":["NONE"]}`)
	if got := strings.Join(order, ","); !strings.HasSuffix(got, "write,flush,term") {
		t.Fatalf("teardown order %s", got)
	}
}

func TestInflightTokensDoNotClobber(t *testing.T) {
	f := newFixture(t, "rel19")
	var c1, c2 int
	t1 := f.svc.registerInflight(plmn1, func(error) { c1++ })
	t2 := f.svc.registerInflight(plmn1, func(error) { c2++ })
	f.svc.clearInflight(t1)
	if _, ok := f.svc.lookupInflight(plmn1); !ok {
		t.Fatal("clearing the first request removed the second")
	}
	f.svc.abandonInflight(plmn1)
	if c1 != 0 || c2 != 1 {
		t.Fatalf("cancel counts %d %d", c1, c2)
	}
	f.svc.clearInflight(t2)
	if _, ok := f.svc.lookupInflight(plmn1); ok {
		t.Fatal("registry not empty")
	}
}

func TestClientVerifiesResponderBody(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"sender other plmn", `{"sender":"` + peer3FQDN + `","selectedSecCapability":"TLS"}`},
		{"sender not 3gpp", `{"sender":"sepp.example.org","selectedSecCapability":"TLS"}`},
		{"plmnIdList other plmn", `{"sender":"` + peer1FQDN + `","selectedSecCapability":"TLS","plmnIdList":[{"mcc":"001","mnc":"03"}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, tc.body) }))
			defer ts.Close()
			f := newFixture(t, "rel17", func(c *Config) { c.HTTPClient = ts.Client() })
			_, err := f.svc.Exchange(context.Background(), ts.URL, plmn1)
			if !errors.Is(err, ErrResponderIdentity) || f.svc.Store().Len() != 0 {
				t.Fatalf("err %v len %d", err, f.svc.Store().Len())
			}
			if !strings.Contains(f.logBuf.String(), `"result":"FAILURE"`) {
				t.Fatal("no FAILURE log")
			}
		})
	}
}

func TestClientRejectsWhenResponderCertPLMNDiffers(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"sender":"`+peer1FQDN+`","selectedSecCapability":"TLS"}`)
	}))
	defer ts.Close()
	f := newFixture(t, "rel17", func(c *Config) {
		c.HTTPClient = ts.Client()
		c.ResponderIdentity = func(*http.Response) (PeerIdentity, error) {
			return PeerIdentity{FQDN: peer3FQDN, PLMN: plmn3}, nil
		}
	})
	if _, err := f.svc.Exchange(context.Background(), ts.URL, plmn1); !errors.Is(err, ErrResponderIdentity) {
		t.Fatalf("err %v", err)
	}
}

// selfSigned returns a TLS server certificate whose SAN is san.
func selfSigned(t *testing.T, san string) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: san}, DNSNames: []string{san, "localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:   time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, leaf
}

// tlsServer starts a real TLS (HTTP/2) server with handler h and a client that trusts it.
func tlsServer(t *testing.T, san string, h http.Handler, onClose func()) (*httptest.Server, *http.Client) {
	t.Helper()
	cert, leaf := selfSigned(t, san)
	ts := httptest.NewUnstartedServer(h)
	ts.EnableHTTP2 = true
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2"}}
	ts.Config.ConnState = func(_ net.Conn, st http.ConnState) {
		if st == http.StateClosed && onClose != nil {
			onClose()
		}
	}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, ForceAttemptHTTP2: true,
	}}
	return ts, client
}

func TestN32cConnectionClosedAfterTLSSelected(t *testing.T) {
	closed := make(chan struct{}, 4)
	f := newFixture(t, "rel17")
	ts, client := tlsServer(t, localFQDN, f.svc.Handler(), func() { closed <- struct{}{} })
	r, _ := http.NewRequest(http.MethodPost, ts.URL+route, strings.NewReader(validBody("")))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Test-Peer", peer1FQDN)
	resp, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.ProtoMajor != 2 {
		t.Fatalf("status %d proto %d", resp.StatusCode, resp.ProtoMajor)
	}
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("N32-c HTTP/2 connection not terminated after TLS was selected (TS 29.573 §5.2.2)")
	}
}

func TestClientDefaultResponderIdentityFromServerCert(t *testing.T) {
	remote, _ := New(Config{
		LocalPLMN: plmn1, LocalFQDN: peer1FQDN, Partners: []PlmnId{plmnLocal}, TargetAPIRootSupported: true,
		Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)),
		PeerIdentity: func(*http.Request) (PeerIdentity, error) {
			return PeerIdentity{FQDN: localFQDN, PLMN: plmnLocal}, nil
		},
	})
	for _, tc := range []struct {
		san string
		ok  bool
	}{{peer1FQDN, true}, {peer3FQDN, false}} {
		t.Run(tc.san, func(t *testing.T) {
			ts, client := tlsServer(t, tc.san, remote.Handler(), nil)
			f := newFixture(t, "rel17", func(c *Config) { c.HTTPClient = client; c.ResponderIdentity = nil })
			c, err := f.svc.Exchange(context.Background(), ts.URL, plmn1)
			if tc.ok && (err != nil || c.PeerFQDN != peer1FQDN) {
				t.Fatalf("err %v ctx %+v", err, c)
			}
			if !tc.ok && !errors.Is(err, ErrResponderIdentity) {
				t.Fatalf("err %v", err)
			}
		})
	}
	// Plain HTTP carries no server certificate: never trusted.
	plain := httptest.NewServer(remote.Handler())
	defer plain.Close()
	f := newFixture(t, "rel17", func(c *Config) { c.HTTPClient = plain.Client(); c.ResponderIdentity = nil })
	if _, err := f.svc.Exchange(context.Background(), plain.URL, plmn1); !errors.Is(err, ErrResponderIdentity) {
		t.Fatalf("err %v", err)
	}
}

// TestProblemDetailsInvalidParamsJSON checks the 400 body names the offending attribute (TS 29.500 Table 5.2.7.2-1 NOTE 1).
func TestProblemDetailsInvalidParamsJSON(t *testing.T) {
	b, err := json.Marshal(ProblemDetails{Status: 400, Cause: CauseMandatoryIEMissing, InvalidParams: []InvalidParam{{Param: "sender"}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"invalidParams":[{"param":"sender"}]`) {
		t.Fatalf("invalidParams missing: %s", b)
	}
}
