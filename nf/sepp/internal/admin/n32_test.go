package admin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/francurieses/claudia-5gc/nf/sepp/internal/config"
	"github.com/francurieses/claudia-5gc/nf/sepp/internal/n32c"
	"github.com/francurieses/claudia-5gc/nf/sepp/internal/n32trust"
)

var (
	local = n32c.PlmnId{Mcc: "001", Mnc: "01"}
	home  = n32c.PlmnId{Mcc: "001", Mnc: "02"}
	third = n32c.PlmnId{Mcc: "001", Mnc: "03"}
)

type fakeN32 struct {
	store      *n32c.Store
	attempts   map[string]n32c.Attempt
	exchangeTo string
	err        error
}

func (f *fakeN32) Store() *n32c.Store      { return f.store }
func (f *fakeN32) Partners() []n32c.PlmnId { return []n32c.PlmnId{home, third} }
func (f *fakeN32) LocalPLMN() n32c.PlmnId  { return local }
func (f *fakeN32) LocalFQDN() string       { return "sepp.5gc.mnc001.mcc001.3gppnetwork.org" }
func (f *fakeN32) LastAttempt(p n32c.PlmnId) (n32c.Attempt, bool) {
	a, ok := f.attempts[p.Key()]
	return a, ok
}
func (f *fakeN32) Exchange(_ context.Context, apiRoot string, p n32c.PlmnId) (n32c.Context, error) {
	f.exchangeTo = apiRoot
	if f.err != nil {
		return n32c.Context{}, f.err
	}
	c := n32c.Context{RemotePLMN: p, SecCapability: n32c.CapTLS, NFTLST: true, CreatedAt: time.Now()}
	f.store.Replace(c)
	return c, nil
}
func (f *fakeN32) Teardown(_ context.Context, _ string, p n32c.PlmnId) error {
	if f.err != nil {
		return f.err
	}
	f.store.Delete(p)
	return nil
}

func newHandler(f *fakeN32) *Handler {
	return NewHandler(f, Info{
		ReleaseProfile: "rel19", TopologyHiding: true,
		Partners: []config.Partner{{PLMN: config.PLMN{MCC: "001", MNC: "02"}, Source: config.SourceFile,
			N32: config.PartnerN32{CAFile: "/etc/5gc/pki/n32/peers/001-02/ca.crt", Address: "hsepp.n32:8443"}}},
		Anchors: []n32trust.AnchorInfo{{PLMN: "001-02", CAFile: "/etc/5gc/pki/n32/peers/001-02/ca.crt",
			Subject: "CN=n32 ca", NotAfter: time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)}},
	}, slog.New(slog.NewJSONHandler(io.Discard, nil)))
}

func serve(h http.Handler, method, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(method, path, nil))
	return w
}

func TestContextsView(t *testing.T) {
	f := &fakeN32{store: n32c.NewStore(nil), attempts: map[string]n32c.Attempt{
		third.Key(): {At: time.Now(), Role: n32c.RoleResponder, Result: "REJECT", Cause: "plmn_mismatch"},
	}}
	f.store.Replace(n32c.Context{RemotePLMN: home, SecCapability: n32c.CapTLS, TargetAPIRootHeader: true,
		NFTLST: true, PeerFQDN: "sepp.5gc.mnc002.mcc001.3gppnetwork.org", CreatedAt: time.Now()})
	w := serve(newHandler(f), http.MethodGet, ContextsPath)
	if w.Code != 200 {
		t.Fatalf("status %d %s", w.Code, w.Body)
	}
	var v ContextsView
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if v.LocalPLMN != "001/001" || v.Established != 1 || len(v.Partners) != 2 || v.SecurityMode != "TLS" {
		t.Fatalf("view %+v", v)
	}
	h0, h1 := v.Partners[0], v.Partners[1]
	if h0.PLMN != "001/002" || h0.State != stateEstablished || !h0.Initiator || h0.PeerAddress != "hsepp.n32:8443" ||
		!h0.NFTLST || h0.EstablishedAt == nil {
		t.Fatalf("home partner %+v", h0)
	}
	if h1.State != stateNone || h1.Initiator || h1.LastAttempt == nil || h1.LastAttempt.Result != "REJECT" {
		t.Fatalf("third partner %+v", h1)
	}
}

func TestActions(t *testing.T) {
	f := &fakeN32{store: n32c.NewStore(nil)}
	h := newHandler(f)
	if w := serve(h, http.MethodPost, ContextsPath+"/001-02/handshake"); w.Code != 200 {
		t.Fatalf("handshake %d %s", w.Code, w.Body)
	}
	if f.exchangeTo != "https://hsepp.n32:8443" {
		t.Fatalf("dialled %q", f.exchangeTo)
	}
	if _, ok := f.store.Get(home); !ok {
		t.Fatal("context not stored")
	}
	if w := serve(h, http.MethodPost, ContextsPath+"/001-02/teardown"); w.Code != 200 {
		t.Fatalf("teardown %d", w.Code)
	}
	// Partner without an n32.address: responder only.
	if w := serve(h, http.MethodPost, ContextsPath+"/001-03/handshake"); w.Code != http.StatusConflict {
		t.Fatalf("no-peer %d", w.Code)
	}
	f.err = n32c.ErrTeardownNotAllowed
	if w := serve(h, http.MethodPost, ContextsPath+"/001-02/teardown"); w.Code != http.StatusConflict {
		t.Fatalf("teardown not allowed %d", w.Code)
	}
	f.err = errors.New("dial tcp: refused")
	w := serve(h, http.MethodPost, ContextsPath+"/001-02/handshake")
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "N32C_EXCHANGE_FAILED") {
		t.Fatalf("failure %d %s", w.Code, w.Body)
	}
}

func TestBadRequests(t *testing.T) {
	h := newHandler(&fakeN32{store: n32c.NewStore(nil)})
	for _, tc := range []struct {
		method, path string
		status       int
	}{
		{http.MethodPost, ContextsPath, 405},
		{http.MethodGet, ContextsPath + "/001-02/handshake", 405},
		{http.MethodPost, ContextsPath + "/1-2/handshake", 400},
		{http.MethodPost, ContextsPath + "/001-02/reboot", 404},
	} {
		if w := serve(h, tc.method, tc.path); w.Code != tc.status {
			t.Errorf("%s %s = %d, want %d", tc.method, tc.path, w.Code, tc.status)
		}
	}
	if w := serve(NewHandler(nil, Info{}, nil), http.MethodGet, ContextsPath); w.Code != 503 {
		t.Errorf("nil service = %d, want 503", w.Code)
	}
}

func TestPartnersView(t *testing.T) {
	h := newHandler(&fakeN32{store: n32c.NewStore(nil)})
	w := serve(http.HandlerFunc(h.ServePartners), http.MethodGet, PartnersPath)
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	var v struct {
		Partners []map[string]any `json:"partners"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil || len(v.Partners) != 1 {
		t.Fatalf("body %s err=%v", w.Body, err)
	}
	p := v.Partners[0]
	want := map[string]any{"plmn": "001-02", "source": "file", "caFile": "/etc/5gc/pki/n32/peers/001-02/ca.crt",
		"seppFqdn": "sepp.5gc.mnc002.mcc001.3gppnetwork.org", "address": "hsepp.n32:8443",
		"anchorSubject": "CN=n32 ca", "anchorNotAfter": "2030-01-02T03:04:05Z"}
	for k, wv := range want {
		if p[k] != wv {
			t.Errorf("%s = %v, want %v", k, p[k], wv)
		}
	}
	if w := serve(http.HandlerFunc(h.ServePartners), http.MethodPost, PartnersPath); w.Code != 405 {
		t.Errorf("POST = %d, want 405", w.Code)
	}
	// No partners: empty list (not null), works without an N32-c service.
	e := serve(http.HandlerFunc(NewHandler(nil, Info{}, nil).ServePartners), http.MethodGet, PartnersPath)
	if e.Code != 200 || !strings.Contains(e.Body.String(), `"partners":[]`) {
		t.Errorf("empty = %d %s", e.Code, e.Body)
	}
}
