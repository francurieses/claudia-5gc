package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func putReq(body *strings.Reader) *http.Request {
	r := httptest.NewRequest(http.MethodPut, "/", body)
	r.Header.Set("Content-Type", "application/json")
	return r
}

const okBody = `{"partners":[{"plmn":{"mcc":"001","mnc":"02"},"n32":{}}]}`

func okPartner() RoamingPartner {
	return RoamingPartner{
		PLMN:    PartnerPLMN{MCC: "001", MNC: "02"},
		N32:     PartnerN32{CAFile: "/etc/5gc/pki/n32/peers/001-02/ca.crt", Address: "sepp.5gc.mnc002.mcc001.3gppnetwork.org:8443"},
		HomeNFs: &PartnerHomeNFs{AUSFAPIRoot: "https://ausf.5gc.mnc002.mcc001.3gppnetwork.org:8002"},
	}
}

func TestValidatePartners(t *testing.T) {
	mut := func(f func(p *RoamingPartner)) []RoamingPartner { p := okPartner(); f(&p); return []RoamingPartner{p} }
	for _, tc := range []struct {
		name string
		in   []RoamingPartner
		want string // "" = valid
	}{
		{"valid", []RoamingPartner{okPartner()}, ""},
		{"empty", nil, ""},
		{"mcc short", mut(func(p *RoamingPartner) { p.PLMN.MCC = "01" }), "mcc"},
		{"mnc 1 digit", mut(func(p *RoamingPartner) { p.PLMN.MNC = "2" }), "mnc"},
		{"mnc 3 digits", mut(func(p *RoamingPartner) { p.PLMN.MNC = "002"; p.N32.CAFile = "/etc/5gc/pki/n32/peers/001-002/ca.crt" }), ""},
		{"mnc letters", mut(func(p *RoamingPartner) { p.PLMN.MNC = "0a" }), "mnc"},
		{"no ca", mut(func(p *RoamingPartner) { p.N32.CAFile = "" }), "ca_file"},
		{"relative ca", mut(func(p *RoamingPartner) { p.N32.CAFile = "ca.crt" }), "ca_file"},
		{"ca override", mut(func(p *RoamingPartner) { p.N32.CAFile = "/etc/5gc/pki/sbi/ca.crt" }), "ca_file"},
		{"ca traversal", mut(func(p *RoamingPartner) { p.N32.CAFile = "/etc/5gc/pki/n32/peers/001-02/../../../sbi/ca.crt" }), "ca_file"},
		{"ca other plmn", mut(func(p *RoamingPartner) { p.N32.CAFile = "/etc/5gc/pki/n32/peers/001-03/ca.crt" }), "ca_file"},
		{"smf apiRoot outside domain", mut(func(p *RoamingPartner) { p.HomeNFs.SMFAPIRoot = "https://smf.example.org:8004" }), "smf_api_root"},
		{"smf apiRoot valid", mut(func(p *RoamingPartner) { p.HomeNFs.SMFAPIRoot = "https://smf.5gc.mnc002.mcc001.3gppnetwork.org:8004" }), ""},
		{"apiRoot outside domain", mut(func(p *RoamingPartner) { p.HomeNFs.UDMAPIRoot = "https://udm.example.org:8003" }), "udm_api_root"},
		{"apiRoot wrong mnc", mut(func(p *RoamingPartner) { p.HomeNFs.UDMAPIRoot = "https://udm.5gc.mnc001.mcc001.3gppnetwork.org" }), "udm_api_root"},
		{"apiRoot path", mut(func(p *RoamingPartner) { p.HomeNFs.UDMAPIRoot = "https://udm.5gc.mnc002.mcc001.3gppnetwork.org/x" }), "udm_api_root"},
		{"fqdn outside domain", mut(func(p *RoamingPartner) { p.N32.SEPPFQDN = "sepp.example.org" }), "sepp_fqdn"},
		{"fqdn ok", mut(func(p *RoamingPartner) { p.N32.SEPPFQDN = "sepp1.5gc.mnc002.mcc001.3gppnetwork.org" }), ""},
		{"no address ok", mut(func(p *RoamingPartner) { p.N32.Address = "" }), ""},
		{"address no port", mut(func(p *RoamingPartner) { p.N32.Address = "host" }), "address"},
		{"address url", mut(func(p *RoamingPartner) { p.N32.Address = "https://h:1" }), "address"},
		{"apiRoot http", mut(func(p *RoamingPartner) { p.HomeNFs.UDMAPIRoot = "http://udm.5gc.mnc002.mcc001.3gppnetwork.org:8003" }), "udm_api_root"},
		{"apiRoot junk", mut(func(p *RoamingPartner) { p.HomeNFs.AUSFAPIRoot = "ausf" }), "ausf_api_root"},
		{"duplicate", []RoamingPartner{okPartner(), okPartner()}, "duplicate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePartners(tc.in)
			if tc.want == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("error = %v, want containing %q", err, tc.want)
			}
		})
	}
}

func TestPartnersFileMissingAndRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "partners.yaml")
	got, err := ReadPartnersFile(path)
	if err != nil || got == nil || len(got) != 0 {
		t.Fatalf("missing file: got %v, %v; want empty list", got, err)
	}
	if err := WritePartnersFile(path, []RoamingPartner{okPartner()}); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o644 {
		t.Fatalf("stat = %v, %v; want mode 0644", st, err)
	}
	ents, _ := os.ReadDir(filepath.Dir(path))
	if len(ents) != 1 {
		t.Fatalf("temp file left behind: %v", ents)
	}
	got, err = ReadPartnersFile(path)
	if err != nil || len(got) != 1 || got[0].PLMN.MNC != "02" || got[0].HomeNFs.AUSFAPIRoot == "" {
		t.Fatalf("round trip: %+v, %v", got, err)
	}
	// smf_api_root must survive a portal read/write cycle (it is the H-SMF target of home-routed sessions).
	sp := okPartner()
	sp.HomeNFs.SMFAPIRoot = "https://smf.5gc.mnc002.mcc001.3gppnetwork.org:8004"
	if err := WritePartnersFile(path, []RoamingPartner{sp}); err != nil {
		t.Fatal(err)
	}
	if got, err = ReadPartnersFile(path); err != nil || got[0].HomeNFs.SMFAPIRoot != sp.HomeNFs.SMFAPIRoot {
		t.Fatalf("smf_api_root lost in round trip: %+v, %v", got, err)
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), "ca_file:") || !strings.Contains(string(b), "ausf_api_root:") {
		t.Fatalf("schema keys missing:\n%s", b)
	}
}

func TestPartnersHandlers(t *testing.T) {
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/v1/n32/partners" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"partners":[{"plmn":"001-02","source":"file"}]}`))
	}))
	defer admin.Close()
	fake := &fakeLifecycle{}
	path := filepath.Join(t.TempDir(), "partners.yaml")
	d := Deps{PartnersFile: path, SEPPAdminBase: admin.URL, Lifecycle: fake}

	// GET with missing file.
	rec := httptest.NewRecorder()
	d.handleGetPartners(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"file":[]`) || !strings.Contains(rec.Body.String(), `"source":"file"`) {
		t.Fatalf("GET: %d %s", rec.Code, rec.Body)
	}

	// PUT invalid -> 400, nothing written, nothing restarted.
	rec = httptest.NewRecorder()
	d.handlePutPartners(rec, putReq(strings.NewReader(`{"partners":[{"plmn":{"mcc":"1","mnc":"02"},"n32":{"ca_file":"/x"}}]}`)))
	if rec.Code != 400 || len(fake.calls) != 0 {
		t.Fatalf("invalid PUT: %d %s calls=%v", rec.Code, rec.Body, fake.calls)
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("file written for invalid PUT")
	}

	// PUT valid -> written, sepp and amf restarted.
	rec = httptest.NewRecorder()
	d.handlePutPartners(rec, putReq(strings.NewReader(`{"partners":[{"plmn":{"mcc":"001","mnc":"02"},"n32":{"ca_file":"/etc/5gc/pki/n32/peers/001-02/ca.crt"}}]}`)))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"sepp":"ok"`) || !strings.Contains(rec.Body.String(), `"amf":"ok"`) {
		t.Fatalf("PUT: %d %s", rec.Code, rec.Body)
	}
	if got := strings.Join(fake.calls, ","); !strings.Contains(got, "restart:sepp") || !strings.Contains(got, "restart:amf") {
		t.Fatalf("calls = %s", got)
	}
	if ps, err := ReadPartnersFile(path); err != nil || len(ps) != 1 {
		t.Fatalf("file after PUT: %v %v", ps, err)
	}

	// GET with SEPP admin down -> effective null + reason.
	admin.Close()
	rec = httptest.NewRecorder()
	d.handleGetPartners(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"effective":null`) || !strings.Contains(rec.Body.String(), "effective_reason") {
		t.Fatalf("GET admin down: %d %s", rec.Code, rec.Body)
	}
}

func TestPutPartnersGuards(t *testing.T) {
	fake := &fakeLifecycle{}
	path := filepath.Join(t.TempDir(), "partners.yaml")
	d := Deps{PartnersFile: path, Lifecycle: fake}
	for _, tc := range []struct {
		name, origin, ct string
		code             int
	}{
		{"cross origin", "http://evil.example", "application/json", 403},
		{"wrong content type", "", "application/x-www-form-urlencoded", 403},
		{"no content type", "", "", 403},
		{"same origin", "http://example.com", "application/json; charset=utf-8", 200},
		{"no origin", "", "application/json", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPut, "http://example.com/", strings.NewReader(okBody))
			if tc.ct != "" {
				r.Header.Set("Content-Type", tc.ct)
			}
			if tc.origin != "" {
				r.Header.Set("Origin", tc.origin)
			}
			rec := httptest.NewRecorder()
			d.handlePutPartners(rec, r)
			if rec.Code != tc.code {
				t.Fatalf("code = %d %s, want %d", rec.Code, rec.Body, tc.code)
			}
		})
	}
	ps, _ := ReadPartnersFile(path)
	if len(ps) != 1 || ps[0].N32.CAFile != "/etc/5gc/pki/n32/peers/001-02/ca.crt" {
		t.Fatalf("ca_file not auto-filled: %+v", ps)
	}
}

func TestPutPartnersCAOverrideRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "partners.yaml")
	d := Deps{PartnersFile: path, Lifecycle: &fakeLifecycle{}}
	rec := httptest.NewRecorder()
	d.handlePutPartners(rec, putReq(strings.NewReader(`{"partners":[{"plmn":{"mcc":"001","mnc":"02"},"n32":{"ca_file":"/etc/5gc/pki/sbi/ca.crt"}}]}`)))
	if rec.Code != 400 {
		t.Fatalf("code = %d %s", rec.Code, rec.Body)
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("file written")
	}
}

func TestPutPartnersRestartFailure502(t *testing.T) {
	path := filepath.Join(t.TempDir(), "partners.yaml")
	d := Deps{PartnersFile: path, Lifecycle: &fakeLifecycle{actionErr: errors.New("boom")}}
	rec := httptest.NewRecorder()
	d.handlePutPartners(rec, putReq(strings.NewReader(okBody)))
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), `"saved":true`) || !strings.Contains(rec.Body.String(), "error: ") {
		t.Fatalf("code = %d %s", rec.Code, rec.Body)
	}
	if ps, _ := ReadPartnersFile(path); len(ps) != 1 {
		t.Fatal("file not written")
	}
}

// blockingLifecycle detects overlapping restarts.
type blockingLifecycle struct {
	fakeLifecycle
	mu      sync.Mutex
	active  int
	maxSeen int
}

func (b *blockingLifecycle) Restart(_ context.Context, _ string) error {
	b.mu.Lock()
	b.active++
	if b.active > b.maxSeen {
		b.maxSeen = b.active
	}
	b.mu.Unlock()
	time.Sleep(10 * time.Millisecond)
	b.mu.Lock()
	b.active--
	b.mu.Unlock()
	return nil
}

func TestPutPartnersSerialised(t *testing.T) {
	path := filepath.Join(t.TempDir(), "partners.yaml")
	bl := &blockingLifecycle{}
	d := Deps{PartnersFile: path, Lifecycle: bl}
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := httptest.NewRecorder()
			d.handlePutPartners(rec, putReq(strings.NewReader(okBody)))
			if rec.Code != 200 {
				t.Errorf("code = %d %s", rec.Code, rec.Body)
			}
		}()
	}
	wg.Wait()
	if bl.maxSeen != 1 {
		t.Fatalf("concurrent restarts observed: %d", bl.maxSeen)
	}
}
