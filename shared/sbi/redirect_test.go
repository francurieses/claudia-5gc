package sbi

// redirect_test.go - ES3XX consumer redirect policy (TS 29.500 §6.10.9.1,
// §6.4.2.4; TS 29.502 §6.1.8 feature 8; TS 29.518 §6.1.8 feature 7).

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// recorded is one request seen by a mock peer.
type recorded struct {
	Method string
	Path   string
	Query  string
	Body   string
	Header http.Header
}

// peer is a mock NF (TLS + h2) recording every request it receives.
type peer struct {
	srv  *httptest.Server
	mu   sync.Mutex
	reqs []recorded
}

func newPeer(t *testing.T, h func(p *peer, w http.ResponseWriter, r *http.Request)) *peer {
	t.Helper()
	p := &peer{}
	p.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		p.mu.Lock()
		p.reqs = append(p.reqs, recorded{r.Method, r.URL.Path, r.URL.RawQuery, string(raw), r.Header.Clone()})
		p.mu.Unlock()
		h(p, w, r)
	}))
	p.srv.EnableHTTP2 = true
	p.srv.StartTLS()
	t.Cleanup(p.srv.Close)
	return p
}

func (p *peer) url() string { return p.srv.URL }

func (p *peer) got() []recorded {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]recorded(nil), p.reqs...)
}

// created answers 201.
func created(_ *peer, w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusCreated) }

func redirectTo(status int, loc string) func(*peer, http.ResponseWriter, *http.Request) {
	return func(_ *peer, w http.ResponseWriter, _ *http.Request) {
		if loc != "" {
			w.Header().Set("Location", loc)
		}
		w.WriteHeader(status)
	}
}

type logBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) { l.mu.Lock(); defer l.mu.Unlock(); return l.b.Write(p) }

func (l *logBuf) records(t *testing.T) []map[string]any {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(l.b.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		out = append(out, m)
	}
	return out
}

func newClient(t *testing.T, p *peer) (*http.Client, *logBuf) {
	t.Helper()
	lb := &logBuf{}
	c := p.srv.Client()
	ApplyRedirectPolicy(c, slog.New(slog.NewJSONHandler(lb, nil)).With("nf", "AMF"))
	return c, lb
}

func post(t *testing.T, c *http.Client, url, body string) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Correlation-Id", "01HCORR")
	req.Header.Set("3gpp-Sbi-Message-Priority", "5")
	return c.Do(req)
}

func TestRedirect307308FollowedPreservesMethodBodyHeaders(t *testing.T) {
	for _, status := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			b := newPeer(t, created)
			a := newPeer(t, func(p *peer, w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", b.url()+r.URL.Path)
				w.Header().Set(HeaderTargetNfID, "nfinst=4947a69a-f61b-4bc1-b9da-47c9c5d12345")
				w.WriteHeader(status)
			})
			c, lb := newClient(t, a)
			resp, err := post(t, c, a.url()+"/nsmf-pdusession/v1/sm-contexts?x=1", `{"k":"v"}`)
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusCreated {
				t.Fatalf("status = %d, want 201", resp.StatusCode)
			}
			ga, gb := a.got(), b.got()
			if len(ga) != 1 || len(gb) != 1 {
				t.Fatalf("requests A=%d B=%d, want 1/1", len(ga), len(gb))
			}
			if gb[0].Method != http.MethodPost || gb[0].Path != "/nsmf-pdusession/v1/sm-contexts" {
				t.Errorf("B got %s %s", gb[0].Method, gb[0].Path)
			}
			if gb[0].Body != ga[0].Body || gb[0].Body != `{"k":"v"}` {
				t.Errorf("body A=%q B=%q", ga[0].Body, gb[0].Body)
			}
			for _, h := range []string{"Content-Type", "X-Correlation-Id", "3gpp-Sbi-Message-Priority"} {
				if ga[0].Header.Get(h) != gb[0].Header.Get(h) || gb[0].Header.Get(h) == "" {
					t.Errorf("header %s A=%q B=%q", h, ga[0].Header.Get(h), gb[0].Header.Get(h))
				}
			}
			if gb[0].Header.Get("Referer") != "" {
				t.Errorf("Referer must not be added, got %q", gb[0].Header.Get("Referer"))
			}

			recs := lb.records(t)
			if len(recs) != 1 {
				t.Fatalf("log records = %d, want 1: %v", len(recs), recs)
			}
			r := recs[0]
			want := map[string]any{
				"nf": "AMF", "procedure": "HttpRedirection", "interface": "Nsmf", "direction": "OUT",
				"spec_ref": RedirectSpecRef, "http_status": float64(status),
				"target_nf_id": "nfinst=4947a69a-f61b-4bc1-b9da-47c9c5d12345", "redirect_count": float64(1),
				"result": "OK", "location": b.url() + "/nsmf-pdusession/v1/sm-contexts",
			}
			for k, v := range want {
				if r[k] != v {
					t.Errorf("log %s = %v, want %v", k, r[k], v)
				}
			}
		})
	}
}

func TestRedirectRelativeLocation(t *testing.T) {
	a := newPeer(t, func(p *peer, w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/alt/") {
			w.WriteHeader(http.StatusCreated)
			return
		}
		w.Header().Set("Location", "/alt"+r.URL.Path)
		w.WriteHeader(http.StatusTemporaryRedirect)
	})
	c, _ := newClient(t, a)
	resp, err := post(t, c, a.url()+"/namf-comm/v1/ue-contexts/x/n1-n2-messages", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	g := a.got()
	if resp.StatusCode != 201 || len(g) != 2 || g[1].Path != "/alt/namf-comm/v1/ue-contexts/x/n1-n2-messages" || g[1].Method != "POST" || g[1].Body != "{}" {
		t.Fatalf("status=%d reqs=%+v", resp.StatusCode, g)
	}
}

func TestRedirectOther3xxNotFollowed(t *testing.T) {
	for _, status := range []int{301, 302, 303} {
		b := newPeer(t, created)
		a := newPeer(t, redirectTo(status, b.url()+"/nsmf-pdusession/v1/sm-contexts"))
		c, lb := newClient(t, a)
		resp, err := post(t, c, a.url()+"/nsmf-pdusession/v1/sm-contexts", `{}`)
		if err != nil {
			t.Fatalf("%d: %v", status, err)
		}
		resp.Body.Close()
		if resp.StatusCode != status || len(a.got()) != 1 || len(b.got()) != 0 {
			t.Errorf("%d: status=%d A=%d B=%d", status, resp.StatusCode, len(a.got()), len(b.got()))
		}
		recs := lb.records(t)
		if len(recs) != 1 || recs[0]["result"] != "FAILURE" || recs[0]["http_status"] != float64(status) || recs[0]["spec_ref"] != RedirectNotFollowedSpecRef {
			t.Errorf("%d: log %v", status, recs)
		}
	}
}

func TestRedirectSCPSEPPRetargetsIgnoringLocation(t *testing.T) {
	cases := []struct {
		name, cause, field, base string
	}{
		{"scp", CauseSCPRedirection, "targetScp", ""},
		{"sepp", CauseSEPPRedirection, "targetSepp", ""},
		{"scp with base path", CauseSCPRedirection, "targetScp", "/apiroot/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := newPeer(t, created)
			var a *peer
			a = newPeer(t, func(_ *peer, w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", a.url()+"/ignored-location")
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTemporaryRedirect)
				_ = json.NewEncoder(w).Encode(map[string]string{"cause": tc.cause, tc.field: b.url() + tc.base})
			})
			c, lb := newClient(t, a)
			resp, err := post(t, c, a.url()+"/nsmf-pdusession/v1/sm-contexts/c1/modify?q=2", `{"a":1}`)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			gb := b.got()
			wantPath := strings.TrimRight(tc.base, "/") + "/nsmf-pdusession/v1/sm-contexts/c1/modify"
			if resp.StatusCode != 201 || len(a.got()) != 1 || len(gb) != 1 {
				t.Fatalf("status=%d A=%d B=%d", resp.StatusCode, len(a.got()), len(gb))
			}
			if gb[0].Path != wantPath || gb[0].Query != "q=2" || gb[0].Method != "POST" || gb[0].Body != `{"a":1}` {
				t.Errorf("B got %+v", gb[0])
			}
			recs := lb.records(t)
			if len(recs) != 1 || recs[0]["cause"] != tc.cause || recs[0]["result"] != "OK" {
				t.Errorf("log %v", recs)
			}
		})
	}
}

func TestRedirectMalformedRedirectResponseFallsBackToLocation(t *testing.T) {
	bodies := map[string]string{
		"scp without targetScp": `{"cause":"SCP_REDIRECTION"}`,
		"invalid json":          `{not json`,
		"unknown cause":         `{"cause":"OTHER","targetScp":"https://x.invalid"}`,
		"targetScp not a uri":   `{"cause":"SCP_REDIRECTION","targetScp":"::::"}`,
		"targetScp no host":     `{"cause":"SCP_REDIRECTION","targetScp":"/only/path"}`,
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			b := newPeer(t, created)
			a := newPeer(t, func(_ *peer, w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", b.url()+r.URL.Path)
				w.WriteHeader(http.StatusTemporaryRedirect)
				_, _ = w.Write([]byte(body))
			})
			c, _ := newClient(t, a)
			resp, err := post(t, c, a.url()+"/nsmf-pdusession/v1/sm-contexts", `{}`)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != 201 || len(b.got()) != 1 {
				t.Fatalf("status=%d B=%d", resp.StatusCode, len(b.got()))
			}
		})
	}
}

func TestRedirectMissingOrUnparsableLocationNotFollowed(t *testing.T) {
	t.Run("missing Location", func(t *testing.T) {
		for _, status := range []int{307, 308} {
			a := newPeer(t, redirectTo(status, ""))
			c, _ := newClient(t, a)
			resp, err := post(t, c, a.url()+"/nsmf-pdusession/v1/sm-contexts", `{}`)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != status || len(a.got()) != 1 {
				t.Errorf("%d: status=%d reqs=%d", status, resp.StatusCode, len(a.got()))
			}
		}
	})
	t.Run("unparsable Location", func(t *testing.T) {
		a := newPeer(t, redirectTo(307, "http://[::1"))
		c, _ := newClient(t, a)
		resp, err := post(t, c, a.url()+"/nsmf-pdusession/v1/sm-contexts", `{}`)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode != 307 {
				t.Fatalf("status = %d, want 307 or error", resp.StatusCode)
			}
		}
		if len(a.got()) != 1 {
			t.Errorf("requests = %d, want 1", len(a.got()))
		}
	})
}

func TestRedirectLoopBounded(t *testing.T) {
	var a, b *peer
	a = newPeer(t, func(_ *peer, w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", b.url()+r.URL.Path)
		w.WriteHeader(http.StatusTemporaryRedirect)
	})
	b = newPeer(t, func(_ *peer, w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", a.url()+r.URL.Path)
		w.WriteHeader(http.StatusTemporaryRedirect)
	})
	c, lb := newClient(t, a)
	resp, err := post(t, c, a.url()+"/nsmf-pdusession/v1/sm-contexts", `{}`)
	if resp != nil {
		resp.Body.Close()
	}
	if err == nil || !errors.Is(err, ErrTooManyRedirects) || !strings.Contains(err.Error(), "too many redirects") {
		t.Fatalf("err = %v, want too many redirects", err)
	}
	if n := len(a.got()) + len(b.got()); n != MaxRedirects+1 {
		t.Errorf("total requests = %d, want %d", n, MaxRedirects+1)
	}
	recs := lb.records(t)
	if len(recs) != MaxRedirects+1 {
		t.Fatalf("log records = %d, want %d", len(recs), MaxRedirects+1)
	}
	if last := recs[len(recs)-1]; last["result"] != "FAILURE" || last["http_status"] != float64(307) || last["spec_ref"] != RedirectLoopSpecRef {
		t.Errorf("last log %v", last)
	}
}

func TestRedirectSchemeDowngradeRefused(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("plain-HTTP target must not be contacted")
		w.WriteHeader(http.StatusCreated)
	}))
	defer plain.Close()
	a := newPeer(t, redirectTo(307, plain.URL+"/nsmf-pdusession/v1/sm-contexts"))
	c, lb := newClient(t, a)
	resp, err := post(t, c, a.url()+"/nsmf-pdusession/v1/sm-contexts", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 307 {
		t.Errorf("status = %d, want 307 returned", resp.StatusCode)
	}
	if recs := lb.records(t); len(recs) != 1 || recs[0]["result"] != "FAILURE" {
		t.Errorf("log %v", recs)
	}
}

func TestRedirectNonReplayableBodyNotFollowed(t *testing.T) {
	b := newPeer(t, created)
	a := newPeer(t, redirectTo(307, b.url()+"/x"))
	c, _ := newClient(t, a)
	req, _ := http.NewRequest(http.MethodPost, a.url()+"/x", io.NopCloser(strings.NewReader("data")))
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 307 || len(b.got()) != 0 {
		t.Errorf("status=%d B=%d", resp.StatusCode, len(b.got()))
	}
}

func TestRedirectInterfaceDerivation(t *testing.T) {
	cases := map[string]string{
		"/nsmf-pdusession/v1/sm-contexts": "Nsmf",
		"/namf-comm/v1/ue-contexts/x":     "Namf",
		"/nudm-sdm/v2/x":                  "Nudm",
		"/nausf-auth/v1/ue-auth":          "Nausf",
		"/npcf-am-policy-control/v1/x":    "Npcf",
		"/nnssf-nsselection/v2/x":         "Nnssf",
		"/nnrf-disc/v1/nf-instances":      "Nnrf",
		"/nnrf-nfm/v1/nf-instances":       "Nnrf",
		"/nsmsf-sms/v2/x":                 "Nsmsf",
		"/oauth2/token":                   "Nnrf",
		"/unknown/x":                      "SBI",
		"/":                               "SBI",
	}
	for path, want := range cases {
		b := newPeer(t, created)
		a := newPeer(t, redirectTo(308, b.url()+path))
		c, lb := newClient(t, a)
		resp, err := post(t, c, a.url()+path, `{}`)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if recs := lb.records(t); len(recs) != 1 || recs[0]["interface"] != want {
			t.Errorf("%s: log %v, want interface %s", path, recs, want)
		}
	}
}
