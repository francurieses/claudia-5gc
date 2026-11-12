//go:build functional

// Package features_test contains godog step definitions for the SEPP N32-c
// Security Capability Negotiation (n32_handshake.feature). Run with:
//
//	go test -race -tags=functional ./nf/sepp/tests/...
//
// The scenarios drive the real nf/sepp/internal/n32c Service through an
// httptest server (plain HTTP). The authenticated peer identity is injected
// through Config.PeerIdentity (header X-Test-Peer), which stands in for the
// verified client-certificate SAN. Only the "client without certificate"
// scenario uses real TLS (httptest TLS server with RequireAndVerifyClientCert).
//
// Pending (not implemented, godog.ErrPending): n32f-terminate scenarios (n/a in
// TLS-only mode, no n32fContextId exists), the N32-f ingress rejection after
// teardown (N32-f lands in REL19-9.5) and the optional n32HandshakeId echo
// (SEPP-001 does not support it).
//
// Ref: TS 29.573 §5.2.2, §6.1.4.2; TS 33.501 §13.1.2.
package features_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cucumber/godog"

	"github.com/francurieses/claudia-5gc/nf/sepp/internal/n32c"
	"github.com/francurieses/claudia-5gc/shared/capability"
)

const (
	defaultPeerFQDN = "sepp.5gc.mnc001.mcc001.3gppnetwork.org"
	exchangePath    = "/n32c-handshake/v1/exchange-capability"
	waitDeadline    = 3 * time.Second
)

// syncBuf is a concurrency-safe log sink.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type world struct {
	localPLMN  n32c.PlmnId
	localFQDN  string
	partners   []n32c.PlmnId
	profile    string
	targetRoot bool
	peerFQDN   string

	logs   *syncBuf
	store  *n32c.Store
	events []n32c.StoreEvent
	evMu   sync.Mutex
	termMu sync.Mutex
	terms  []string

	svc *n32c.Service
	srv *httptest.Server

	sent    bool
	status  int
	rawBody []byte
	rspMap  map[string]any

	// collision scenarios
	mock     *httptest.Server
	release  chan struct{}
	relOnce  sync.Once
	received chan struct{}
	exchErr  chan error

	// TLS scenario
	tlsSrv  *httptest.Server
	tlsHits atomic.Int32
	tlsErr  error
}

func (w *world) reset() {
	w.cleanup()
	*w = world{
		localPLMN: n32c.PlmnId{Mcc: "001", Mnc: "02"},
		localFQDN: "sepp.5gc.mnc002.mcc001.3gppnetwork.org",
		profile:   "rel17",
		peerFQDN:  defaultPeerFQDN,
		logs:      &syncBuf{},
	}
	w.store = n32c.NewStore(func(e n32c.StoreEvent) {
		w.evMu.Lock()
		defer w.evMu.Unlock()
		w.events = append(w.events, e)
	})
}

func (w *world) cleanup() {
	if w.release != nil {
		w.relOnce.Do(func() { close(w.release) })
	}
	if w.exchErr != nil {
		select {
		case <-w.exchErr:
		case <-time.After(waitDeadline):
		}
	}
	if w.mock != nil {
		w.mock.Close()
	}
	if w.srv != nil {
		w.srv.Close()
	}
	if w.tlsSrv != nil {
		w.tlsSrv.Close()
	}
}

func parsePLMN(s string) (n32c.PlmnId, error) {
	mcc, mnc, ok := strings.Cut(s, "/")
	if !ok {
		return n32c.PlmnId{}, fmt.Errorf("plmn %q: want mcc/mnc", s)
	}
	return n32c.PlmnId{Mcc: mcc, Mnc: mnc}, nil
}

// ensureService builds the Service and the httptest server on first use.
func (w *world) ensureService() error {
	if w.svc != nil {
		return nil
	}
	p, err := capability.NewProfile(capability.ReleaseConfig{Profile: w.profile}, func(string) string { return "" })
	if err != nil {
		return fmt.Errorf("profile %q: %w", w.profile, err)
	}
	svc, err := n32c.New(n32c.Config{
		LocalPLMN: w.localPLMN, LocalFQDN: w.localFQDN, Partners: w.partners, Profile: p,
		TargetAPIRootSupported: w.targetRoot,
		Logger:                 slog.New(slog.NewJSONHandler(w.logs, nil)),
		Store:                  w.store,
		HTTPClient:             &http.Client{Timeout: 10 * time.Second},
		PeerIdentity: func(r *http.Request) (n32c.PeerIdentity, error) {
			fq := r.Header.Get("X-Test-Peer")
			pl, err := n32c.ParsePLMNFromFQDN(fq)
			if err != nil {
				return n32c.PeerIdentity{}, err
			}
			return n32c.PeerIdentity{FQDN: fq, PLMN: pl}, nil
		},
		Terminator: func(_ context.Context, r n32c.PlmnId, reason string) {
			w.termMu.Lock()
			defer w.termMu.Unlock()
			w.terms = append(w.terms, reason+":"+r.Key())
		},
	})
	if err != nil {
		return fmt.Errorf("new service: %w", err)
	}
	w.svc = svc
	w.srv = httptest.NewServer(svc.Handler())
	return nil
}

func (w *world) post(path, ctype string, body []byte) error {
	if err := w.ensureService(); err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, w.srv.URL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	req.Header.Set("X-Test-Peer", w.peerFQDN)
	resp, err := w.srv.Client().Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", path, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	w.sent, w.status, w.rawBody, w.rspMap = true, resp.StatusCode, b, nil
	var m map[string]any
	if json.Unmarshal(b, &m) == nil {
		w.rspMap = m
	}
	return nil
}

func (w *world) sendJSON(m map[string]any) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return w.post(exchangePath, "application/json", b)
}

// baseBody is a valid SecNegotiateReqData from the peer in the certificate.
func (w *world) baseBody(caps string) map[string]any {
	return map[string]any{
		"sender":                     w.peerFQDN,
		"supportedSecCapabilityList": json.RawMessage(caps),
	}
}

func (w *world) seed(p n32c.PlmnId, nftlst bool) {
	w.store.Replace(n32c.Context{
		RemotePLMN: p, SecCapability: n32c.CapTLS, NFTLST: nftlst,
		PeerFQDN: defaultPeerFQDN, CreatedAt: time.Now(),
	})
	w.evMu.Lock()
	w.events = nil
	w.evMu.Unlock()
}

func jsonEqual(a, b string) (bool, error) {
	var x, y any
	if err := json.Unmarshal([]byte(a), &x); err != nil {
		return false, fmt.Errorf("actual %q: %w", a, err)
	}
	if err := json.Unmarshal([]byte(b), &y); err != nil {
		return false, fmt.Errorf("expected %q: %w", b, err)
	}
	return reflect.DeepEqual(x, y), nil
}

// ---- Background / Given ------------------------------------------------------

func (w *world) localServes(plmn, fqdn string) error {
	p, err := parsePLMN(plmn)
	if err != nil {
		return err
	}
	w.localPLMN, w.localFQDN = p, fqdn
	return nil
}

func (w *world) partnersOnly(plmn string) error {
	p, err := parsePLMN(plmn)
	if err != nil {
		return err
	}
	w.partners = []n32c.PlmnId{p}
	return nil
}

func (w *world) partnersTwo(a, b string) error {
	pa, err := parsePLMN(a)
	if err != nil {
		return err
	}
	pb, err := parsePLMN(b)
	if err != nil {
		return err
	}
	w.partners = []n32c.PlmnId{pa, pb}
	return nil
}

func (w *world) supportsTLSOnly(caps string) error {
	if caps != "TLS" {
		return fmt.Errorf("this increment supports TLS only, scenario states %q", caps)
	}
	return nil
}

// listenerRequiresCert is a documentation step: the injectable PeerIdentity
// stands in for the verified certificate; the real TLS enforcement is
// asserted by the "without a client certificate" scenario.
func (w *world) listenerRequiresCert() error { return nil }

func (w *world) runsWithProfile(profile string) error {
	if w.svc != nil {
		return errors.New("profile must be selected before the service is started")
	}
	w.profile = profile
	return nil
}

func (w *world) peerCertSAN(san string) error {
	w.peerFQDN = san
	return nil
}

func (w *world) supportsTargetAPIRoot() error {
	if w.svc != nil {
		return errors.New("service already started")
	}
	w.targetRoot = true
	return nil
}

func (w *world) supportsFeature(name string) error {
	if name != "NFTLST" {
		return fmt.Errorf("unknown feature %q", name)
	}
	return nil // the Service always implements NFTLST (service.go New)
}

func (w *world) supportsHandshakeID() error {
	return fmt.Errorf("%w: SEPP-001 does not support the N32 handshake identifier (optional, TS 29.573 §5.2.2 step 2a; nf/sepp/CLAUDE.md: never echoed)", godog.ErrPending)
}

// contextExists is both a Given (seed) and a Then (assert).
func (w *world) contextExists(plmn, cap string) error {
	p, err := parsePLMN(plmn)
	if err != nil {
		return err
	}
	if !w.sent {
		if cap != "TLS" {
			return fmt.Errorf("cannot seed capability %q", cap)
		}
		w.seed(p, false)
		return nil
	}
	c, ok := w.store.Get(p)
	if !ok {
		return fmt.Errorf("no N32 context for %s", plmn)
	}
	if string(c.SecCapability) != cap {
		return fmt.Errorf("context capability %q, want %q", c.SecCapability, cap)
	}
	return nil
}

func (w *world) contextWithNFTLST(plmn, state string) error {
	p, err := parsePLMN(plmn)
	if err != nil {
		return err
	}
	w.seed(p, state == "negotiated")
	return nil
}

func (w *world) tornDown(plmn, cap string) error {
	if cap != "NONE" {
		return fmt.Errorf("unsupported teardown capability %q", cap)
	}
	p, err := parsePLMN(plmn)
	if err != nil {
		return err
	}
	w.seed(p, true)
	if err := w.sendJSON(w.baseBody(`["NONE"]`)); err != nil {
		return err
	}
	if w.status != http.StatusOK {
		return fmt.Errorf("teardown status %d: %s", w.status, w.rawBody)
	}
	if _, ok := w.store.Get(p); ok {
		return errors.New("context still present after teardown")
	}
	return nil
}

func (w *world) outgoingAwaiting(peer string) error {
	if w.profile != "rel19" {
		return errors.New("collision handling exists only in the rel19 profile")
	}
	if err := w.ensureService(); err != nil {
		return err
	}
	pl, err := n32c.ParsePLMNFromFQDN(peer)
	if err != nil {
		return err
	}
	w.release = make(chan struct{})
	w.received = make(chan struct{}, 1)
	w.exchErr = make(chan error, 1)
	w.mock = httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case w.received <- struct{}{}:
		default:
		}
		select {
		case <-w.release:
		case <-r.Context().Done():
		}
	}))
	go func() {
		_, err := w.svc.Exchange(context.Background(), w.mock.URL, pl)
		w.exchErr <- err
	}()
	select {
	case <-w.received: // in-flight entry is registered before the POST is sent
		return nil
	case <-time.After(waitDeadline):
		return errors.New("outgoing exchange-capability never reached the mock peer")
	}
}

// ---- When ---------------------------------------------------------------------

func (w *world) postTable(path string, t *godog.Table) error {
	m := map[string]any{}
	for _, row := range t.Rows {
		if len(row.Cells) != 2 {
			return errors.New("table rows need 2 cells")
		}
		k, v := row.Cells[0].Value, row.Cells[1].Value
		if json.Valid([]byte(v)) {
			m[k] = json.RawMessage(v)
		} else {
			m[k] = v
		}
	}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return w.post(path, "application/json", b)
}

func (w *world) postContentType(path, ctype string) error {
	return w.post(path, ctype, []byte("hello"))
}

func (w *world) withCaps(caps string) error { return w.sendJSON(w.baseBody(caps)) }

func (w *world) withCapsNoFeatures(caps string) error { return w.sendJSON(w.baseBody(caps)) }

func (w *world) withCapsUnknownKey(caps, key string) error {
	m := w.baseBody(caps)
	m[key] = "value"
	return w.sendJSON(m)
}

func (w *world) withTargetRoot(caps string) error {
	m := w.baseBody(caps)
	m["3GppSbiTargetApiRootSupported"] = true
	return w.sendJSON(m)
}

func (w *world) withoutTargetRoot(caps string) error { return w.sendJSON(w.baseBody(caps)) }

func (w *world) withRel19IEs() error {
	m := w.baseBody(`["TLS"]`)
	m["n32HandshakeId"] = "0123456789abcdef"
	m["senderN32fFqdn"] = "n32f.example.org"
	m["senderN32fPortList"] = []int{8443}
	m["n32KeepaliveTimer"] = 30
	return w.sendJSON(m)
}

func (w *world) withHandshakeID(id string) error {
	m := w.baseBody(`["TLS"]`)
	m["n32HandshakeId"] = id
	return w.sendJSON(m)
}

func (w *world) withPlmnList(plmns, caps string) error {
	m := w.baseBody(caps)
	m["plmnIdList"] = json.RawMessage(plmns)
	return w.sendJSON(m)
}

func (w *world) withSenderAndPlmnList(sender, plmns string) error {
	m := w.baseBody(`["TLS"]`)
	m["sender"] = sender
	m["plmnIdList"] = json.RawMessage(plmns)
	return w.sendJSON(m)
}

func (w *world) withSenderAndCaps(sender, caps string) error {
	m := w.baseBody(caps)
	m["sender"] = sender
	return w.sendJSON(m)
}

func (w *world) unknownPartner() error {
	w.peerFQDN = "sepp.5gc.mnc099.mcc999.3gppnetwork.org"
	return w.sendJSON(w.baseBody(`["TLS"]`))
}

func (w *world) emptyBody() error { return w.post(exchangePath, "application/json", nil) }

func (w *world) onlyPRINS() error { return w.sendJSON(w.baseBody(`["PRINS"]`)) }

func (w *world) malformed(kind string) error {
	m := w.baseBody(`["TLS"]`)
	switch kind {
	case `no "sender" IE`:
		delete(m, "sender")
	case `no "supportedSecCapabilityList" IE`:
		delete(m, "supportedSecCapabilityList")
	case "an empty supportedSecCapabilityList":
		m["supportedSecCapabilityList"] = json.RawMessage(`[]`)
	case "a body that is not valid JSON":
		return w.post(exchangePath, "application/json", []byte(`{"sender": `))
	default:
		return fmt.Errorf("unknown malformed case %q", kind)
	}
	return w.sendJSON(m)
}

func (w *world) terminatePending(string) error {
	return fmt.Errorf("%w: n32f-terminate is not applicable in TLS-only mode (no n32fContextId exists without PRINS exchange-params; TS 29.573 §5.2.4) and is not implemented", godog.ErrPending)
}

func (w *world) n32fRequestPending(string) error {
	return fmt.Errorf("%w: N32-f ingress is implemented in REL19-9.5; nothing to reject requests yet", godog.ErrPending)
}

// ---- TLS handshake failure ----------------------------------------------------

func (w *world) clientWithoutCert() error {
	svc, err := n32c.New(n32c.Config{
		LocalPLMN: w.localPLMN, LocalFQDN: w.localFQDN, Partners: w.partners,
		Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)),
	})
	if err != nil {
		return err
	}
	inner := svc.Handler()
	w.tlsSrv = httptest.NewUnstartedServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		w.tlsHits.Add(1)
		inner.ServeHTTP(rw, r)
	}))
	w.tlsSrv.TLS = &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  x509.NewCertPool(),
		MinVersion: tls.VersionTLS12,
	}
	w.tlsSrv.StartTLS()
	// Trust the server certificate but present no client certificate.
	client := w.tlsSrv.Client()
	req, err := http.NewRequest(http.MethodPost, w.tlsSrv.URL+exchangePath, strings.NewReader("{}"))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if resp != nil {
		resp.Body.Close()
	}
	w.tlsErr = err
	return nil
}

func (w *world) tlsHandshakeFails() error {
	if w.tlsErr == nil {
		return errors.New("request without a client certificate succeeded")
	}
	return nil
}

func (w *world) noHTTPProcessed() error {
	if n := w.tlsHits.Load(); n != 0 {
		return fmt.Errorf("handler processed %d request(s)", n)
	}
	return nil
}

// ---- Then ---------------------------------------------------------------------

func (w *world) statusIs(code int) error {
	if w.status != code {
		return fmt.Errorf("status %d, want %d (body %s)", w.status, code, w.rawBody)
	}
	return nil
}

func parseCodes(s string) ([]int, error) {
	var out []int
	for _, f := range strings.Split(s, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(f))
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}

func (w *world) statusOneOf(s string) error {
	codes, err := parseCodes(s)
	if err != nil {
		return err
	}
	for _, c := range codes {
		if w.status == c {
			return nil
		}
	}
	return fmt.Errorf("status %d not in %v", w.status, codes)
}

func (w *world) statusNotOneOf(s string) error {
	codes, err := parseCodes(s)
	if err != nil {
		return err
	}
	for _, c := range codes {
		if w.status == c {
			return fmt.Errorf("status %d must not be in %v", w.status, codes)
		}
	}
	return nil
}

func (w *world) rspSelected(cap string) error {
	if w.rspMap == nil {
		return fmt.Errorf("response is not a JSON object: %s", w.rawBody)
	}
	if got, _ := w.rspMap["selectedSecCapability"].(string); got != cap {
		return fmt.Errorf("selectedSecCapability %q, want %q (body %s)", got, cap, w.rawBody)
	}
	return nil
}

func (w *world) rspField(key, expected string) error {
	got, ok := w.rspMap[key]
	if !ok {
		return fmt.Errorf("response has no %q: %s", key, w.rawBody)
	}
	gb, _ := json.Marshal(got)
	eq, err := jsonEqual(string(gb), expected)
	if err != nil {
		return err
	}
	if !eq {
		return fmt.Errorf("response %q = %s, want %s", key, gb, expected)
	}
	return nil
}

func (w *world) rspFieldAbsent(key string) error {
	if _, ok := w.rspMap[key]; ok {
		return fmt.Errorf("response must not carry %q: %s", key, w.rawBody)
	}
	return nil
}

func (w *world) rspNoneOf(list string) error {
	for _, part := range strings.Split(list, ",") {
		k := strings.Trim(strings.TrimSpace(part), `"`)
		if _, ok := w.rspMap[k]; ok {
			return fmt.Errorf("response carries Rel-19-only IE %q: %s", k, w.rawBody)
		}
	}
	return nil
}

func (w *world) rel19IEsNotStored() error {
	p, _ := parsePLMN("001/01")
	c, ok := w.store.Get(p)
	if !ok {
		return errors.New("no context to inspect")
	}
	t := reflect.TypeOf(c)
	for i := 0; i < t.NumField(); i++ {
		n := strings.ToLower(t.Field(i).Name)
		for _, bad := range []string{"handshake", "n32f", "keepalive"} {
			if strings.Contains(n, bad) {
				return fmt.Errorf("N32 context stores Rel-19-only field %s", t.Field(i).Name)
			}
		}
	}
	return nil
}

func (w *world) problemDetails(cause string) error {
	if w.rspMap == nil {
		return fmt.Errorf("body is not a ProblemDetails JSON object: %s", w.rawBody)
	}
	if _, ok := w.rspMap["status"]; !ok {
		return fmt.Errorf("ProblemDetails has no status: %s", w.rawBody)
	}
	if cause != "" {
		if got, _ := w.rspMap["cause"].(string); got != cause {
			return fmt.Errorf("ProblemDetails cause %q, want %q", got, cause)
		}
	}
	return nil
}

func (w *world) noContext(plmn string) error {
	p, err := parsePLMN(plmn)
	if err != nil {
		return err
	}
	if _, ok := w.store.Get(p); ok {
		return fmt.Errorf("N32 context for %s must not exist", plmn)
	}
	return nil
}

func (w *world) exactlyOneContext(plmn string) error {
	p, err := parsePLMN(plmn)
	if err != nil {
		return err
	}
	if _, ok := w.store.Get(p); !ok {
		return fmt.Errorf("no N32 context for %s", plmn)
	}
	if n := w.store.Len(); n != 1 {
		return fmt.Errorf("%d contexts in store, want exactly 1", n)
	}
	return nil
}

func (w *world) deletedBeforeCreated() error {
	w.evMu.Lock()
	defer w.evMu.Unlock()
	ops := make([]string, len(w.events))
	for i, e := range w.events {
		ops[i] = e.Op
	}
	if len(ops) != 2 || ops[0] != "delete" || ops[1] != "create" {
		return fmt.Errorf("store events %v, want [delete create]", ops)
	}
	return nil
}

func (w *world) headerMode(plmn, mode string) error {
	p, err := parsePLMN(plmn)
	if err != nil {
		return err
	}
	c, ok := w.store.Get(p)
	if !ok {
		return fmt.Errorf("no N32 context for %s", plmn)
	}
	if want := mode == "enabled"; c.TargetAPIRootHeader != want {
		return fmt.Errorf("targetApiRoot header mode %v, want %v", c.TargetAPIRootHeader, want)
	}
	return nil
}

func (w *world) logHas(proc, iface, dir, result, cause string) error {
	want := map[string]string{"procedure": proc, "interface": iface, "direction": dir, "result": result, "cause": cause}
	for _, line := range strings.Split(w.logs.String(), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		match := true
		for k, v := range want {
			if v == "" {
				continue
			}
			if got, _ := rec[k].(string); got != v {
				match = false
				break
			}
		}
		if match {
			return nil
		}
	}
	return fmt.Errorf("no SEPP log record matching %v", want)
}

func (w *world) terminatesConnections() error {
	deadline := time.Now().Add(waitDeadline)
	for {
		w.termMu.Lock()
		got := append([]string(nil), w.terms...)
		w.termMu.Unlock()
		for _, t := range got {
			if t == "teardown:001-001" {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("Terminator not called with teardown for 001/01, calls: %v", got)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (w *world) answersOngoing(cause string) error {
	if err := w.statusIs(http.StatusConflict); err != nil {
		return err
	}
	if err := w.problemDetails(cause); err != nil {
		return err
	}
	select {
	case err := <-w.exchErr:
		w.exchErr <- err
		return fmt.Errorf("own outgoing request ended (%v), it must continue", err)
	default:
		return nil
	}
}

func (w *world) abandonsOwn() error {
	select {
	case err := <-w.exchErr:
		w.exchErr <- err
		if !errors.Is(err, n32c.ErrAbandoned) {
			return fmt.Errorf("outgoing request ended with %v, want ErrAbandoned", err)
		}
		return nil
	case <-time.After(waitDeadline):
		return errors.New("outgoing request was not abandoned")
	}
}

// ---- wiring -------------------------------------------------------------------

// InitializeScenario wires all step definitions into the godog scenario context.
func InitializeScenario(sc *godog.ScenarioContext) {
	w := &world{}
	sc.Before(func(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
		w.reset()
		return ctx, nil
	})
	sc.After(func(ctx context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
		w.cleanup()
		return ctx, nil
	})

	// Background
	sc.Step(`^the local SEPP serves PLMN "([^"]+)" with SEPP FQDN "([^"]+)"$`, w.localServes)
	sc.Step(`^the roaming-partner list of the local SEPP contains only PLMN "([^"]+)"$`, w.partnersOnly)
	sc.Step(`^the roaming-partner list of the local SEPP contains PLMNs "([^"]+)" and "([^"]+)"$`, w.partnersTwo)
	sc.Step(`^the local SEPP supports security capabilities "([^"]+)" only$`, w.supportsTLSOnly)
	sc.Step(`^the N32 listener requires and verifies a client certificate$`, w.listenerRequiresCert)

	// Given
	sc.Step(`^the SEPP runs with the "([^"]+)" release profile$`, w.runsWithProfile)
	sc.Step(`^the peer presents a certificate whose SAN is "([^"]+)"$`, w.peerCertSAN)
	sc.Step(`^the local SEPP supports the 3gpp-Sbi-Target-apiRoot header$`, w.supportsTargetAPIRoot)
	sc.Step(`^the local SEPP supports feature "([^"]+)"$`, w.supportsFeature)
	sc.Step(`^the local SEPP supports the N32 handshake identifier$`, w.supportsHandshakeID)
	sc.Step(`^an N32 context exists for remote PLMN "([^"]+)" with security capability "([^"]+)"$`, w.contextExists)
	sc.Step(`^an N32 context exists for remote PLMN "([^"]+)" with security capability "TLS" and feature "NFTLST" (negotiated|not negotiated)$`, w.contextWithNFTLST)
	sc.Step(`^the N32 context for remote PLMN "([^"]+)" was torn down with capability "([^"]+)"$`, w.tornDown)
	sc.Step(`^the local SEPP has an outgoing exchange-capability towards "([^"]+)" awaiting its response$`, w.outgoingAwaiting)

	// When
	sc.Step(`^the peer sends POST "([^"]+)" with SecNegotiateReqData:$`, w.postTable)
	sc.Step(`^the peer sends POST "([^"]+)" with Content-Type "([^"]+)"$`, w.postContentType)
	sc.Step(`^the peer sends exchange-capability with "3GppSbiTargetApiRootSupported" true and capabilities (\[.*\])$`, w.withTargetRoot)
	sc.Step(`^the peer sends exchange-capability without the "3GppSbiTargetApiRootSupported" IE and capabilities (\[.*\])$`, w.withoutTargetRoot)
	sc.Step(`^the peer sends exchange-capability with capabilities (\[.*\]) and an unknown JSON key "([^"]+)"$`, w.withCapsUnknownKey)
	sc.Step(`^the peer sends exchange-capability with capabilities (\[.*\]) and no supportedFeatures$`, w.withCapsNoFeatures)
	sc.Step(`^the peer sends a valid exchange-capability with capabilities (\[.*\])$`, w.withCaps)
	sc.Step(`^the peer sends a valid exchange-capability with sender "([^"]+)" and capabilities (\[.*\])$`, w.withSenderAndCaps)
	sc.Step(`^the peer sends exchange-capability with supportedSecCapabilityList (\[.*\])$`, w.withCaps)
	sc.Step(`^the peer sends exchange-capability including Rel-19 IEs .*$`, w.withRel19IEs)
	sc.Step(`^the peer sends exchange-capability with n32HandshakeId "([^"]+)"$`, w.withHandshakeID)
	sc.Step(`^the peer sends exchange-capability with plmnIdList (\[.*\]) and capabilities (\[.*\])$`, w.withPlmnList)
	sc.Step(`^the peer sends exchange-capability with sender "([^"]+)" and plmnIdList (\[.*\])$`, w.withSenderAndPlmnList)
	sc.Step(`^the peer sends exchange-capability with (no "sender" IE|no "supportedSecCapabilityList" IE|an empty supportedSecCapabilityList|a body that is not valid JSON)$`, w.malformed)
	sc.Step(`^the peer sends an unknown-partner exchange-capability$`, w.unknownPartner)
	sc.Step(`^the peer sends an exchange-capability with an empty body$`, w.emptyBody)
	sc.Step(`^the peer sends exchange-capability with only capability PRINS$`, w.onlyPRINS)
	sc.Step(`^the peer sends n32f-terminate for (?:unknown )?n32fContextId "([^"]*)"$`, w.terminatePending)
	sc.Step(`^the peer sends an N32-f request for PLMN "([^"]+)"$`, w.n32fRequestPending)
	sc.Step(`^a client connects to the N32 listener without presenting a client certificate$`, w.clientWithoutCert)

	// Then
	sc.Step(`^the TLS handshake fails$`, w.tlsHandshakeFails)
	sc.Step(`^no HTTP request is processed$`, w.noHTTPProcessed)
	sc.Step(`^the response status is (\d+)$`, func(c int) error { return w.statusIs(c) })
	sc.Step(`^the response status is one of ([\d, ]+)$`, w.statusOneOf)
	sc.Step(`^the response status is not one of ([\d, ]+)$`, w.statusNotOneOf)
	sc.Step(`^the response body is SecNegotiateRspData with selectedSecCapability "([^"]+)"$`, w.rspSelected)
	sc.Step(`^the response "([^"]+)" is absent when the negotiated set is empty$`, w.rspFieldAbsent)
	sc.Step(`^the response "([^"]+)" is (\[.*\]|true|false|".*")$`, w.rspField)
	sc.Step(`^the response body contains none of (.+)$`, w.rspNoneOf)
	sc.Step(`^the Rel-19-only IEs received are ignored and not stored in the N32 context$`, w.rel19IEsNotStored)
	sc.Step(`^the response body is ProblemDetails(?: with cause "([^"]+)")?$`, w.problemDetails)
	sc.Step(`^no N32 context exists for remote PLMN "([^"]+)"$`, w.noContext)
	sc.Step(`^exactly one N32 context exists for remote PLMN "([^"]+)"$`, w.exactlyOneContext)
	sc.Step(`^the previous N32 context was deleted before the new one was created$`, w.deletedBeforeCreated)
	sc.Step(`^the N32 context for remote PLMN "([^"]+)" has targetApiRoot header mode (enabled|disabled)$`, w.headerMode)
	sc.Step(`^the SEPP log has procedure "([^"]+)"(?: interface "([^"]+)")?(?: direction "([^"]+)")?(?: result "([^"]+)")?(?: cause "([^"]+)")?$`, w.logHas)
	sc.Step(`^the SEPP terminates the N32-c and N32-f TLS connections of that peer$`, w.terminatesConnections)
	sc.Step(`^the local SEPP answers ProblemDetails cause "([^"]+)" and keeps its own request$`, w.answersOngoing)
	sc.Step(`^the local SEPP abandons its own outgoing request$`, w.abandonsOwn)
	sc.Step(`^the N32-f ingress rejects the request with status (\d+)$`, func(int) error {
		return fmt.Errorf("%w: N32-f ingress is implemented in REL19-9.5", godog.ErrPending)
	})
}

func TestFeatures(t *testing.T) {
	suite := godog.TestSuite{
		ScenarioInitializer: InitializeScenario,
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{"n32_handshake.feature"},
			TestingT: t,
		},
	}
	if suite.Run() != 0 {
		t.Fatal("non-zero exit status from godog test suite")
	}
}

func TestMain(m *testing.M) { os.Exit(m.Run()) }
