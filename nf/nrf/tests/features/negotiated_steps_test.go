//go:build functional

package features_test

// negotiated_steps_test.go - godog steps for nrf_negotiated_features.feature
// (NRF-003). Each scenario starts its own in-process NRF (h2c on a random
// port) under the requested release profile; NFStatusNotify callbacks are
// captured by h2c httptest servers. Ref: TS 29.510 §5.2.2.5, §5.2.2.6,
// §5.3.2.2, §6.1.6.2.2, §6.1.6.2.16, §6.1.9.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/cucumber/godog"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/francurieses/claudia-5gc/nf/nrf/internal/config"
	"github.com/francurieses/claudia-5gc/nf/nrf/internal/registry"
	"github.com/francurieses/claudia-5gc/nf/nrf/internal/server"
	"github.com/francurieses/claudia-5gc/shared/capability"
)

const notifyWait = 5 * time.Second

// negCtx is the per-scenario state.
type negCtx struct {
	srv     *server.Server
	baseURL string
	client  *http.Client

	lastStatus int
	lastHeader http.Header
	lastRaw    []byte
	lastBody   map[string]interface{}

	subs      map[string]chan map[string]interface{}
	notifiers []*httptest.Server
}

func (c *negCtx) stop() {
	if c.srv != nil {
		_ = c.srv.Shutdown(context.Background())
		c.srv = nil
	}
}

func (c *negCtx) start(profile string) error {
	c.stop()
	cfg := &config.Config{}
	cfg.SBI.Address = "127.0.0.1:0"
	cfg.Metrics.Address = "127.0.0.1:0"
	cfg.OAuth2Secret = "test-secret"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv, err := server.New(cfg, registry.NewInMemory(logger), logger)
	if err != nil {
		return fmt.Errorf("start NRF: %w", err)
	}
	p, err := capability.NewProfile(capability.ReleaseConfig{Profile: profile}, func(string) string { return "" })
	if err != nil {
		return fmt.Errorf("release profile %q: %w", profile, err)
	}
	srv.SetProfile(p)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	go func() { _ = srv.ServeH2C(ln) }()
	c.srv = srv
	c.baseURL = "http://" + ln.Addr().String()
	c.client = &http.Client{Timeout: 5 * time.Second}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := c.client.Get(c.baseURL + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("NRF did not become healthy")
}

func (c *negCtx) do(method, path string, body []byte) error {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, c.baseURL+path, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	c.lastStatus = resp.StatusCode
	c.lastHeader = resp.Header
	c.lastRaw, _ = io.ReadAll(resp.Body)
	c.lastBody = nil
	_ = json.Unmarshal(c.lastRaw, &c.lastBody)
	return nil
}

func (c *negCtx) register(id string, profile map[string]interface{}) error {
	b, _ := json.Marshal(profile)
	if err := c.do(http.MethodPut, "/nnrf-nfm/v1/nf-instances/"+id, b); err != nil {
		return err
	}
	if c.lastStatus != http.StatusCreated {
		return fmt.Errorf("register %s: status %d body %s", id, c.lastStatus, c.lastRaw)
	}
	return nil
}

func svcObj(name string) map[string]interface{} {
	return map[string]interface{}{
		"serviceInstanceId": name + "-1",
		"serviceName":       name,
		"versions":          []map[string]string{{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}},
		"scheme":            "https",
		"nfServiceStatus":   "REGISTERED",
	}
}

func amfProfile(id string) map[string]interface{} {
	return map[string]interface{}{"nfInstanceId": id, "nfType": "AMF", "nfStatus": "REGISTERED"}
}

func amfWithServices(id string, names ...string) map[string]interface{} {
	p := amfProfile(id)
	var l []map[string]interface{}
	for _, n := range names {
		l = append(l, svcObj(n))
	}
	p["nfServices"] = l
	return p
}

// ---- Background / registration ----

func (c *negCtx) cleanNRF(profile string) error { return c.start(profile) }

func (c *negCtx) registeredTwo(id, a, b string) error {
	return c.register(id, amfWithServices(id, a, b))
}

func (c *negCtx) registeredOne(id, a string) error {
	return c.register(id, amfWithServices(id, a))
}

func (c *negCtx) registeredMapUnknown(id, k1, k2, ext string) error {
	p := amfProfile(id)
	m := map[string]interface{}{}
	for _, k := range []string{k1, k2} {
		s := svcObj("namf-comm")
		s["serviceInstanceId"] = k
		s[ext] = "x-" + k
		m[k] = s
	}
	p["nfServiceList"] = m
	return c.register(id, p)
}

// ---- Discovery / retrieve ----

func (c *negCtx) discover(rf string) error {
	q := "/nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=SMF"
	if rf != "" {
		q += "&requester-features=" + rf
	}
	return c.do(http.MethodGet, q, nil)
}

func (c *negCtx) discoverWith(rf string) error { return c.discover(rf) }
func (c *negCtx) discoverWithout() error       { return c.discover("") }
func (c *negCtx) retrieveWith(id, rf string) error {
	return c.do(http.MethodGet, "/nnrf-nfm/v1/nf-instances/"+id+"?requester-features="+rf, nil)
}
func (c *negCtx) retrieveWithout(id string) error {
	return c.do(http.MethodGet, "/nnrf-nfm/v1/nf-instances/"+id, nil)
}

func (c *negCtx) firstInstance() (map[string]interface{}, error) {
	l, _ := c.lastBody["nfInstances"].([]interface{})
	if len(l) != 1 {
		return nil, fmt.Errorf("expected exactly 1 nfInstance, got %d (body %s)", len(l), c.lastRaw)
	}
	m, ok := l[0].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("nfInstance is not an object")
	}
	return m, nil
}

// ---- generic response assertions ----

func (c *negCtx) status(code int) error {
	if c.lastStatus != code {
		return fmt.Errorf("expected status %d, got %d (body %s)", code, c.lastStatus, c.lastRaw)
	}
	return nil
}

func (c *negCtx) contentType(want string) error {
	if got := c.lastHeader.Get("Content-Type"); got != want {
		return fmt.Errorf("expected Content-Type %q, got %q", want, got)
	}
	return nil
}

func (c *negCtx) cause(want string) error {
	if got, _ := c.lastBody["cause"].(string); got != want {
		return fmt.Errorf("expected cause %q, got %q (body %s)", want, got, c.lastRaw)
	}
	return nil
}

func (c *negCtx) invalidParam(want string) error {
	l, _ := c.lastBody["invalidParams"].([]interface{})
	for _, e := range l {
		if m, ok := e.(map[string]interface{}); ok && m["param"] == want {
			return nil
		}
	}
	return fmt.Errorf("invalidParams does not contain param %q (body %s)", want, c.lastRaw)
}

// ---- profile shape assertions (shared by discovery / retrieve / notify) ----

func keysOf(m map[string]interface{}) []string {
	var k []string
	for x := range m {
		k = append(k, x)
	}
	sort.Strings(k)
	return k
}

func hasKey(m map[string]interface{}, k string) bool { _, ok := m[k]; return ok }

func assertServiceList(p map[string]interface{}, ids ...string) error {
	if hasKey(p, "nfServices") {
		return fmt.Errorf("profile carries nfServices alongside nfServiceList")
	}
	l, ok := p["nfServiceList"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("profile has no nfServiceList object: %v", p)
	}
	want := append([]string(nil), ids...)
	sort.Strings(want)
	if got := keysOf(l); !reflect.DeepEqual(got, want) {
		return fmt.Errorf("nfServiceList keys %v, want %v", got, want)
	}
	for k, v := range l {
		if sv, _ := v.(map[string]interface{}); sv["serviceInstanceId"] != k {
			return fmt.Errorf("nfServiceList[%q].serviceInstanceId = %v", k, sv["serviceInstanceId"])
		}
	}
	return nil
}

func assertServicesArray(p map[string]interface{}) ([]interface{}, error) {
	if hasKey(p, "nfServiceList") {
		return nil, fmt.Errorf("profile carries nfServiceList alongside nfServices")
	}
	l, ok := p["nfServices"].([]interface{})
	if !ok || len(l) == 0 {
		return nil, fmt.Errorf("profile has no non-empty nfServices array: %v", p)
	}
	return l, nil
}

func (c *negCtx) searchServiceList(a, b string) error {
	p, err := c.firstInstance()
	if err != nil {
		return err
	}
	return assertServiceList(p, a, b)
}

func (c *negCtx) searchNoServices() error {
	p, err := c.firstInstance()
	if err != nil {
		return err
	}
	if hasKey(p, "nfServices") {
		return fmt.Errorf("nfInstance still has nfServices")
	}
	return nil
}

func (c *negCtx) searchNoServiceList() error {
	p, err := c.firstInstance()
	if err != nil {
		return err
	}
	if hasKey(p, "nfServiceList") {
		return fmt.Errorf("nfInstance still has nfServiceList")
	}
	return nil
}

func (c *negCtx) searchNrfFeatures() error {
	if s, _ := c.lastBody["nrfSupportedFeatures"].(string); s == "" {
		return fmt.Errorf("SearchResult has no nrfSupportedFeatures (body %s)", c.lastRaw)
	}
	return nil
}

func (c *negCtx) searchServicesOrdered(a, b string) error {
	p, err := c.firstInstance()
	if err != nil {
		return err
	}
	l, err := assertServicesArray(p)
	if err != nil {
		return err
	}
	var got []string
	for _, e := range l {
		m, _ := e.(map[string]interface{})
		id, _ := m["serviceInstanceId"].(string)
		got = append(got, id)
	}
	if !reflect.DeepEqual(got, []string{a, b}) {
		return fmt.Errorf("nfServices order %v, want [%s %s]", got, a, b)
	}
	return nil
}

func (c *negCtx) searchUnknownAttr(attr string) error {
	p, err := c.firstInstance()
	if err != nil {
		return err
	}
	l, err := assertServicesArray(p)
	if err != nil {
		return err
	}
	for _, e := range l {
		m, _ := e.(map[string]interface{})
		if !hasKey(m, attr) {
			return fmt.Errorf("service %v lost unknown attribute %q", m["serviceInstanceId"], attr)
		}
	}
	return nil
}

func (c *negCtx) retrievedList() error {
	if err := c.status(http.StatusOK); err != nil {
		return err
	}
	return assertServiceList(c.lastBody, "namf-comm-1", "namf-evts-1")
}

func (c *negCtx) retrievedArray() error {
	if err := c.status(http.StatusOK); err != nil {
		return err
	}
	l, err := assertServicesArray(c.lastBody)
	if err != nil {
		return err
	}
	if len(l) != 2 {
		return fmt.Errorf("expected 2 nfServices, got %d", len(l))
	}
	return nil
}

// ---- subscribers & notifications ----

func (c *negCtx) addSubscriber(name, rf, nfType string) error {
	if c.subs == nil {
		c.subs = map[string]chan map[string]interface{}{}
	}
	ch := make(chan map[string]interface{}, 8)
	c.subs[name] = ch
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m map[string]interface{}
		if json.Unmarshal(b, &m) == nil {
			select {
			case ch <- m:
			default:
			}
		}
		w.WriteHeader(http.StatusNoContent)
	})
	ts := httptest.NewUnstartedServer(h2c.NewHandler(h, &http2.Server{}))
	ts.Start()
	c.notifiers = append(c.notifiers, ts)
	req := map[string]interface{}{"nfStatusNotificationUri": ts.URL + "/notify", "reqNfType": nfType}
	if rf != "" {
		req["requesterFeatures"] = rf
	}
	b, _ := json.Marshal(req)
	if err := c.do(http.MethodPost, "/nnrf-nfm/v1/subscriptions", b); err != nil {
		return err
	}
	return c.status(http.StatusCreated)
}

func (c *negCtx) subscriberWithFeatures(name, rf, nfType string) error {
	return c.addSubscriber(name, rf, nfType)
}
func (c *negCtx) subscriberNoFeatures(name, nfType string) error {
	return c.addSubscriber(name, "", nfType)
}

func (c *negCtx) sendProfileServices(id, svc string) error {
	return c.register(id, amfWithServices(id, svc))
}

func (c *negCtx) sendProfileFqdn(id string) error {
	const f = "amf.5gc.mnc099.mcc999.3gppnetwork.org"
	p := amfWithServices(id, "namf-comm")
	p["interPlmnFqdn"] = f
	p["nfServices"].([]map[string]interface{})[0]["interPlmnFqdn"] = f
	return c.register(id, p)
}

// notified waits (bounded) for the next NFStatusNotify of a subscriber and
// returns its nfProfile.
func (c *negCtx) notified(name string) (map[string]interface{}, error) {
	ch, ok := c.subs[name]
	if !ok {
		return nil, fmt.Errorf("unknown subscriber %q", name)
	}
	select {
	case m := <-ch:
		if m["event"] != "NF_REGISTERED" {
			return nil, fmt.Errorf("subscriber %q: event %v, want NF_REGISTERED", name, m["event"])
		}
		p, ok := m["nfProfile"].(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("subscriber %q: notification has no nfProfile: %v", name, m)
		}
		return p, nil
	case <-time.After(notifyWait):
		return nil, fmt.Errorf("subscriber %q: no NFStatusNotify within %s", name, notifyWait)
	}
}

func (c *negCtx) notifiedList(name string) error {
	p, err := c.notified(name)
	if err != nil {
		return err
	}
	return assertServiceList(p, "namf-comm-1")
}

func (c *negCtx) notifiedArray(name string) error {
	p, err := c.notified(name)
	if err != nil {
		return err
	}
	_, err = assertServicesArray(p)
	return err
}

func fqdnPresence(p map[string]interface{}) (profile, service bool) {
	profile = hasKey(p, "interPlmnFqdn")
	// "5" negotiates Service-Map too, so services may be an array or a map.
	if l, ok := p["nfServices"].([]interface{}); ok && len(l) > 0 {
		m, _ := l[0].(map[string]interface{})
		service = hasKey(m, "interPlmnFqdn")
	}
	if l, ok := p["nfServiceList"].(map[string]interface{}); ok && len(l) > 0 {
		for _, v := range l {
			m, _ := v.(map[string]interface{})
			service = hasKey(m, "interPlmnFqdn")
		}
	}
	return
}

func (c *negCtx) notifiedNoFqdn(name string) error {
	p, err := c.notified(name)
	if err != nil {
		return err
	}
	if _, err := assertServicesArray(p); err != nil {
		return err
	}
	if pr, sv := fqdnPresence(p); pr || sv {
		return fmt.Errorf("subscriber %q: interPlmnFqdn present (profile=%v service=%v)", name, pr, sv)
	}
	return nil
}

func (c *negCtx) notifiedKeepsFqdn(name string) error {
	p, err := c.notified(name)
	if err != nil {
		return err
	}
	if pr, sv := fqdnPresence(p); !pr || !sv {
		return fmt.Errorf("subscriber %q: interPlmnFqdn dropped (profile=%v service=%v)", name, pr, sv)
	}
	return nil
}

// ---- NFStatusSubscribe ----

func (c *negCtx) postSub(m map[string]interface{}) error {
	b, _ := json.Marshal(m)
	return c.do(http.MethodPost, "/nnrf-nfm/v1/subscriptions", b)
}

func (c *negCtx) subFull(uri, nfType, vt, rf string) error {
	return c.postSub(map[string]interface{}{
		"nfStatusNotificationUri": uri, "reqNfType": nfType, "validityTime": vt, "requesterFeatures": rf})
}

func (c *negCtx) subURIOnly(uri string) error {
	return c.postSub(map[string]interface{}{"nfStatusNotificationUri": uri})
}

func (c *negCtx) subBad(kind string) error {
	if kind == "malformed JSON body" {
		return c.do(http.MethodPost, "/nnrf-nfm/v1/subscriptions", []byte("{"))
	}
	return c.postSub(map[string]interface{}{"reqNfType": "AMF"})
}

func (c *negCtx) subEchoes(uri, nfType string) error {
	if c.lastBody["nfStatusNotificationUri"] != uri || c.lastBody["reqNfType"] != nfType {
		return fmt.Errorf("SubscriptionData does not echo request: %s", c.lastRaw)
	}
	return nil
}

func (c *negCtx) subID() (string, error) {
	id, _ := c.lastBody["subscriptionId"].(string)
	if id == "" {
		return "", fmt.Errorf("SubscriptionData has no subscriptionId: %s", c.lastRaw)
	}
	return id, nil
}

func (c *negCtx) subHasID() error { _, err := c.subID(); return err }

func (c *negCtx) subValidity(want string) error {
	if got, _ := c.lastBody["validityTime"].(string); got != want {
		return fmt.Errorf("validityTime %q, want %q", got, want)
	}
	return nil
}

func (c *negCtx) subValidityFuture() error {
	got, _ := c.lastBody["validityTime"].(string)
	t, err := time.Parse(time.RFC3339, got)
	if err != nil {
		return fmt.Errorf("validityTime %q is not an RFC 3339 DateTime: %w", got, err)
	}
	if !t.After(time.Now()) {
		return fmt.Errorf("validityTime %q is not in the future", got)
	}
	return nil
}

func (c *negCtx) subNrfFeatures(want string) error {
	if got, _ := c.lastBody["nrfSupportedFeatures"].(string); got != want {
		return fmt.Errorf("nrfSupportedFeatures %q, want %q", got, want)
	}
	return nil
}

func (c *negCtx) subNoRequesterFeatures() error {
	if hasKey(c.lastBody, "requesterFeatures") {
		return fmt.Errorf("SubscriptionData echoes writeOnly requesterFeatures: %s", c.lastRaw)
	}
	return nil
}

func (c *negCtx) locationEnds(prefix string) error {
	id, err := c.subID()
	if err != nil {
		return err
	}
	if loc := c.lastHeader.Get("Location"); !strings.HasSuffix(loc, prefix+id) {
		return fmt.Errorf("Location %q does not end with %q", loc, prefix+id)
	}
	return nil
}

func (c *negCtx) onlySubscriptionID() error {
	if got := keysOf(c.lastBody); !reflect.DeepEqual(got, []string{"subscriptionId"}) {
		return fmt.Errorf("legacy body attributes %v, want only [subscriptionId]", got)
	}
	return nil
}

func (c *negCtx) exactlyAsRegistered() error {
	p, err := c.firstInstance()
	if err != nil {
		return err
	}
	l, err := assertServicesArray(p)
	if err != nil {
		return err
	}
	if m, _ := l[0].(map[string]interface{}); len(l) != 1 || m["serviceInstanceId"] != "namf-comm-1" {
		return fmt.Errorf("rel17 nfServices differ from registration: %v", l)
	}
	return nil
}

// InitializeNegotiatedScenario registers the steps of
// nrf_negotiated_features.feature.
func InitializeNegotiatedScenario(sc *godog.ScenarioContext) {
	c := &negCtx{}
	sc.After(func(ctx context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
		c.stop()
		for _, n := range c.notifiers {
			n.Close()
		}
		return ctx, nil
	})

	sc.Step(`^a clean NRF instance is running with release profile "([^"]+)"$`, c.cleanNRF)
	sc.Step(`^an NF profile for AMF with instance id "([^"]+)" registered with nfServices "([^"]+)" and "([^"]+)"$`, c.registeredTwo)
	sc.Step(`^an NF profile for AMF with instance id "([^"]+)" registered with nfServices "([^"]+)"$`, c.registeredOne)
	sc.Step(`^an NF profile for AMF with instance id "([^"]+)" registered with nfServiceList keys "([^"]+)" and "([^"]+)" and unknown nested service attribute "([^"]+)"$`, c.registeredMapUnknown)

	sc.Step(`^an SMF queries NFDiscover for AMFs with requester-features "([^"]+)"$`, c.discoverWith)
	sc.Step(`^an SMF queries NFDiscover for AMFs without requester-features$`, c.discoverWithout)
	sc.Step(`^the consumer retrieves NF profile "([^"]+)" with requester-features "([^"]+)"$`, c.retrieveWith)
	sc.Step(`^the consumer retrieves NF profile "([^"]+)" without requester-features$`, c.retrieveWithout)

	sc.Step(`^the NRF responds with status (\d+) (?:OK|Created|Bad Request)$`, func(n int) error { return c.status(n) })
	sc.Step(`^the response content type is "([^"]+)"$`, c.contentType)
	sc.Step(`^the cause is "([^"]+)"$`, c.cause)
	sc.Step(`^the invalidParams contains param "([^"]+)"$`, c.invalidParam)

	sc.Step(`^the SearchResult nfInstance has nfServiceList keyed by serviceInstanceId "([^"]+)" and "([^"]+)"$`, c.searchServiceList)
	sc.Step(`^the SearchResult nfInstance has no nfServices$`, c.searchNoServices)
	sc.Step(`^the SearchResult nfInstance has no nfServiceList$`, c.searchNoServiceList)
	sc.Step(`^the SearchResult nrfSupportedFeatures is present$`, c.searchNrfFeatures)
	sc.Step(`^the SearchResult nfInstance has nfServices ordered "([^"]+)", "([^"]+)"$`, c.searchServicesOrdered)
	sc.Step(`^every returned NFService still carries the unknown attribute "([^"]+)"$`, c.searchUnknownAttr)
	sc.Step(`^the retrieved profile has nfServiceList and no nfServices$`, c.retrievedList)
	sc.Step(`^the retrieved profile has nfServices and no nfServiceList$`, c.retrievedArray)
	sc.Step(`^the SearchResult nfInstance is returned exactly as registered with nfServices and no nfServiceList$`, c.exactlyAsRegistered)

	sc.Step(`^a subscriber "([^"]+)" with nfStatusNotificationUri and requesterFeatures "([^"]+)" for NF type "([^"]+)"$`, c.subscriberWithFeatures)
	sc.Step(`^a subscriber "([^"]+)" with nfStatusNotificationUri and no requesterFeatures for NF type "([^"]+)"$`, c.subscriberNoFeatures)
	sc.Step(`^an NF profile for AMF with instance id "([^"]+)" registered with nfServices "([^"]+)" is sent to the NRF$`, c.sendProfileServices)
	sc.Step(`^an NF profile for AMF with instance id "([^"]+)" with interPlmnFqdn at profile and service level is sent to the NRF$`, c.sendProfileFqdn)
	sc.Step(`^subscriber "([^"]+)" is notified with an nfProfile carrying nfServiceList and no nfServices$`, c.notifiedList)
	sc.Step(`^subscriber "([^"]+)" is notified with an nfProfile carrying nfServices and no nfServiceList$`, c.notifiedArray)
	sc.Step(`^subscriber "([^"]+)" is notified with an nfProfile without interPlmnFqdn at profile or service level$`, c.notifiedNoFqdn)
	sc.Step(`^subscriber "([^"]+)" is notified with an nfProfile that keeps interPlmnFqdn at profile and service level$`, c.notifiedKeepsFqdn)

	sc.Step(`^a consumer sends NFStatusSubscribe with nfStatusNotificationUri "([^"]+)", reqNfType "([^"]+)", validityTime "([^"]+)" and requesterFeatures "([^"]+)"$`, c.subFull)
	sc.Step(`^a consumer sends NFStatusSubscribe with nfStatusNotificationUri "([^"]+)" and (?:no validityTime|no requesterFeatures)$`, c.subURIOnly)
	sc.Step(`^a consumer sends NFStatusSubscribe with a (body without nfStatusNotificationUri|malformed JSON body)$`, c.subBad)
	sc.Step(`^the SubscriptionData body echoes nfStatusNotificationUri "([^"]+)" and reqNfType "([^"]+)"$`, c.subEchoes)
	sc.Step(`^the SubscriptionData body has a subscriptionId$`, c.subHasID)
	sc.Step(`^the SubscriptionData body has validityTime "([^"]+)"$`, c.subValidity)
	sc.Step(`^the SubscriptionData body has a validityTime in the future$`, c.subValidityFuture)
	sc.Step(`^the SubscriptionData body has nrfSupportedFeatures "([^"]+)"$`, c.subNrfFeatures)
	sc.Step(`^the SubscriptionData body does not echo requesterFeatures$`, c.subNoRequesterFeatures)
	sc.Step(`^the Location header ends with "([^"]+)" followed by the subscriptionId$`, c.locationEnds)
	sc.Step(`^the subscribe response body contains only the attribute "subscriptionId"$`, c.onlySubscriptionID)
}

func TestNegotiatedFeatures(t *testing.T) {
	suite := godog.TestSuite{
		ScenarioInitializer: InitializeNegotiatedScenario,
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{"./nrf_negotiated_features.feature"},
			Strict:   true,
			TestingT: t,
		},
	}
	if suite.Run() != 0 {
		t.Fatal("non-zero exit status from godog negotiated-features suite")
	}
}
