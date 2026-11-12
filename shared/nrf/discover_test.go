package nrf

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

func TestDiscoverSupportedFeaturesParam(t *testing.T) {
	var mu sync.Mutex
	var gotPath string
	var gotQuery url.Values
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotPath, gotQuery = r.URL.Path, r.URL.Query()
		calls++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"validityPeriod":60,"nfInstances":[],"nrfSupportedFeatures":"3","searchId":"s1"}`))
	}))
	defer srv.Close()
	c := testClient(srv.URL)

	tests := []struct {
		name      string
		q         DiscoveryQuery
		wantErr   bool
		wantQuery url.Values
	}{
		{
			name: "single service with both feature params",
			q: DiscoveryQuery{TargetNFType: "UDM", RequesterNFType: "AMF",
				ServiceNames: []string{"nudm-sdm"}, SupportedFeatures: "1f", RequesterFeatures: "a3"},
			wantQuery: url.Values{"target-nf-type": {"UDM"}, "requester-nf-type": {"AMF"},
				"service-names": {"nudm-sdm"}, "supported-features": {"1f"}, "requester-features": {"a3"}},
		},
		{
			name: "multiple services comma-joined, no supported-features",
			q: DiscoveryQuery{TargetNFType: "SMF", RequesterNFType: "AMF",
				ServiceNames: []string{"nsmf-pdusession", "nsmf-event-exposure"}, RequesterFeatures: "0"},
			wantQuery: url.Values{"target-nf-type": {"SMF"}, "requester-nf-type": {"AMF"},
				"service-names": {"nsmf-pdusession,nsmf-event-exposure"}, "requester-features": {"0"}},
		},
		{
			name: "optional params and extra",
			q: DiscoveryQuery{TargetNFType: "SMF", RequesterNFType: "AMF", DNN: "internet",
				RequesterNFInstanceID: "abc", SNSSAIs: []SNSSAIEntry{{SST: 1, SD: "010203"}},
				Extra: url.Values{"tai": {"x"}, "dnn": {"ignored"}}},
			wantQuery: url.Values{"target-nf-type": {"SMF"}, "requester-nf-type": {"AMF"}, "dnn": {"internet"},
				"requester-nf-instance-id": {"abc"}, "snssais": {`[{"sst":1,"sd":"010203"}]`}, "tai": {"x"}},
		},
		{name: "supported-features with two services rejected", wantErr: true,
			q: DiscoveryQuery{TargetNFType: "UDM", RequesterNFType: "AMF", ServiceNames: []string{"a", "b"}, SupportedFeatures: "1"}},
		{name: "supported-features without service rejected", wantErr: true,
			q: DiscoveryQuery{TargetNFType: "UDM", RequesterNFType: "AMF", SupportedFeatures: "1"}},
		{name: "invalid supported-features hex", wantErr: true,
			q: DiscoveryQuery{TargetNFType: "UDM", RequesterNFType: "AMF", ServiceNames: []string{"a"}, SupportedFeatures: "xyz"}},
		{name: "invalid requester-features hex", wantErr: true,
			q: DiscoveryQuery{TargetNFType: "UDM", RequesterNFType: "AMF", RequesterFeatures: "0g"}},
		{name: "missing target", wantErr: true, q: DiscoveryQuery{RequesterNFType: "AMF"}},
		{name: "missing requester", wantErr: true, q: DiscoveryQuery{TargetNFType: "UDM"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mu.Lock()
			before := calls
			mu.Unlock()
			res, err := c.Discover(context.Background(), tc.q)
			mu.Lock()
			defer mu.Unlock()
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				if calls != before {
					t.Fatal("request sent despite invalid query")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if gotPath != DiscoveryPath {
				t.Errorf("path = %q", gotPath)
			}
			if !reflect.DeepEqual(gotQuery, tc.wantQuery) {
				t.Errorf("query = %v, want %v", gotQuery, tc.wantQuery)
			}
			if res.ValidityPeriod != 60 || res.NRFSupportedFeatures != "3" || string(res.Extra["searchId"]) != `"s1"` {
				t.Errorf("result = %+v", res)
			}
		})
	}
}

func TestDiscoverNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	_, err := testClient(srv.URL).Discover(context.Background(), DiscoveryQuery{TargetNFType: "UDM", RequesterNFType: "AMF"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestProfileRoundTripUnknownAttrs(t *testing.T) {
	in := `{"nfInstanceId":"id1","nfType":"SMF","nfStatus":"REGISTERED","futureTop":{"a":[1,2,{"b":null}]},` +
		`"nfServices":[{"serviceInstanceId":"s1","serviceName":"nsmf-pdusession","versions":[],"scheme":"https",` +
		`"nfServiceStatus":"REGISTERED","supportedFeatures":"1f","rel20Svc":"x","oauthScope":["a"]}],"zeta":1.5}`
	var p NFProfile
	if err := json.Unmarshal([]byte(in), &p); err != nil {
		t.Fatal(err)
	}
	if p.NFServices[0].SupportedFeatures != "1f" || len(p.Extra) != 2 || len(p.NFServices[0].Extra) != 2 {
		t.Fatalf("decoded = %+v", p)
	}
	out, err := json.Marshal(&p)
	if err != nil {
		t.Fatal(err)
	}
	var a, b any
	_ = json.Unmarshal([]byte(in), &a)
	if err := json.Unmarshal(out, &b); err != nil {
		t.Fatal(err)
	}
	// "versions":[] decodes to an empty slice and re-encodes as [] (not null).
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("round trip lost data:\n in  %s\n out %s", in, out)
	}
	out2, _ := json.Marshal(&p)
	if string(out) != string(out2) {
		t.Fatal("non-deterministic marshal")
	}
}

func TestRegisterParsesHeartBeatTimerWithExtras(t *testing.T) {
	f := &fakeNRF{hbTimer: 15}
	srv := httptest.NewServer(f)
	defer srv.Close()
	got, err := testClient(srv.URL).Register(context.Background(), testProfile())
	if err != nil || got != 15 {
		t.Fatalf("timer=%d err=%v", got, err)
	}
}

func TestFeatureCache(t *testing.T) {
	now := time.Unix(1000, 0)
	fc := NewFeatureCache()
	fc.SetClock(func() time.Time { return now })
	mustSet := func(s string) features.Set {
		v, err := features.Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	res := &SearchResult{ValidityPeriod: 10, NFInstances: []NFProfile{
		{NFInstanceID: "n1", NFServices: []NFService{
			{ServiceName: "svcA", SupportedFeatures: "7"},
			{ServiceName: "svcB"},
			{ServiceName: "svcC", SupportedFeatures: "zz"},
		}},
		{NFInstanceID: "n2", NFServices: []NFService{{ServiceName: "svcA", SupportedFeatures: "1"}}},
	}}
	offered := func(s string) features.Set { return mustSet("5") }
	if n := fc.StoreResult(res, offered); n != 4 {
		t.Fatalf("stored %d", n)
	}
	for _, tc := range []struct{ id, svc, want string }{
		{"n1", "svcA", "5"}, {"n1", "svcB", ""}, {"n1", "svcC", ""}, {"n2", "svcA", "1"},
	} {
		got, ok := fc.Get(tc.id, tc.svc)
		if !ok || !got.Equal(mustSet(tc.want)) {
			t.Errorf("%s/%s = %v,%v want %q", tc.id, tc.svc, got, ok, tc.want)
		}
	}
	if _, ok := fc.Get("n2", "svcB"); ok {
		t.Error("unknown key present")
	}
	now = now.Add(9 * time.Second)
	if _, ok := fc.Get("n1", "svcA"); !ok {
		t.Error("expired too early")
	}
	now = now.Add(time.Second) // exactly validityPeriod elapsed
	if _, ok := fc.Get("n1", "svcA"); ok {
		t.Error("not expired")
	}
	if fc.Len() != 3 {
		t.Errorf("len = %d, want 3 after one eviction", fc.Len())
	}

	// nil offered => empty sets; absent/<=0 validityPeriod => not cached.
	fc2 := NewFeatureCache()
	if fc2.StoreResult(&SearchResult{NFInstances: res.NFInstances}, offered) != 0 || fc2.Len() != 0 {
		t.Error("cached without validityPeriod")
	}
	if fc2.StoreResult(&SearchResult{ValidityPeriod: -1, NFInstances: res.NFInstances}, offered) != 0 {
		t.Error("cached with negative validityPeriod")
	}
	if fc2.StoreResult(nil, offered) != 0 {
		t.Error("nil result cached")
	}
	fc2.StoreResult(res, nil)
	if s, ok := fc2.Get("n1", "svcA"); !ok || !s.IsEmpty() {
		t.Errorf("nil offered => %v,%v", s, ok)
	}
}

func TestFeatureCacheConcurrent(t *testing.T) {
	fc := NewFeatureCache()
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 200 {
				fc.Put("n", "s", features.Set{}.With(i), time.Minute)
				fc.Get("n", "s")
			}
		}()
	}
	wg.Wait()
}
