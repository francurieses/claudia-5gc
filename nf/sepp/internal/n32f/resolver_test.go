package n32f

import (
	"context"
	"errors"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/nrf"
)

type fakeNRF struct {
	calls int
	res   *nrf.SearchResult
	err   error
	q     nrf.DiscoveryQuery
}

func (f *fakeNRF) Discover(_ context.Context, q nrf.DiscoveryQuery) (*nrf.SearchResult, error) {
	f.calls++
	f.q = q
	return f.res, f.err
}

func TestNRFResolver(t *testing.T) {
	fn := &fakeNRF{res: &nrf.SearchResult{NFInstances: []nrf.NFProfile{
		{FQDN: "other." + localNF, NFServices: []nrf.NFService{{ServiceName: "nudm-sdm", Scheme: "https"}}},
		{FQDN: localNF, NFServices: []nrf.NFService{{ServiceName: "nudm-sdm", Scheme: "https",
			IPEndpoints: []nrf.IPEndpoint{{IPv4Address: "10.0.0.5", Port: 8005}}}}},
	}}}
	r := NewNRFResolver(fn)
	u, err := r.Resolve(context.Background(), localNF, "/nudm-sdm/v2/x")
	if err != nil || u.String() != "https://"+localNF+":8005" {
		t.Fatalf("%v %v", u, err)
	}
	if fn.q.TargetNFType != "UDM" || fn.q.RequesterNFType != "SEPP" || fn.q.ServiceNames[0] != "nudm-sdm" {
		t.Fatalf("query %+v", fn.q)
	}
	if _, err := r.Resolve(context.Background(), localNF, "/nudm-sdm/v2/y"); err != nil || fn.calls != 1 {
		t.Fatalf("cache: calls=%d err=%v", fn.calls, err)
	}
	if _, err := r.Resolve(context.Background(), "ghost.5gc.mnc001.mcc001.3gppnetwork.org", "/nudm-sdm/v2/x"); !errors.Is(err, ErrTargetNotFound) {
		t.Fatalf("unknown NF: %v", err)
	}
	if _, err := r.Resolve(context.Background(), localNF, "/nunknown/v1/x"); !errors.Is(err, ErrTargetNotFound) {
		t.Fatalf("unknown service: %v", err)
	}
	fn.res.NFInstances[1].NFServices[0].Scheme = "http"
	if _, err := NewNRFResolver(fn).Resolve(context.Background(), localNF, "/nudm-sdm/v2/x"); !errors.Is(err, ErrTargetNotFound) {
		t.Fatalf("http scheme must be refused: %v", err)
	}
	fn.err = errors.New("nrf down")
	if _, err := NewNRFResolver(fn).Resolve(context.Background(), localNF, "/nudm-sdm/v2/x"); err == nil {
		t.Fatal("NRF error must propagate")
	}
}
