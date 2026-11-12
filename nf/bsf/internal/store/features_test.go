package store

// features_test.go - the negotiated feature set rides on the stored binding
// but never changes its JSON representation (REL19-2.7 slice 3).
// Ref: TS 29.500 §6.6.2; TS 29.521 §5.8.

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

func TestFeaturesNotSerialised(t *testing.T) {
	cat := features.MustCatalog(features.MustImplement(features.NbsfManagementEntries(), 1)...)
	_, set := features.Answer(cat, nil, "ff")
	b := &PcfBinding{BindingID: "b1", Ipv4Addr: "10.0.0.1", Dnn: "internet", SuppFeat: "1", Features: set}
	out, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "Features") || strings.Contains(string(out), "features") {
		t.Errorf("Features leaked into JSON: %s", out)
	}
	if !strings.Contains(string(out), `"suppFeat":"1"`) {
		t.Errorf("suppFeat missing: %s", out)
	}
}

func TestFeaturesKeptByStoreCopies(t *testing.T) {
	cat := features.MustCatalog(features.MustImplement(features.NbsfManagementEntries(), 1)...)
	_, set := features.Answer(cat, nil, "ff")
	s := New()
	created, ok := s.Create(&PcfBinding{BindingID: "b1", Ipv4Addr: "10.0.0.1", Dnn: "internet", Features: set})
	if !ok || !created.Features.Has(1) {
		t.Fatalf("created = %+v ok=%v", created, ok)
	}
	found, ok := s.FindByQuery(&DiscoveryQuery{Ipv4Addr: "10.0.0.1"})
	if !ok || !found.Features.Has(1) {
		t.Errorf("found = %+v ok=%v", found, ok)
	}
}
