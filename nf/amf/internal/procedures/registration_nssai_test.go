package procedures

import (
	"testing"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
)

func TestFilterAllowedNSSAI_NilRequest(t *testing.T) {
	subscribed := []amfctx.SNSSAISubscribed{
		{SST: 1, SD: "000001"},
		{SST: 2, SD: "000002"},
	}
	got := filterAllowedNSSAI(nil, subscribed)
	if len(got) != 2 {
		t.Fatalf("expected 2 slices, got %d", len(got))
	}
}

func TestFilterAllowedNSSAI_Intersection(t *testing.T) {
	requested := []amfctx.SNSSAISubscribed{{SST: 1, SD: "000001"}}
	subscribed := []amfctx.SNSSAISubscribed{
		{SST: 1, SD: "000001"},
		{SST: 2, SD: "000002"},
	}
	got := filterAllowedNSSAI(requested, subscribed)
	if len(got) != 1 || got[0].SST != 1 {
		t.Fatalf("expected [{SST:1}], got %v", got)
	}
}

func TestFilterAllowedNSSAI_NoMatch(t *testing.T) {
	requested := []amfctx.SNSSAISubscribed{{SST: 3, SD: "000003"}}
	subscribed := []amfctx.SNSSAISubscribed{{SST: 1, SD: "000001"}}
	got := filterAllowedNSSAI(requested, subscribed)
	if len(got) != 0 {
		t.Fatalf("expected empty, got %v", got)
	}
}

func TestFilterAllowedNSSAI_WildcardSD(t *testing.T) {
	// SD=="" in requested means "any SD with same SST" (TS 24.501 §5.5.1.2.4)
	requested := []amfctx.SNSSAISubscribed{{SST: 1, SD: ""}}
	subscribed := []amfctx.SNSSAISubscribed{
		{SST: 1, SD: "000001"},
		{SST: 2, SD: "000002"},
	}
	got := filterAllowedNSSAI(requested, subscribed)
	if len(got) != 1 || got[0].SST != 1 || got[0].SD != "000001" {
		t.Fatalf("expected [{SST:1,SD:000001}], got %v", got)
	}
}
