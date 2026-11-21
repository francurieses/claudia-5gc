package nasmsg

// nssai_mapped_test.go - AMF-036: the mapped HPLMN S-NSSAI of a requested
// S-NSSAI survives nssaiToSubscribed (TS 24.501 §9.11.2.8, §9.11.3.75).

import (
	"testing"

	"github.com/francurieses/claudia-5gc/shared/nas"
)

func TestNssaiToSubscribedKeepsMapped(t *testing.T) {
	got := nssaiToSubscribed(&nas.NSSAI{SNSSAIs: []nas.SNSSAI{
		{SST: 1, SD: 5, HasMappedHPLMN: true, MappedHPLMNSST: 2, MappedHPLMNSD: 6},
		{SST: 3, SD: nas.SDNotPresent, HasMappedHPLMN: true, MappedHPLMNSST: 4, MappedHPLMNSD: nas.SDNotPresent},
		{SST: 5, SD: nas.SDNotPresent},
	}})
	if !got[0].HasMapped || got[0].MappedSST != 2 || got[0].MappedSD != "000006" ||
		!got[1].HasMapped || got[1].MappedSST != 4 || got[1].MappedSD != "" || got[2].HasMapped {
		t.Fatalf("got %+v", got)
	}
}
