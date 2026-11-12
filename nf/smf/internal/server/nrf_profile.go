// Package server: NRF NFProfile construction for the SMF.

package server

import (
	"github.com/francurieses/claudia-5gc/nf/smf/internal/config"
	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/nrf"
	"github.com/francurieses/claudia-5gc/shared/sbi/apiversion"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

// BuildNFProfile builds the NFProfile the SMF registers with the NRF
// (Nnrf_NFManagement_NFRegister). Pure function of cfg and the release
// profile p (nil behaves as rel17). The nsmf-pdusession service advertises
// supportedFeatures only under rel19 (features.Request; omitted under rel17 so
// the profile is byte-identical to the baseline).
// Ref: TS 29.510 §5.2.2.2.2, §6.1.6.2.3; TS 29.500 §6.6.2.
func BuildNFProfile(cfg *config.Config, p *capability.Profile) *nrf.NFProfile {
	var snssais []nrf.SNSSAIEntry
	for _, s := range cfg.SNSSAIs {
		snssais = append(snssais, nrf.SNSSAIEntry{SST: s.SST, SD: s.SD})
	}
	if len(snssais) == 0 {
		snssais = []nrf.SNSSAIEntry{{SST: 1, SD: "000001"}}
	}
	// Advertise all configured DNNs to NRF (TS 29.510 §6.1.6.2.28).
	var dnnList []string
	for _, d := range cfg.DNNs {
		dnnList = append(dnnList, d.Name)
	}
	if len(dnnList) == 0 {
		dnnList = []string{"internet"}
	}
	return &nrf.NFProfile{
		NFInstanceID: cfg.NFInstanceID,
		NFType:       "SMF",
		NFStatus:     "REGISTERED",
		SNSSAIs:      snssais,
		DNNList:      dnnList,
		NFServices: []nrf.NFService{{
			ServiceInstanceID: cfg.NFInstanceID + "-nsmf-pdusession",
			ServiceName:       "nsmf-pdusession",
			Scheme:            "https",
			NFServiceStatus:   "REGISTERED",
			Versions:          []nrf.NFServiceVersion{nrf.ServiceVersion(p, apiversion.NsmfPDUSession)},
			SupportedFeatures: features.Request(nsmfPDUSessionCatalog, p),
		}},
	}
}
