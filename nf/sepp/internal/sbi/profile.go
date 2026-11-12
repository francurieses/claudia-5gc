// Package sbi builds the SEPP NF profile registered at the NRF.
// Ref: TS 29.510 §6.1.6.2.2 (NFProfile), TS 29.573 §6.1 (n32c-handshake service name).
package sbi

import (
	"encoding/json"

	"github.com/francurieses/claudia-5gc/nf/sepp/internal/config"
	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/nrf"
	"github.com/francurieses/claudia-5gc/shared/sbi/apiversion"
)

const (
	// NFTypeSEPP is the NFType registered at the NRF. Ref: TS 29.510 NFType enum.
	NFTypeSEPP = "SEPP"
	// ServiceN32cHandshake is the apiName of the N32-c Handshake service.
	// Ref: TS 29.573 Table 6-1 (n32c-handshake).
	//
	// "n32c-handshake" is not in the Rel-17 TS 29.510 ServiceName enum (the
	// attribute is free-form there, anyOf string), so it is registered as the
	// TS 29.573 Table 6-1 apiName without an enum change.
	ServiceN32cHandshake = "n32c-handshake"
	// seppInfoKey is the NFProfile.seppInfo attribute name (SeppInfo, present
	// in the Rel-17 and Rel-19 schemas). Ref: TS 29.510 §6.1.6.2.2.
	seppInfoKey = "seppInfo"
)

// BuildNFProfile returns the NFProfile the SEPP registers at the NRF.
// The version pair comes from shared/sbi/apiversion for the release profile p
// (nil behaves as Rel-17).
//
// remotePLMNs (from n32.roaming_partners) populate seppInfo.remotePlmnList
// (TS 29.510 SeppInfo; minItems 1, so seppInfo is omitted when empty). SeppInfo
// exists in the Rel-17 schema, so it is emitted under both release profiles.
func BuildNFProfile(nfInstanceID string, p *capability.Profile, remotePLMNs []config.PLMN) *nrf.NFProfile {
	v := apiversion.Of(p, apiversion.N32cHandshake)
	prof := &nrf.NFProfile{
		NFInstanceID: nfInstanceID,
		NFType:       NFTypeSEPP,
		NFStatus:     "REGISTERED",
		NFServices: []nrf.NFService{{
			ServiceInstanceID: nfInstanceID + "-" + ServiceN32cHandshake,
			ServiceName:       ServiceN32cHandshake,
			Scheme:            "https",
			NFServiceStatus:   "REGISTERED",
			Versions:          []nrf.NFServiceVersion{{APIVersionInURI: v.InURI, APIFullVersion: v.Full}},
		}},
	}
	if len(remotePLMNs) > 0 {
		list := make([]map[string]string, 0, len(remotePLMNs))
		for _, r := range remotePLMNs {
			list = append(list, map[string]string{"mcc": r.MCC, "mnc": r.MNC})
		}
		// Marshalling a slice of string maps cannot fail.
		raw, _ := json.Marshal(map[string]any{"remotePlmnList": list})
		prof.Extra = map[string]json.RawMessage{seppInfoKey: raw}
	}
	return prof
}
