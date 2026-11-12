package server

// gpsi_golden_test.go - AMF-020 byte-identity golden: a UDR answer carrying
// gpsis must not change the Nudm_SDM am-data response under rel17 / no
// profile. Captured at HEAD 430aa9e (before gpsis were decoded).

import (
	"net/http"
	"testing"
)

const goldenUDRAMGPSIRsp = `{"gpsis":["msisdn-490123456789","extid-user@example.com"],"nssai":{"defaultSingleNssais":[{"sst":1,"sd":"000001","dnn":"internet"}]},"subscribedUeAmbr":{"uplink":"100000 Kbps","downlink":"100000 Kbps"}}`

func TestGolden_SDMAMDataUDRGPSIsLegacy(t *testing.T) {
	for pname := range goldenProfiles(t) {
		t.Run(pname, func(t *testing.T) {
			st := newUDRStub(t, map[string]string{"am": goldenUDRAMGPSIRsp})
			c := newTestUDRClient(st.address(), st.srv.Client(), goldenProfiles(t)[pname])
			s := newSDMGoldenUDMWith(t, goldenProfiles(t)[pname], c)
			checkGolden(t, "golden_sdm_am_data_udr_gpsi.txt",
				snapshot(t, s, http.MethodGet, "/nudm-sdm/v2/imsi-001010000000001/am-data", ""))
		})
	}
}
