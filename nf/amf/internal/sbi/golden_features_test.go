package sbi

// golden_features_test.go - REL19-2.7 byte-identity goldens for the namf-comm
// producer. Captured against the pre-REL19-2.7 code for a request WITHOUT
// supportedFeatures; they must pass UNCHANGED with no profile / rel17 (decision
// D1, dev/REL19_PROGRAM.md §2). Nothing is normalised.
// Ref: TS 29.500 §6.6.2; TS 29.518 §6.1.6.2.3, §6.1.6.2.6.

import (
	"net/http"
	"testing"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
)

// The trailing newline is the json.Encoder terminator.
const (
	goldenUECtxTransferRsp = `{"ueContext":{"supi":"imsi-001010000000001","mmContextList":[{"accessType":"3GPP_ACCESS","nasSecurityMode":{"integrityAlgorithm":"NIA2","cipheringAlgorithm":"NEA2"},"nasDownlinkCount":4,"nasUplinkCount":3,"kamf":"q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s="}],"sessionContextList":[{"pduSessionId":1,"smContextRef":"smf-ctx-ref-1","sNssai":{"sst":1,"sd":"000001"},"dnn":"internet","accessType":"3GPP_ACCESS","smfInstanceId":"smf-ctx-ref-1"}]}}` + "\n"
	goldenN1N2Rsp200       = `{"cause":"N1_N2_TRANSFER_INITIATED"}` + "\n"
	goldenN1N2Rsp202       = `{"cause":"ATTEMPTING_TO_REACH_UE"}` + "\n"
)

func TestGolden_UEContextTransferRsp_NoSupportedFeatures(t *testing.T) {
	srv, mgr := newTestServer(t)
	seedRegisteredUE(mgr, "imsi-001010000000001")
	resp, raw := post(t, srv, "imsi-001010000000001", []byte(`{"reason":"MOBI_REG","accessType":"3GPP_ACCESS"}`))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, raw)
	}
	if string(raw) != goldenUECtxTransferRsp {
		t.Fatalf("body changed:\n got %s\nwant %s", raw, goldenUECtxTransferRsp)
	}
}

func TestGolden_N1N2Rsp_NoSupportedFeatures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		state  amfctx.CMState
		status int
		want   string
	}{
		{"200 CM-CONNECTED", amfctx.CMConnected, http.StatusOK, goldenN1N2Rsp200},
		{"202 CM-IDLE", amfctx.CMIdle, http.StatusAccepted, goldenN1N2Rsp202},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, mgr := newTestServer(t)
			ue := seedRegisteredUE(mgr, "imsi-001010000000001")
			ue.Lock()
			ue.CMState = tc.state
			ue.Unlock()
			resp, raw := postN1N2(t, srv, "imsi-001010000000001", []byte(`{"pduSessionId":1}`))
			if resp.StatusCode != tc.status {
				t.Fatalf("status %d, want %d: %s", resp.StatusCode, tc.status, raw)
			}
			if string(raw) != tc.want {
				t.Fatalf("body changed:\n got %s\nwant %s", raw, tc.want)
			}
		})
	}
}
