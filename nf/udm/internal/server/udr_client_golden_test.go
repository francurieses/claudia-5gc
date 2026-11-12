package server

// udr_client_golden_test.go - byte-identity goldens for the UDM's Nudr_
// DataRepository client requests (REL19-2.7 slice 6b-2). The files under
// testdata/golden_udr_*.txt were captured from the pristine HEAD tree (before
// supportedFeatures negotiation existed) and must pass UNCHANGED under rel17
// and under no profile (decision D2, dev/REL19_PROGRAM.md section 2).
// UPDATE_GOLDEN=1 rewrites them; only ever run it on the pristine tree.
// Each subtest builds its own UDR stub.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	goldenUDRSupi    = "imsi-001010000000001"
	goldenUDRAuthRsp = `{"authenticationMethod":"5G_AKA","encPermanentKey":"00112233445566778899aabbccddeeff","encOpcKey":"ffeeddccbbaa99887766554433221100","authenticationManagementField":"8000","algorithmId":"milenage","sequenceNumber":{"sqn":"000000000020"}}`
	goldenUDRAMRsp   = `{"nssai":{"defaultSingleNssais":[{"sst":1,"sd":"000001","dnn":"internet"},{"sst":2,"sd":"000002","subjectToNetworkSliceSpecificAuthenticationAndAuthorization":true}]}}`
	goldenUDRSMRsp   = `[{"singleNssai":{"sst":1,"sd":"000001"},"dnnConfigurations":{"internet":{"pduSessionTypes":{"defaultSessionType":"IPV4"}}}}]`
)

// udrStub answers the four UDM->UDR operations with fixed bodies and records
// the request exactly as it arrived.
type udrStub struct {
	srv  *httptest.Server
	seen string
}

func newUDRStub(t *testing.T, rsp map[string]string) *udrStub {
	t.Helper()
	st := &udrStub{}
	st.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("stub: read body: %v", err)
		}
		st.seen = fmt.Sprintf("%s %s\nContent-Type: %s\nAccept: %s\n\n%s", r.Method, r.RequestURI,
			r.Header.Get("Content-Type"), r.Header.Get("Accept"), body)
		if r.Method == http.MethodPatch {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		key := "auth"
		switch {
		case strings.HasSuffix(r.URL.Path, "/am-data"):
			key = "am"
		case strings.HasSuffix(r.URL.Path, "/sm-data"):
			key = "sm"
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, rsp[key])
	}))
	t.Cleanup(st.srv.Close)
	return st
}

func (st *udrStub) address() string { return strings.TrimPrefix(st.srv.URL, "https://") }

func TestGolden_UDRClientRequests(t *testing.T) {
	defaults := map[string]string{"auth": goldenUDRAuthRsp, "am": goldenUDRAMRsp, "sm": goldenUDRSMRsp}
	ops := []struct {
		name, golden string
		call         func(ctx context.Context, c *HTTPUDRClient) (any, error)
	}{
		{"get_auth_subscription", "golden_udr_get_auth_sub.txt", func(ctx context.Context, c *HTTPUDRClient) (any, error) {
			return c.GetAuthSubscription(ctx, goldenUDRSupi)
		}},
		{"patch_sqn", "golden_udr_patch_sqn.txt", func(ctx context.Context, c *HTTPUDRClient) (any, error) {
			return nil, c.UpdateSQN(ctx, goldenUDRSupi, "000000000040")
		}},
		{"get_sm_data", "golden_udr_get_sm_data.txt", func(ctx context.Context, c *HTTPUDRClient) (any, error) {
			return c.GetSMData(ctx, goldenUDRSupi)
		}},
		{"get_am_data", "golden_udr_get_am_data.txt", func(ctx context.Context, c *HTTPUDRClient) (any, error) {
			return c.GetAMData(ctx, goldenUDRSupi)
		}},
	}
	for _, pname := range []string{"no-profile", "explicit-rel17"} {
		for _, op := range ops {
			t.Run(pname+"/"+op.name, func(t *testing.T) {
				st := newUDRStub(t, defaults)
				c := newTestUDRClient(st.address(), st.srv.Client(), goldenProfiles(t)[pname])
				res, err := op.call(context.Background(), c)
				if err != nil {
					t.Fatalf("call: %v", err)
				}
				out, merr := json.Marshal(res)
				if merr != nil {
					t.Fatalf("marshal result: %v", merr)
				}
				checkGolden(t, op.golden, st.seen+"\n\n--- result\n"+string(out)+"\n")
			})
		}
	}
}
