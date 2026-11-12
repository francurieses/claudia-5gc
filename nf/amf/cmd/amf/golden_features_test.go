package main

// golden_features_test.go - REL19-2.7 byte-identity goldens. They were captured
// against the pre-REL19-2.7 code (no profile) and must keep passing UNCHANGED
// under the rel17 profile / no profile: a rel17 network is byte-identical on the
// wire (decision D1/D2, dev/REL19_PROGRAM.md §2).
// Only the call lines changed after the fact (CreateSMContext gained a
// negotiated-set return; the profile builder moved to amfsbi.BuildNFProfile);
// the expected bytes are untouched.
// Ref: TS 29.500 §6.6.2; TS 29.502 §6.1.6.2.2; TS 29.510 §6.1.6.2.3.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	amfsbi "github.com/francurieses/claudia-5gc/nf/amf/internal/sbi"
)

// goldenSMContextCreateBody is the SmContextCreateData body sent by
// CreateSMContext for (supi imsi-001010000000001, dnn internet, psi 5,
// n1SmMsg 01 02 03, S-NSSAI sst 1 sd 000001). json.Marshal of a map sorts
// keys, so the bytes are deterministic; nothing is normalised.
const goldenSMContextCreateBody = `{"anType":"3GPP_ACCESS","dnn":"internet","n1SmMsg":"AQID","pduSessionId":5,"requestType":"INITIAL_REQUEST","servingNfId":"amf-001","snssai":{"sd":"000001","sst":1},"supi":"imsi-001010000000001"}`

// goldenNFProfileJSON is json.Marshal of the AMF NFProfile for nf instance
// "amf-test-1". Nothing is normalised.
const goldenNFProfileJSON = `{"nfInstanceId":"amf-test-1","nfType":"AMF","nfStatus":"REGISTERED","nfServices":[{"serviceInstanceId":"amf-test-1-namf-comm","serviceName":"namf-comm","versions":[{"apiVersionInUri":"v1","apiFullVersion":"1.2.8"}],"scheme":"https","nfServiceStatus":"REGISTERED"}]}`

func TestGolden_CreateSMContextRequestBody(t *testing.T) {
	var got string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		got = string(raw)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"smContextRef":"ref-1","n1SmMsg":"AQID","n2SmInfo":"BAUG"}`))
	}))
	defer srv.Close()
	c := &HTTPSMFClient{address: strings.TrimPrefix(srv.URL, "https://"), client: srv.Client()}

	ref, n1, n2, _, err := c.CreateSMContext(t.Context(),
		"imsi-001010000000001", "internet", 5, []byte{1, 2, 3},
		amfctx.SNSSAISubscribed{SST: 1, SD: "000001"})
	if err != nil {
		t.Fatalf("CreateSMContext: %v", err)
	}
	if ref != "ref-1" || string(n1) != "\x01\x02\x03" || string(n2) != "\x04\x05\x06" {
		t.Fatalf("results: %q %x %x", ref, n1, n2)
	}
	if got != goldenSMContextCreateBody {
		t.Fatalf("request body changed:\n got %s\nwant %s", got, goldenSMContextCreateBody)
	}
}

func TestGolden_NFProfileJSON(t *testing.T) {
	b, err := json.Marshal(amfsbi.BuildNFProfile("amf-test-1", nil, amfsbi.NamfCommunicationCatalog()))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != goldenNFProfileJSON {
		t.Fatalf("NFProfile JSON changed:\n got %s\nwant %s", b, goldenNFProfileJSON)
	}
}
