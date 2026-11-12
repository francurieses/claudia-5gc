package server

// consumer_golden_test.go - byte-identity goldens for the NEF outbound
// requests to the BSF (Nbsf_Management_Discovery) and the PCF
// (Npcf_PolicyAuthorization Create/Delete), REL19-2.7 slice 7. Captured on the
// pre-change HEAD tree; they must pass UNCHANGED with no profile and with an
// explicit rel17 profile (decision D2, dev/REL19_PROGRAM.md section 2).
// Ref: TS 29.521 §5.2.2.4, TS 29.514 §5.2.2.2, §4.2.4.2.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/capability"
)

// recordingServer answers every request with status/headers/body and records
// the request bytes that matter (method, path+query, selected headers, body).
func recordingServer(t *testing.T, status int, loc, respBody string) (*httptest.Server, *string) {
	t.Helper()
	var rec string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		rec = r.Method + " " + r.URL.RequestURI() + "\n" +
			"Content-Type: " + r.Header.Get("Content-Type") + "\n" +
			"Accept: " + r.Header.Get("Accept") + "\n" +
			"Content-Length: " + r.Header.Get("Content-Length") + "\n\n" + string(b)
		if loc != "" {
			w.Header().Set("Location", loc)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(respBody))
	}))
	t.Cleanup(ts.Close)
	return ts, &rec
}

func TestGolden_ConsumerRequests(t *testing.T) {
	profiles := []struct {
		name string
		p    func(*testing.T) *capability.Profile
	}{
		{"noprofile", func(*testing.T) *capability.Profile { return nil }},
		{"rel17", func(t *testing.T) *capability.Profile { return profileNamed(t, "rel17") }},
	}
	for _, pr := range profiles {
		t.Run(pr.name, func(t *testing.T) {
			t.Run("bsf_discover", func(t *testing.T) {
				ts, rec := recordingServer(t, http.StatusOK, "", `{"bindingId":"b1","pcfFqdn":"pcf.example","dnn":"internet"}`)
				c := hookBSF(ts.URL, ts.Client(), pr.p(t))
				if _, err := c.Discover(context.Background(), "10.60.0.1"); err != nil {
					t.Fatal(err)
				}
				checkGolden(t, "golden_bsf_discover.txt", strings.ReplaceAll(*rec, ts.URL, "<URL>"))
			})
			t.Run("pcf_create", func(t *testing.T) {
				ts, rec := recordingServer(t, http.StatusCreated, "/npcf-policyauthorization/v1/app-sessions/as-1", "")
				c := hookPCF(ts.Client(), pr.p(t))
				req := &AppSessionContextReqData{
					AspId: "af-1", AfAppId: "app-1", UeIpv4: "10.60.0.1", QosReference: "qos-1", qosTopLevel: true, Dnn: "internet",
					SliceInfo:     &BindingSnssai{Sst: 1, Sd: "000001"},
					MedComponents: map[string]any{"1": LegacyMediaComponent{MedType: "DATA", FDescs: []string{"permit out ip from any to any"}}},
				}
				if _, err := hookCreate(context.Background(), c, ts.URL, req); err != nil {
					t.Fatal(err)
				}
				checkGolden(t, "golden_pcf_create.txt", *rec)
			})
			t.Run("pcf_delete", func(t *testing.T) {
				ts, rec := recordingServer(t, http.StatusNoContent, "", "")
				c := hookPCF(ts.Client(), pr.p(t))
				if err := c.DeleteAppSession(context.Background(), ts.URL, "as-1"); err != nil {
					t.Fatal(err)
				}
				checkGolden(t, "golden_pcf_delete.txt", *rec)
			})
		})
	}
}
