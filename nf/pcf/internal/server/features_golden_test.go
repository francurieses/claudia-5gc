package server

// features_golden_test.go - byte-identity goldens for the PCF producer answers
// (REL19-2.7 slice 4). Captured against the pre-change code (git worktree at
// HEAD) and run UNCHANGED under rel17 / no profile for requests WITHOUT
// suppFeat (decision D1, dev/REL19_PROGRAM.md section 2). Only minted UUID /
// ULID identifiers are normalised; keys, order and every other byte compare
// as-is. UPDATE_GOLDEN=1 rewrites the files and is only ever used on the
// pre-change tree, except for deliberate conformance fixes (3c2eef4; PCF-003:
// absolute Location on all four creates, AM/UE 201 bodies without the
// non-schema polAssoId / uePolicySections, UE policy as `uePolicy`).

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/francurieses/claudia-5gc/nf/pcf/internal/config"
)

var (
	goldenUUIDRE = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	goldenULIDRE = regexp.MustCompile(`[0-9A-HJKMNP-TV-Z]{26}`)
)

// checkGolden compares got with testdata/<name>.
func checkGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v", name, err)
	}
	if got != string(b) {
		t.Fatalf("%s changed\n got: %q\nwant: %q", name, got, b)
	}
}

// goldenSnapshot renders status, Content-Type, Location and the body with
// identifiers replaced by <UUID> / <ULID>.
func goldenSnapshot(resp *http.Response) string {
	raw, _ := io.ReadAll(resp.Body)
	norm := func(s string) string {
		return goldenULIDRE.ReplaceAllString(goldenUUIDRE.ReplaceAllString(s, "<UUID>"), "<ULID>")
	}
	return "status: " + http.StatusText(resp.StatusCode) + "\n" +
		"Content-Type: " + resp.Header.Get("Content-Type") + "\n" +
		"Location: " + norm(resp.Header.Get("Location")) + "\n\n" +
		norm(string(raw))
}

// goldenPost sends body through the full handler chain (middleware + mux).
func goldenPost(t *testing.T, s *Server, target, body string) string {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Correlation-Id", "01TESTCORRELATIONID00000000")
	w := httptest.NewRecorder()
	s.httpSrv.Handler.ServeHTTP(w, r)
	return goldenSnapshot(w.Result())
}

func TestGolden_ProducerCreates(t *testing.T) {
	s := newTestPCF(t)
	s.cfg.DefaultURSP.Rules = []config.URSPRuleConfig{{Precedence: 255}}
	s.cfg.DefaultURSP.Rules[0].TrafficDescriptor.MatchAll = true

	checkGolden(t, "golden_smpolicy_201.txt", goldenPost(t, s,
		"/npcf-smpolicycontrol/v1/sm-policies",
		`{"supi":"imsi-001010000000001","pduSessionId":5,"pduSessionType":"IPV4","dnn":"internet","notificationUri":"https://smf/notif","sliceInfo":{"sst":1,"sd":"000001"},"ipv4Address":"10.60.0.1"}`))
	checkGolden(t, "golden_ampolicy_201.txt", goldenPost(t, s,
		"/npcf-am-policy-control/v1/policies",
		`{"supi":"imsi-001010000000001","accessType":"3GPP_ACCESS","notificationUri":"https://amf/notif"}`))
	checkGolden(t, "golden_uepolicy_201.txt", goldenPost(t, s,
		"/npcf-ue-policy-control/v1/policies",
		`{"supi":"imsi-001010000000001","servingPlmn":"00101","notificationUri":"https://amf/notif"}`))
	checkGolden(t, "golden_appsession_201.txt", goldenPost(t, s,
		"/npcf-policyauthorization/v1/app-sessions",
		`{"ascReqData":{"aspId":"af-test","ueIpv4":"10.60.0.1","qosReference":"qos-gold","dnn":"internet"}}`))
}
