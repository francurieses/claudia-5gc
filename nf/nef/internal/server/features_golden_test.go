package server

// features_golden_test.go - byte-identity goldens for the NEF
// AsSessionWithQoS Create/Get answers (REL19-2.7 slice 2). Captured against the
// pre-change code (git worktree at HEAD); they must pass UNCHANGED under rel17
// / no profile for a request WITHOUT supportedFeatures (decision D1,
// dev/REL19_PROGRAM.md section 2). Only the random subscriptionId UUID is
// normalised.

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

var uuidRE = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

// checkGolden compares got with testdata/<name>. UPDATE_GOLDEN=1 rewrites the
// file; only ever used on the pre-change tree (git worktree at HEAD).
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

// snapshot renders status, Content-Type, Location and body, UUID-normalised.
func snapshot(t *testing.T, resp *http.Response) string {
	t.Helper()
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return uuidRE.ReplaceAllString("status: "+http.StatusText(resp.StatusCode)+"\n"+
		"Content-Type: "+resp.Header.Get("Content-Type")+"\n"+
		"Location: "+resp.Header.Get("Location")+"\n\n"+string(raw), "<SUBID>")
}

func TestGolden_CreateAndGet(t *testing.T) {
	_, ts := newTestServer(t, defaultBSF(), defaultPCF())
	body := []byte(`{"ueIpv4Addr":"10.60.0.1","qosReference":"qos-1","afAppId":"app-1","dnn":"internet"}`)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/3gpp-as-session-with-qos/v1/af-1/subscriptions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+mintToken(t, testScope))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	loc := resp.Header.Get("Location")
	created := snapshot(t, resp)
	checkGolden(t, "golden_create_201.txt", created)

	// GET the same resource (Location is https://<fqdn>/...; use the path).
	idx := regexp.MustCompile(`/3gpp-as-session-with-qos/.*$`).FindString(loc)
	greq, _ := http.NewRequest(http.MethodGet, ts.URL+idx, nil)
	greq.Header.Set("Authorization", "Bearer "+mintToken(t, testScope))
	gresp, err := http.DefaultClient.Do(greq)
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "golden_get_200.txt", snapshot(t, gresp))
}
