package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

type stubLogs struct {
	logs  map[string]string
	calls atomic.Int32
}

func (s *stubLogs) StartupLogs(_ context.Context, name string) (string, error) {
	s.calls.Add(1)
	return s.logs[name], nil
}

func line(msg, p string) string {
	return `{"level":"INFO","msg":"` + msg + `","release_profile":"` + p + `"}` + "\n"
}

func TestParseReleaseProfile_LastWins(t *testing.T) {
	logs := line("release profile loaded", "rel17") + "noise\n" + line("release profile loaded", "rel19")
	if got := parseReleaseProfile(logs); got != "rel19" {
		t.Fatalf("got %q", got)
	}
	if got := parseReleaseProfile(line("SMF release profile", "rel17")); got != "rel17" {
		t.Fatalf("smf got %q", got)
	}
	if got := parseReleaseProfile("nothing here"); got != "" {
		t.Fatalf("got %q", got)
	}
}

func getRelease(t *testing.T, src StartupLogReader) (ReleaseInfo, *ReleaseResolver) {
	t.Helper()
	res := NewReleaseResolver(src)
	h := NewRouter(Deps{Release: res}, http.FS(emptyFS(t)))
	rec := do(t, h, http.MethodGet, "/api/v1/release", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var ri ReleaseInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &ri); err != nil {
		t.Fatal(err)
	}
	return ri, res
}

func TestRelease_Profiles(t *testing.T) {
	cases := []struct {
		name string
		logs map[string]string
		want string
	}{
		{"common", map[string]string{"amf": line("release profile loaded", "rel19"), "smf": line("SMF release profile", "rel19")}, "rel19"},
		{"mixed", map[string]string{"amf": line("release profile loaded", "rel19"), "smf": line("SMF release profile", "rel17")}, "mixed"},
		{"unknown", map[string]string{}, "unknown"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ri, _ := getRelease(t, &stubLogs{logs: c.logs})
			if ri.Profile != c.want {
				t.Errorf("profile = %q, want %q (%v)", ri.Profile, c.want, ri.NFs)
			}
		})
	}
}

func TestRelease_Cached(t *testing.T) {
	src := &stubLogs{logs: map[string]string{"amf": line("release profile loaded", "rel19")}}
	res := NewReleaseResolver(src)
	res.Get(context.Background())
	n := src.calls.Load()
	res.Get(context.Background())
	if src.calls.Load() != n {
		t.Error("second Get within TTL re-read logs")
	}
}

func TestRelease_NoDocker(t *testing.T) {
	rec := do(t, newFakeRouter(t), http.MethodGet, "/api/v1/release", "")
	if !strings.Contains(rec.Body.String(), `"unknown"`) {
		t.Errorf("body = %s", rec.Body.String())
	}
}
