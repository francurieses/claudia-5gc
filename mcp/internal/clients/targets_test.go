package clients

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	promclient "github.com/francurieses/claudia-5gc/mcp/internal/prometheus"
)

func promStub(t *testing.T, instance string) *promclient.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[
		 {"metric":{"nf":"SMF","instance":"` + instance + `"},"value":[1,"1"]}]}}`))
	}))
	t.Cleanup(srv.Close)
	return promclient.New(srv.URL, http.DefaultClient, 0)
}

func TestTargetsHostOverride(t *testing.T) {
	tests := []struct {
		name, instance, override, want string
		wantErr                        bool
	}{
		{"override replaces host keeps port", "smf:9105", "localhost", "localhost:9105", false},
		{"no override unchanged", "smf:9105", "", "smf:9105", false},
		{"malformed instance rejected", "smf 9105;x", "localhost", "", true},
		{"missing port rejected", "smf", "", "", true},
		{"bad override ignored", "smf:9105", "evil/host", "smf:9105", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tg := NewTargets(promStub(t, tc.instance), tc.override)
			got, err := tg.Addr(context.Background(), "SMF")
			if tc.wantErr {
				if !errors.Is(err, ErrNoTarget) {
					t.Fatalf("want ErrNoTarget, got %v (%q)", err, got)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("Addr = %q, %v; want %q", got, err, tc.want)
			}
			list, err := tg.List(context.Background())
			if err != nil || len(list) != 1 || list[0].Instance != tc.want || list[0].Raw != tc.instance || !list[0].Up {
				t.Fatalf("List = %+v, %v", list, err)
			}
		})
	}
}

func TestTargetsAddrRejectsInjection(t *testing.T) {
	tg := NewTargets(promStub(t, "smf:9105"), "")
	if _, err := tg.Addr(context.Background(), `SMF"} or up{x="`); err == nil {
		t.Fatal("want error for a hostile NF name")
	}
}
