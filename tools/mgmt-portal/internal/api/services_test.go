package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
)

type fakeLifecycle struct {
	actionErr   error
	sidecars    map[string][]string
	sidecarErrs map[string]map[string]error
	calls       []string
}

func (f *fakeLifecycle) Start(_ context.Context, name string) error {
	f.calls = append(f.calls, "start:"+name)
	return f.actionErr
}

func (f *fakeLifecycle) Restart(_ context.Context, name string) error {
	f.calls = append(f.calls, "restart:"+name)
	return f.actionErr
}

func (f *fakeLifecycle) RestartNetnsSidecars(_ context.Context, name string) ([]string, map[string]error) {
	f.calls = append(f.calls, "sidecars:"+name)
	return f.sidecars[name], f.sidecarErrs[name]
}

func TestStartOrRestart(t *testing.T) {
	tests := []struct {
		name      string
		target    string
		restart   bool
		fake      *fakeLifecycle
		wantCode  int
		wantErr   bool
		wantJSON  string
		wantCalls []string
	}{
		{
			name:      "restart NF with sidecar lists it",
			target:    "amf",
			restart:   true,
			fake:      &fakeLifecycle{sidecars: map[string][]string{"amf": {"amf-pcap"}}},
			wantCode:  http.StatusOK,
			wantJSON:  `{"status":"restarting","sidecars":["amf-pcap"]}`,
			wantCalls: []string{"restart:amf", "sidecars:amf"},
		},
		{
			name:      "start NF with sidecar lists it",
			target:    "smf",
			fake:      &fakeLifecycle{sidecars: map[string][]string{"smf": {"smf-pcap"}}},
			wantCode:  http.StatusOK,
			wantJSON:  `{"status":"started","sidecars":["smf-pcap"]}`,
			wantCalls: []string{"start:smf", "sidecars:smf"},
		},
		{
			name:      "restart without sidecar keeps legacy body",
			target:    "postgres",
			restart:   true,
			fake:      &fakeLifecycle{},
			wantCode:  http.StatusOK,
			wantJSON:  `{"status":"restarting"}`,
			wantCalls: []string{"restart:postgres", "sidecars:postgres"},
		},
		{
			name:    "sidecar failure does not fail the restart",
			target:  "upf",
			restart: true,
			fake: &fakeLifecycle{sidecarErrs: map[string]map[string]error{
				"upf": {"upf-pcap": errors.New("boom")},
			}},
			wantCode:  http.StatusOK,
			wantJSON:  `{"status":"restarting","sidecar_errors":{"upf-pcap":"boom"}}`,
			wantCalls: []string{"restart:upf", "sidecars:upf"},
		},
		{
			name:      "restart failure skips sidecar recovery",
			target:    "nrf",
			restart:   true,
			fake:      &fakeLifecycle{actionErr: errors.New("no such container")},
			wantCode:  http.StatusInternalServerError,
			wantErr:   true,
			wantCalls: []string{"restart:nrf"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, body, err := startOrRestart(context.Background(), tc.fake, tc.target, tc.restart)
			if code != tc.wantCode {
				t.Fatalf("code = %d, want %d", code, tc.wantCode)
			}
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if len(tc.fake.calls) != len(tc.wantCalls) {
				t.Fatalf("calls = %v, want %v", tc.fake.calls, tc.wantCalls)
			}
			for i := range tc.wantCalls {
				if tc.fake.calls[i] != tc.wantCalls[i] {
					t.Fatalf("calls = %v, want %v", tc.fake.calls, tc.wantCalls)
				}
			}
			if tc.wantErr {
				return
			}
			got, _ := json.Marshal(body)
			if string(got) != tc.wantJSON {
				t.Fatalf("body = %s, want %s", got, tc.wantJSON)
			}
		})
	}
}
