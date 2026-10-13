package qos

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/francurieses/claudia-5gc/mcp/internal/clients"
	"github.com/francurieses/claudia-5gc/mcp/internal/mcperr"
)

func TestSubscriptionAMGet(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if strings.Contains(r.URL.Path, "imsi-001010000000099") {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"nssai":{"defaultSingleNssais":[{"sd":"000001","sst":1}]},"subscribedUeAmbr":{"downlink":"100000 Kbps","uplink":"100000 Kbps"}}`))
	}))
	defer srv.Close()
	tool := subscriptionAMGetTool{clients.NewUDM(srv.URL, srv.Client())}

	tests := []struct {
		name     string
		args     string
		wantCode int
		wantHits int32
	}{
		{"ok", `{"supi":"imsi-001010000000001"}`, 0, 1},
		{"malformed supi", `{"supi":"not-a-supi"}`, mcperr.CodeInvalidParams, 0},
		{"404", `{"supi":"imsi-001010000000099"}`, mcperr.CodeToolError, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hits.Store(0)
			out, err := tool.Invoke(context.Background(), json.RawMessage(tc.args))
			if tc.wantCode == 0 {
				if err != nil {
					t.Fatalf("invoke: %v", err)
				}
				if !strings.Contains(string(out.(json.RawMessage)), "defaultSingleNssais") {
					t.Errorf("not passed through: %s", out)
				}
			} else {
				var me *mcperr.Error
				if !errors.As(err, &me) || me.Code != tc.wantCode {
					t.Fatalf("want code %d, got %v", tc.wantCode, err)
				}
			}
			if hits.Load() != tc.wantHits {
				t.Errorf("UDM hits %d, want %d", hits.Load(), tc.wantHits)
			}
		})
	}
}
