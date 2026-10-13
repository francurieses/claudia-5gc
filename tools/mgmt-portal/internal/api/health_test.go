package api

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestHealthStoreDown(t *testing.T) {
	rec := do(t, newFakeRouter(t), http.MethodGet, "/api/v1/health", "application/json")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var got map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("body not JSON: %v (%q)", err, rec.Body.String())
	}
	if got["status"] != "ok" || got["store"] != "down" {
		t.Fatalf("body = %v, want status=ok store=down", got)
	}
}

func TestHealthResponseShape(t *testing.T) {
	b, err := json.Marshal(healthResponse{Status: "ok", Store: "up"})
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"status":"ok","store":"up"}` {
		t.Fatalf("shape = %s", b)
	}
}
