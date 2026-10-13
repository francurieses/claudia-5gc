package clients

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPortalStoreStatus(t *testing.T) {
	tests := []struct {
		name, body string
		status     int
		want       StoreState
	}{
		{"up", `{"status":"ok","store":"up"}`, 200, StoreUp},
		{"down", `{"status":"ok","store":"down"}`, 200, StoreDown},
		{"empty body (older portal)", ``, 200, StoreUnknown},
		{"field absent", `{"status":"ok"}`, 200, StoreUnknown},
		{"not json", `ok`, 200, StoreUnknown},
		{"404", ``, 404, StoreUnknown},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			if got := NewPortal(srv.URL, http.DefaultClient).StoreStatus(context.Background()); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close()
	reachable, st := NewPortal(srv.URL, http.DefaultClient).Health(context.Background())
	if reachable || st != StoreUnknown {
		t.Fatalf("unreachable: %v %q", reachable, st)
	}
}
