package ueransim

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newTestClient(srvURL string) *PortalClient {
	return NewPortalClient(srvURL, "ueransim-ue", time.Second, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestNRCLI_NotDeployed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":"ueransim is not deployed in the current mode","code":"RAN_TOOL_NOT_DEPLOYED","tool":"ueransim"}`))
	}))
	defer srv.Close()

	_, err := newTestClient(srv.URL).UEStatus(context.Background(), "imsi-001010000000001")
	if !errors.Is(err, ErrNotDeployed) {
		t.Fatalf("err = %v, want ErrNotDeployed", err)
	}
}

func TestNRCLI_OtherConflictIsNotMappedToNotDeployed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":"busy"}`))
	}))
	defer srv.Close()

	_, err := newTestClient(srv.URL).UEStatus(context.Background(), "imsi-001010000000001")
	if err == nil || errors.Is(err, ErrNotDeployed) {
		t.Fatalf("err = %v, want a generic status error", err)
	}
}
