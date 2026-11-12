package server

import (
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"

	"github.com/francurieses/claudia-5gc/nf/udr/internal/store"
	"github.com/francurieses/claudia-5gc/shared/capability"
)

// goldenServerWithGPSIs is goldenServer with GPSIs stored on the AM record.
func goldenServerWithGPSIs(t *testing.T, prof *capability.Profile, gpsis []string) *httptest.Server {
	t.Helper()
	st := store.NewInMemory()
	if err := store.SeedTestSubscriberWithNSSAI(st, goldenSUPI,
		"465b5ce8b199b49faa5f0a2ee238a6bc", "cd63cb71954a9f4e48a5994e37a02baf", "b9b9", "000000000020",
		[]store.SNSSAISubscribed{{SST: 1, SD: "000001"}}); err != nil {
		t.Fatal(err)
	}
	am, err := st.GetAMSubscription(goldenSUPI)
	if err != nil {
		t.Fatal(err)
	}
	am.GPSIS = gpsis
	if err := st.PutAMSubscription(am); err != nil {
		t.Fatal(err)
	}
	srv, err := New(":0", TLSConfig{}, st, slog.New(slog.NewTextHandler(io.Discard, nil)).With("nf", "UDR"))
	if err != nil {
		t.Fatal(err)
	}
	if prof != nil {
		srv.SetProfile(prof)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}
