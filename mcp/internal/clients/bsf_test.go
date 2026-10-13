package clients

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestBSFDiscover(t *testing.T) {
	var gotPath, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery = r.URL.Path, r.URL.RawQuery
		if r.URL.Query().Get("supi") == "imsi-001010000000098" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.URL.Query().Get("supi") == "imsi-001010000000099" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"bindingId":"b1","ipv4Addr":"10.60.0.1"}`))
	}))
	defer srv.Close()
	c := NewBSF(srv.URL+"/", srv.Client())

	b, err := c.Discover(context.Background(), url.Values{"ipv4Addr": {"10.60.0.1"}})
	if err != nil || b == nil {
		t.Fatalf("discover: %v %s", err, b)
	}
	if gotPath != "/nbsf-management/v1/pcfBindings" || gotQuery != "ipv4Addr=10.60.0.1" {
		t.Errorf("path/query: %s ?%s", gotPath, gotQuery)
	}
	b, err = c.Discover(context.Background(), url.Values{"supi": {"imsi-001010000000099"}})
	if err != nil || b != nil {
		t.Errorf("404 must be (nil,nil), got %v %v", b, err)
	}
	b, err = c.Discover(context.Background(), url.Values{"supi": {"imsi-001010000000098"}})
	if err != nil || b != nil {
		t.Errorf("204 must be (nil,nil), got %v %v", b, err)
	}
}

func TestBSFDiscoverError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusBadRequest)
	}))
	defer srv.Close()
	if _, err := NewBSF(srv.URL, srv.Client()).Discover(context.Background(), nil); err == nil {
		t.Error("want error on 400")
	}
}

func TestUDMGetAMData(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if r.URL.Path == "/nudm-sdm/v2/imsi-001010000000099/am-data" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"nssai":{}}`))
	}))
	defer srv.Close()
	c := NewUDM(srv.URL, srv.Client())
	b, err := c.GetAMData(context.Background(), "imsi-001010000000001")
	if err != nil || b == nil || gotPath != "/nudm-sdm/v2/imsi-001010000000001/am-data" {
		t.Fatalf("get: %v %s %s", err, b, gotPath)
	}
	if b, err = c.GetAMData(context.Background(), "imsi-001010000000099"); b != nil || err != nil {
		t.Errorf("404 want (nil,nil), got %v %v", b, err)
	}
}
