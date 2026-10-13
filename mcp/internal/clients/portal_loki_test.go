package clients

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPortalRedactsKeys(t *testing.T) {
	in := []byte(`{"subscribers":[{"supi":"imsi-001010000000001","k":"465b5ce8b199b49faa5f0a2ee238a6bc",
		"opc":"cd63cb71954a9f4e48a5994e37a02baf","op":"x","sqn":"000000000020","dnn":"internet",
		"nested":{"K":"upper-case-key-also-redacted"}}]}`)
	out, err := Redact(in)
	if err != nil {
		t.Fatalf("redact: %v", err)
	}
	s := string(out)
	for _, secret := range []string{"465b5ce8", "cd63cb71", "upper-case-key"} {
		if strings.Contains(s, secret) {
			t.Errorf("secret %q leaked: %s", secret, s)
		}
	}
	var v map[string]any
	_ = json.Unmarshal(out, &v)
	sub := v["subscribers"].([]any)[0].(map[string]any)
	if sub["k"] != "<redacted>" || sub["opc"] != "<redacted>" || sub["sqn"] != "<redacted>" {
		t.Errorf("keys not redacted: %v", sub)
	}
	if sub["supi"] != "imsi-001010000000001" || sub["dnn"] != "internet" {
		t.Errorf("non-secret fields changed: %v", sub)
	}
}

func TestRedactRejectsNothingAndKeepsNull(t *testing.T) {
	out, err := Redact([]byte(""))
	if err != nil || string(out) != "null" {
		t.Errorf("empty body: got (%s, %v), want null", out, err)
	}
	if _, err := Redact([]byte("<html>")); err == nil {
		t.Error("non-JSON must be an error from Redact")
	}
}

func TestPortalPostNonJSONIsNotPassedThrough(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte("k=465b5ce8 plain text error"))
	}))
	defer srv.Close()
	body, status, err := NewPortal(srv.URL, http.DefaultClient).Post(context.Background(), "/pcap/AMF/start", nil)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	if status != http.StatusConflict {
		t.Errorf("status: %d", status)
	}
	if !strings.HasPrefix(string(body), `"`) {
		t.Errorf("non-JSON body must come back as a JSON string: %s", body)
	}
}

func TestPortalGetErrorCarriesStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	if _, err := NewPortal(srv.URL, http.DefaultClient).Get(context.Background(), "/deployment", nil); err == nil ||
		!strings.Contains(err.Error(), "status 500") {
		t.Errorf("want status 500 error, got %v", err)
	}
}

func TestLokiQueryRangeSortsAcrossStreams(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/loki/api/v1/query_range" || r.URL.Query().Get("direction") != "backward" {
			t.Errorf("unexpected request %s", r.URL)
		}
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"streams","result":[
		 {"stream":{"nf":"SMF"},"values":[["2000000000","second"]]},
		 {"stream":{"nf":"AMF"},"values":[["1000000000","first"]]}]}}`))
	}))
	defer srv.Close()
	start := time.Unix(0, 0)
	lines, err := NewLoki(srv.URL, http.DefaultClient).QueryRange(context.Background(), `{nf=~".+"}`, start, start.Add(time.Hour), 10)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(lines) != 2 || lines[0].Line != "first" || lines[1].Labels["nf"] != "SMF" {
		t.Errorf("order or labels wrong: %+v", lines)
	}
}

func TestLokiQueryMetric(t *testing.T) {
	var gotPath, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery = r.URL.Path, r.URL.Query().Get("query")
		if gotQuery == "streams" {
			_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"streams","result":[]}}`))
			return
		}
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[
		 {"metric":{"nf":"AMF","cause":"90"},"value":[1.7,"1806"]},
		 {"metric":{"nf":"SMF"},"value":[1.7,"bad"]}]}}`))
	}))
	defer srv.Close()
	l := NewLoki(srv.URL, srv.Client())
	got, err := l.QueryMetric(context.Background(), "sum(count_over_time({nf=~\".+\"}[5m]))", time.Time{})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if gotPath != "/loki/api/v1/query" || !strings.Contains(gotQuery, "count_over_time") {
		t.Errorf("path/query: %s %s", gotPath, gotQuery)
	}
	if len(got) != 1 || got[0].Labels["nf"] != "AMF" || got[0].Value != 1806 {
		t.Errorf("samples: %+v", got)
	}
	if _, err := l.QueryMetric(context.Background(), "streams", time.Time{}); err == nil {
		t.Error("non-vector result must be an error")
	}
}
