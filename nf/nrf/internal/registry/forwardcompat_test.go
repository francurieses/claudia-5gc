package registry

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestForwardCompat: the Redis-stored profile carries schema_version, keeps
// unknown Rel-20 keys, and decode strips the storage-only version.
func TestForwardCompat(t *testing.T) {
	in := `{"nfInstanceId":"a","nfType":"AMF","nfStatus":"REGISTERED","rel20Attr":{"x":1}}`
	var p NFProfile
	if err := json.Unmarshal([]byte(in), &p); err != nil {
		t.Fatal(err)
	}
	js, err := encodeProfile(&p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(js), `"schema_version":1`) || !strings.Contains(string(js), `"rel20Attr":{"x":1}`) {
		t.Fatalf("stored: %s", js)
	}
	q, err := decodeProfile(js)
	if err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(q)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "schema_version") || !strings.Contains(string(out), `"rel20Attr":{"x":1}`) {
		t.Fatalf("served: %s", out)
	}
	// A newer stored version is not lowered.
	newer := strings.Replace(string(js), `"schema_version":1`, `"schema_version":7`, 1)
	r, _ := decodeProfile([]byte(newer))
	if strings.Contains(string(r.raw), "schema_version") {
		t.Errorf("raw not stripped: %s", r.raw)
	}
}
