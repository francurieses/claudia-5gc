package store

import (
	"encoding/json"
	"testing"
)

// TestForwardCompat: a record carrying Rel-20 keys and a newer schema_version
// survives a load→save cycle unchanged (TS 29.500 §6.6.2).
func TestForwardCompat(t *testing.T) {
	in := `{"supi":"imsi-1","gmm_state":1,"cm_state":0,"security_ctx":{"ngksi":0,"integrity_alg_id":0,"ciphering_alg_id":0,"uplink_count":0,"downlink_count":0,"active":false},"allowed_nssai":null,"subscribed_ambr_ul":0,"subscribed_ambr_dl":0,"pdu_sessions":null,"registration_time":"0001-01-01T00:00:00Z","last_activity":"0001-01-01T00:00:00Z","schema_version":2,"rel20_x":{"a":[1,2]},"rel20_y":"v"}`
	rec, err := unmarshalRecord([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Extra) != 2 {
		t.Fatalf("extra=%v", rec.Extra)
	}
	out, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	var a, b map[string]json.RawMessage
	_ = json.Unmarshal([]byte(in), &a)
	_ = json.Unmarshal(out, &b)
	if len(a) != len(b) {
		t.Fatalf("keys differ:\n%s\n%s", in, out)
	}
	for k, v := range a {
		if string(v) != string(b[k]) {
			t.Errorf("key %s: %s != %s", k, v, b[k])
		}
	}
}

func TestSchemaVersionStamped(t *testing.T) {
	out, err := json.Marshal(&UERecord{SUPI: "imsi-1"})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(out, &m)
	if m["schema_version"] != float64(UERecordSchemaVersion) {
		t.Errorf("schema_version=%v", m["schema_version"])
	}
}

func TestForwardCompatBadJSON(t *testing.T) {
	if _, err := unmarshalRecord([]byte(`[1]`)); err == nil {
		t.Error("want error")
	}
}
