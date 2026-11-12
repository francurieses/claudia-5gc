package store

import (
	"encoding/json"
	"testing"
)

// TestForwardCompat: Rel-20 keys survive JSON round trip and the extra column
// encode/decode used by Postgres (TS 29.500 §6.6.2).
func TestForwardCompat(t *testing.T) {
	in := `{"supi":"imsi-1","dnn":"internet","ue_ip":"10.0.0.1","ul_teid":1,"seid":2,"sst":1,"sd":"","pdu_session_id":5,"schema_version":2,"rel20":{"k":[1]}}`
	var s SessionRecord
	if err := json.Unmarshal([]byte(in), &s); err != nil {
		t.Fatal(err)
	}
	// Through the DB column.
	col, err := encodeExtra(s.Extra)
	if err != nil {
		t.Fatal(err)
	}
	extra, err := decodeExtra(col)
	if err != nil {
		t.Fatal(err)
	}
	s2 := s
	s2.Extra = extra
	out, err := json.Marshal(s2)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != in {
		t.Fatalf("not unchanged:\n%s\n%s", in, out)
	}
}

func TestExtraEdgeCases(t *testing.T) {
	if b, _ := encodeExtra(nil); string(b) != "{}" {
		t.Errorf("empty: %s", b)
	}
	if m, err := decodeExtra(nil); m != nil || err != nil {
		t.Error("nil col")
	}
	if m, err := decodeExtra([]byte("{}")); m != nil || err != nil {
		t.Error("empty obj")
	}
	if _, err := decodeExtra([]byte("[")); err == nil {
		t.Error("want error")
	}
	b, _ := json.Marshal(SessionRecord{})
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if m["schema_version"] != float64(SessionSchemaVersion) {
		t.Errorf("version %v", m["schema_version"])
	}
}
