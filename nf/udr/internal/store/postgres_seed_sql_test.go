package store

import (
	"strings"
	"testing"
)

// TestSeedSliceQoSSQLGuard asserts the seed upsert keeps an edited row (design
// step A4) without needing a live database; behaviour is covered by the live gate.
func TestSeedSliceQoSSQLGuard(t *testing.T) {
	sql := strings.Join(strings.Fields(seedSliceQoSSQL), " ")
	for _, col := range []string{"session_ambr_ul", "session_ambr_dl", "source"} {
		want := col + " = CASE WHEN slice_dnn_qos.source = 'edited' THEN slice_dnn_qos." + col + " ELSE EXCLUDED." + col + " END"
		if !strings.Contains(sql, want) {
			t.Errorf("seed SQL lacks edited guard for %s", col)
		}
	}
	for _, col := range []string{"seed_ambr_ul", "seed_ambr_dl", "seed_source"} {
		if !strings.Contains(sql, col+" = EXCLUDED."+col) {
			t.Errorf("seed SQL must always refresh %s", col)
		}
	}
	if !strings.Contains(sql, "RETURNING") {
		t.Error("seed SQL must RETURN the stored row")
	}
}
