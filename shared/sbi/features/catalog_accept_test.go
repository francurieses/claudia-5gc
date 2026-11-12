package features

import (
	"errors"
	"testing"
)

// TestAcceptAnswer covers the Accept + always-validate helper (R13/R14).
func TestAcceptAnswer(t *testing.T) {
	tests := []struct {
		name, offer, answer string
		want                string
		bad                 bool
	}{
		{"intersection", "3", "5", "1", false},
		{"empty offer valid answer", "", "ff", "0", false},
		{"zero offer valid answer", "0", "ff", "0", false},
		{"empty answer", "3", "", "0", false},
		{"malformed answer, empty offer", "", "zz", "", true},
		{"malformed answer, zero offer", "0", "zz", "", true},
		{"malformed answer, real offer", "3", "zz", "", true},
		{"bad offer", "zz", "1", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := AcceptAnswer(tc.offer, tc.answer)
			if tc.bad {
				if err == nil || !got.IsEmpty() {
					t.Fatalf("want error + empty set, got %v %v", got, err)
				}
				return
			}
			if err != nil || got.String() != tc.want {
				t.Fatalf("got %q %v want %q", got.String(), err, tc.want)
			}
		})
	}
	// Accept keeps skipping validation on an empty offer.
	if _, err := Accept("", "zz"); err != nil {
		t.Errorf("Accept semantics changed: %v", err)
	}
	if _, err := AcceptAnswer("3", "zz"); !errors.Is(err, ErrInvalid) {
		t.Errorf("want ErrInvalid, got %v", err)
	}
}
