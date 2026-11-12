package types

import (
	"reflect"
	"testing"
)

func TestValidGpsi(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"msisdn-490123456789", true},
		{"msisdn-12345", true},
		{"extid-user@example.com", true},
		{"anything-else", true}, // ".+" alternative of the schema pattern
		{"", false},
		{"bad\nline", false},
	}
	for _, tc := range tests {
		if got := ValidGpsi(tc.in); got != tc.want {
			t.Errorf("ValidGpsi(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestFilterGpsis(t *testing.T) {
	valid, rej := FilterGpsis([]string{"msisdn-490123456789", "", "msisdn-490123456789", "a\nb", "extid-u@x"})
	if !reflect.DeepEqual(valid, []string{"msisdn-490123456789", "extid-u@x"}) {
		t.Errorf("valid = %v", valid)
	}
	if !reflect.DeepEqual(rej, []string{"", "a\nb"}) {
		t.Errorf("rejected = %v", rej)
	}
}

func TestStrictGpsi(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"msisdn-12345", true},
		{"msisdn-490123456789012", true},
		{"msisdn-1234567890123456", false}, // 16 digits
		{"msisdn-12", false},
		{"msisdn-abc", false},
		{"msisdn-", false},
		{"msisdn-12345\n", false},
		{"extid-u@example.com", true},
		{"extid-u@a@b", false},
		{"extid-@x", false},
		{"extid-u@", false},
		{"anything-else", false}, // valid for ValidGpsi, not for the write side
		{"", false},
	}
	for _, tc := range tests {
		if got := StrictGpsi(tc.in); got != tc.want {
			t.Errorf("StrictGpsi(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
	// Received-data rule stays the verbatim spec pattern.
	if !ValidGpsi("msisdn-12") || !ValidGpsi("anything-else") {
		t.Error("ValidGpsi must keep accepting received values via the spec catch-all")
	}
}
