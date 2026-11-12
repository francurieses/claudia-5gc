package store

import (
	"reflect"
	"testing"
)

func TestDefaultMSISDN(t *testing.T) {
	tests := []struct {
		supi, want string
		ok         bool
	}{
		// Same literals as nf/udr TestSeedMSISDN (default prefix): the two
		// derivations must stay identical.
		{"imsi-001010000000001", "msisdn-4900000000001", true},
		{"imsi-001010000000204", "msisdn-4900000000204", true},
		{"imsi-0010100000", "", false},
		{"imsi-00101000000000x", "", false},
		{"nai-foo@bar", "", false},
	}
	for _, tc := range tests {
		got, ok := DefaultMSISDN(tc.supi)
		if got != tc.want || ok != tc.ok {
			t.Errorf("DefaultMSISDN(%q) = %q,%v want %q,%v", tc.supi, got, ok, tc.want, tc.ok)
		}
	}
}

func TestValidateGPSIs(t *testing.T) {
	if err := ValidateGPSIs([]string{"msisdn-490123456789", "extid-u@example.com"}); err != nil {
		t.Fatalf("valid list rejected: %v", err)
	}
	if err := ValidateGPSIs(nil); err != nil {
		t.Fatalf("nil rejected: %v", err)
	}
	if err := ValidateGPSIs([]string{"msisdn-490123456789", ""}); err == nil {
		t.Fatal("empty entry accepted")
	}
}

func TestValidateGPSIsStrict(t *testing.T) {
	for _, bad := range []string{"msisdn-12", "msisdn-abc", "msisdn-1234567890123456", "anything", "extid-@x", "extid-a@b@c"} {
		if err := ValidateGPSIs([]string{bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// TestStrictGPSILiterals pins this module's copy of the rule to the literals of
// shared/types.StrictGpsi (same table in shared/types/gpsi_test.go).
func TestStrictGPSILiterals(t *testing.T) {
	tests := map[string]bool{
		"msisdn-12345": true, "msisdn-490123456789012": true, "msisdn-1234567890123456": false,
		"msisdn-12": false, "msisdn-abc": false, "msisdn-": false, "msisdn-12345\n": false,
		"extid-u@example.com": true, "extid-u@a@b": false, "extid-@x": false, "extid-u@": false,
		"anything-else": false, "": false,
	}
	for in, want := range tests {
		if got := strictGpsi(in); got != want {
			t.Errorf("strictGpsi(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestGPSIPrefixEnv(t *testing.T) {
	const supi = "imsi-001010000000001"
	tests := []struct {
		env, want string
		ok        bool
	}{
		{"", "msisdn-4900000000001", true},
		{"49", "msisdn-490000000001", true},
		{"off", "", false},
		{"4a", "", false},
		{"123456", "", false}, // 16 digits
	}
	for _, tc := range tests {
		t.Setenv("SEED_GPSI_PREFIX", tc.env)
		got, ok := DefaultMSISDN(supi)
		if got != tc.want || ok != tc.ok {
			t.Errorf("env %q: %q,%v want %q,%v", tc.env, got, ok, tc.want, tc.ok)
		}
	}
}

// TestResolveGPSIsExplicitFlag: the explicit flag drives the SQL
// (CASE WHEN $6 THEN EXCLUDED.gpsis ELSE subscription_am.gpsis END). A
// non-explicit upsert must never overwrite stored gpsis (UPDATE path); the
// default is only the INSERT value. The SQL itself is not integration-tested.
func TestResolveGPSIsCreateVsUpdate(t *testing.T) {
	const supi = "imsi-001010000000001"
	got, explicit, _ := resolveGPSIs(supi, nil)
	if explicit || len(got) != 1 {
		t.Fatalf("create default: %v %v", got, explicit)
	}
	if _, explicit, _ := resolveGPSIs(supi, []string{}); !explicit {
		t.Fatal("[] must be explicit so a clear replaces the stored list")
	}
	t.Setenv("SEED_GPSI_PREFIX", "off")
	if got, explicit, _ := resolveGPSIs(supi, nil); explicit || len(got) != 0 {
		t.Fatalf("off: %v %v", got, explicit)
	}
}

func TestResolveGPSIs(t *testing.T) {
	const supi = "imsi-001010000000001"
	tests := []struct {
		name         string
		in           []string
		want         []string
		wantExplicit bool
		wantErr      bool
	}{
		{"unspecified -> default, not explicit", nil, []string{"msisdn-4900000000001"}, false, false},
		{"explicit replaces", []string{"msisdn-123456"}, []string{"msisdn-123456"}, true, false},
		{"explicit empty clears", []string{}, []string{}, true, false},
		{"invalid rejected", []string{"msisdn-12"}, nil, true, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, explicit, err := resolveGPSIs(supi, tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v", err)
			}
			if err == nil && (!reflect.DeepEqual(got, tc.want) || explicit != tc.wantExplicit) {
				t.Fatalf("got %v,%v want %v,%v", got, explicit, tc.want, tc.wantExplicit)
			}
		})
	}
	// A non-IMSI SUPI has no derivable default.
	if got, explicit, err := resolveGPSIs("nai-x@y", nil); err != nil || explicit || len(got) != 0 {
		t.Fatalf("non-IMSI: %v %v %v", got, explicit, err)
	}
}
