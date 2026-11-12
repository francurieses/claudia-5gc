package n32c

import "testing"

func TestPlmnIdStringCanonical(t *testing.T) {
	a := PlmnId{Mcc: "001", Mnc: "02"}
	b, err := ParsePLMNFromFQDN("sepp.5gc.mnc002.mcc001.3gppnetwork.org")
	if err != nil {
		t.Fatal(err)
	}
	if a.String() != b.String() || a.String() != "001/002" {
		t.Fatalf("String() = %q / %q, want both 001/002", a.String(), b.String())
	}
}
