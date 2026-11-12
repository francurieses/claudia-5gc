package capability

import "testing"

func TestRegistryRegisterLookup(t *testing.T) {
	f := Feature{ID: "TEST-REG-1", Title: "t", Release: Rel19, Visibility: "public"}
	if err := Register(f); err != nil {
		t.Fatalf("Register: %v", err)
	}
	got, ok := Lookup("TEST-REG-1")
	if !ok || got.Title != "t" || got.Release != Rel19 {
		t.Fatalf("Lookup = %+v, %v", got, ok)
	}
	if _, ok := Lookup("TEST-REG-MISSING"); ok {
		t.Fatal("Lookup found unregistered ID")
	}
}

func TestRegistryRejects(t *testing.T) {
	tests := []struct {
		name string
		f    Feature
		pre  bool
	}{
		{"empty ID", Feature{}, false},
		{"duplicate ID", Feature{ID: "TEST-REG-DUP"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.pre {
				if err := Register(tt.f); err != nil {
					t.Fatal(err)
				}
			}
			if err := Register(tt.f); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestReleaseString(t *testing.T) {
	if got := Rel19.String(); got != "Rel-19" {
		t.Fatalf("got %q", got)
	}
}
