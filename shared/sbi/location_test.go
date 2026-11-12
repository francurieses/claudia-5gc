package sbi

import "testing"

func TestResourceIDFromLocationUnder(t *testing.T) {
	const am = "/npcf-am-policy-control/v1/policies"
	tests := []struct {
		name, loc, coll, want string
	}{
		{"absolute", "https://pcf:8006" + am + "/abc-1", am, "abc-1"},
		{"relative", am + "/abc-1", am, "abc-1"},
		{"trailing slash", "https://pcf:8006" + am + "/p9/", am, "p9"},
		{"collection with trailing slash", am + "/p9", am + "/", "p9"},
		{"query and fragment", "https://pcf:8006" + am + "/s1?foo=a/b#frag", am, "s1"},
		{"wrong collection", "https://pcf:8006/npcf-ue-policy-control/v1/policies/x", am, ""},
		{"collection prefix only", "https://pcf:8006" + am + "x/abc", am, ""},
		{"extra segments", "https://pcf:8006" + am + "/abc/extra", am, ""},
		{"no id", "https://pcf:8006" + am, am, ""},
		{"no id trailing slash", "https://pcf:8006" + am + "/", am, ""},
		{"host only", "https://pcf:8006", am, ""},
		{"empty", "", am, ""},
		{"blank", "   ", am, ""},
		{"garbage", "http://[::1", am, ""},
		{"control char", "https://pcf/\x7f%zz", am, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ResourceIDFromLocationUnder(tt.loc, tt.coll); got != tt.want {
				t.Errorf("ResourceIDFromLocationUnder(%q, %q) = %q, want %q", tt.loc, tt.coll, got, tt.want)
			}
		})
	}
}
