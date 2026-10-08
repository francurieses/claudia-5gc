package tun

import (
	"strings"
	"testing"
)

// TestMSSClampArgs pins the iptables rule composition (no exec).
func TestMSSClampArgs(t *testing.T) {
	got := strings.Join(MSSClampArgs("-A", "-o", "upfgtp0"), " ")
	want := "-t mangle -A FORWARD -o upfgtp0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if c := strings.Join(MSSClampArgs("-C", "-i", "upfgtp1"), " "); !strings.Contains(c, "-C FORWARD -i upfgtp1") {
		t.Fatalf("check/ingress form wrong: %q", c)
	}
}
