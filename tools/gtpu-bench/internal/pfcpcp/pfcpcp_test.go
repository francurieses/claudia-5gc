package pfcpcp

import (
	"net"
	"testing"

	pfcpmsg "github.com/wmnsk/go-pfcp/message"
)

func TestNewSessionRanges(t *testing.T) {
	s := NewSession(3, net.IPv4(10, 60, 0, 200))
	if s.SEID < SEIDBase || s.ULTEID < TEIDBase || s.DLTEID < TEIDBase || s.UEIP.String() != "10.60.0.203" {
		t.Fatalf("session %+v outside reserved ranges", s)
	}
	if s.ULTEID == s.DLTEID {
		t.Fatal("UL and DL TEID must differ")
	}
}

// TestPFCPBuildersRoundTrip marshals each request and parses it back through go-pfcp.
func TestPFCPBuildersRoundTrip(t *testing.T) {
	s := NewSession(0, net.IPv4(10, 60, 0, 200))
	reqs := map[string]interface{ Marshal() ([]byte, error) }{
		"est": EstablishmentRequest(1, s, net.IPv4(172, 30, 3, 100), "internet"),
		"mod": ModificationRequest(2, s, net.IPv4(172, 30, 3, 20)),
		"del": DeletionRequest(3, s),
	}
	for name, r := range reqs {
		b, err := r.Marshal()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := pfcpmsg.Parse(b); err != nil {
			t.Fatalf("%s: parse: %v", name, err)
		}
	}
	b, _ := reqs["est"].Marshal()
	m, _ := pfcpmsg.Parse(b)
	est := m.(*pfcpmsg.SessionEstablishmentRequest)
	f, err := est.CPFSEID.FSEID()
	if err != nil || f.SEID != s.SEID {
		t.Fatalf("F-SEID = %+v err=%v", f, err)
	}
}
