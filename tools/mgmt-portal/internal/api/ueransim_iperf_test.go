package api

import (
	"strings"
	"testing"
)

func TestIperfRequestNormalize(t *testing.T) {
	ok := iperfRequest{Container: "ueransim-ue-gold", UEIP: "10.60.0.3"}
	if msg := ok.normalize(); msg != "" {
		t.Fatalf("valid request rejected: %s", msg)
	}
	if ok.Network != "5gc-n6" || ok.Protocol != "tcp" || ok.Direction != "ul" || ok.Duration != 5 || ok.Streams != 1 {
		t.Errorf("defaults not applied: %+v", ok)
	}

	clamp := iperfRequest{Container: "ueransim-ue", UEIP: "10.60.0.3", Duration: 999, Streams: 99, Protocol: "udp", Bandwidth: "500K"}
	if msg := clamp.normalize(); msg != "" {
		t.Fatalf("clamp request rejected: %s", msg)
	}
	if clamp.Duration != iperfMaxDurationSec || clamp.Streams != iperfMaxStreams || clamp.Bandwidth != "500K" {
		t.Errorf("clamping wrong: %+v", clamp)
	}

	bad := []iperfRequest{
		{UEIP: "10.60.0.3"},
		{Container: "postgres", UEIP: "10.60.0.3"},
		{Container: "ueransim-ue", UEIP: "not-an-ip"},
		{Container: "ueransim-ue", UEIP: "2001:db8::1"},
		{Container: "ueransim-ue", UEIP: "10.60.0.3", Network: "bridge"},
		{Container: "ueransim-ue", UEIP: "10.60.0.3", Protocol: "sctp"},
		{Container: "ueransim-ue", UEIP: "10.60.0.3", Direction: "both"},
		{Container: "ueransim-ue", UEIP: "10.60.0.3", Protocol: "udp", Bandwidth: "10M; rm -rf /"},
		{Container: "ueransim-ue", UEIP: "10.60.0.3", Bandwidth: "fast"},
		{Container: "ueransim-ue", UEIP: "10.60.0.3", ServerIP: "example.com"},
		{Container: "ueransim-ue", UEIP: "10.60.0.3", ServerIP: "127.0.0.1"},
		{Container: "ueransim-ue", UEIP: "10.60.0.3", ServerIP: "224.0.0.1"},
		{Container: "ueransim-ue", UEIP: "10.60.0.3", ServerIP: "::1"},
		{Container: "ueransim-ue", UEIP: "10.60.0.3", ServerPort: 70000},
	}
	for i, b := range bad {
		if msg := b.normalize(); msg == "" {
			t.Errorf("bad[%d] accepted: %+v", i, b)
		}
	}
}

func TestIperfClientArgs(t *testing.T) {
	r := iperfRequest{Container: "ueransim-ue", UEIP: "10.60.0.3", Protocol: "udp", Direction: "dl", Bandwidth: "20M", Duration: 7, Streams: 2}
	r.normalize()
	got := strings.Join(r.clientArgs("172.30.6.9"), " ")
	for _, want := range []string{"-c 172.30.6.9", "-B 10.60.0.3", "-t 7", "-P 2", "-u -b 20M", "-R", "-J"} {
		if !strings.Contains(got, want) {
			t.Errorf("args %q missing %q", got, want)
		}
	}
	tcp := iperfRequest{Container: "ueransim-ue", UEIP: "10.60.0.3"}
	tcp.normalize()
	if a := strings.Join(tcp.clientArgs("1.2.3.4"), " "); strings.Contains(a, "-u") || strings.Contains(a, "-R") {
		t.Errorf("tcp/ul args must not carry -u/-R: %s", a)
	}
}

func TestParseIperfJSONTCP(t *testing.T) {
	out := `banner
{"end":{"sum_sent":{"seconds":5,"bits_per_second":120000000,"retransmits":3},"sum_received":{"seconds":5,"bits_per_second":118000000}}}`
	s, err := parseIperfJSON(out)
	if err != nil {
		t.Fatal(err)
	}
	if s.Mbps != 118 || s.Retransmits == nil || *s.Retransmits != 3 {
		t.Errorf("tcp summary wrong: %+v", s)
	}
}

func TestParseIperfJSONUDP(t *testing.T) {
	out := `{"end":{"sum":{"seconds":5,"bits_per_second":10000000,"jitter_ms":0.12,"lost_packets":0,"packets":4300,"lost_percent":0}}}`
	s, err := parseIperfJSON(out)
	if err != nil {
		t.Fatal(err)
	}
	if s.Mbps != 10 || s.JitterMs == nil || *s.JitterMs != 0.12 || s.LossPercent == nil || *s.LossPercent != 0 {
		t.Errorf("udp summary wrong: %+v", s)
	}
}

func TestParseIperfJSONErrors(t *testing.T) {
	if _, err := parseIperfJSON(`{"error":"unable to connect to server: Connection refused"}`); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Errorf("iperf3 error not surfaced: %v", err)
	}
	if _, err := parseIperfJSON("not json"); err == nil {
		t.Error("garbage accepted")
	}
	if _, err := parseIperfJSON(`{"end":{}}`); err == nil {
		t.Error("empty end accepted")
	}
}

func TestParseIperfServerPeer(t *testing.T) {
	log := "-----\nServer listening on 5201\nAccepted connection from 172.30.6.2, port 41234\n"
	if p := parseIperfServerPeer(log); p != "172.30.6.2" {
		t.Errorf("peer = %q", p)
	}
	if p := parseIperfServerPeer("nothing"); p != "" {
		t.Errorf("peer = %q, want empty", p)
	}
}

func TestIperfServerAndBandwidthOptions(t *testing.T) {
	r := iperfRequest{Container: "ueransim-ue", UEIP: "10.60.0.3", ServerIP: " 192.168.1.50 ", ServerPort: 5300, Bandwidth: " 50m "}
	if msg := r.normalize(); msg != "" {
		t.Fatalf("rejected: %s", msg)
	}
	if r.ServerIP != "192.168.1.50" || r.Bandwidth != "50M" || r.Protocol != "tcp" {
		t.Errorf("normalised wrong: %+v", r)
	}
	args := strings.Join(r.clientArgs(r.ServerIP), " ")
	for _, want := range []string{"-c 192.168.1.50", "-p 5300", "-b 50M"} {
		if !strings.Contains(args, want) {
			t.Errorf("args %q missing %q", args, want)
		}
	}
	if strings.Contains(args, " -u") {
		t.Errorf("tcp must not carry -u: %s", args)
	}
	// TCP without bandwidth stays unlimited; default port 5201.
	u := iperfRequest{Container: "ueransim-ue", UEIP: "10.60.0.3"}
	u.normalize()
	if a := strings.Join(u.clientArgs("1.2.3.4"), " "); strings.Contains(a, "-b") || !strings.Contains(a, "-p 5201") {
		t.Errorf("tcp defaults wrong: %s", a)
	}
}

func TestParseIperfJSONTrailingText(t *testing.T) {
	out := `{"error":"unable to connect to server: Connection refused"}` + "\niperf3: error - unable to connect to server\n"
	_, err := parseIperfJSON(out)
	if err == nil || !strings.Contains(err.Error(), "Connection refused") {
		t.Errorf("error not surfaced past trailing text: %v", err)
	}
}

func TestParseIperfJSONTextErrorLine(t *testing.T) {
	out := "{\n\t\"end\":\t{\n\t}\n}\niperf3: error - unable to send control message: Bad file descriptor\n"
	_, err := parseIperfJSON(out)
	if err == nil || !strings.Contains(err.Error(), "Bad file descriptor") {
		t.Errorf("text error line not surfaced: %v", err)
	}
}

func TestAdjustUDPUplink(t *testing.T) {
	loss := 87.5
	sum := &iperfSummary{Mbps: 1000, LossPercent: &loss}
	adjustUDPUplink(&iperfRequest{Protocol: "udp", Direction: "ul"}, sum)
	if sum.OfferedMbps == nil || *sum.OfferedMbps != 1000 || sum.Mbps != 125 {
		t.Errorf("udp ul not adjusted: %+v", sum)
	}
	// Downlink: the client is the receiver, bits_per_second is already the delivered rate.
	dl := &iperfSummary{Mbps: 125, LossPercent: &loss}
	adjustUDPUplink(&iperfRequest{Protocol: "udp", Direction: "dl"}, dl)
	if dl.OfferedMbps != nil || dl.Mbps != 125 {
		t.Errorf("udp dl must not be adjusted: %+v", dl)
	}
	// TCP is untouched.
	tcp := &iperfSummary{Mbps: 100}
	adjustUDPUplink(&iperfRequest{Protocol: "tcp", Direction: "ul"}, tcp)
	if tcp.OfferedMbps != nil || tcp.Mbps != 100 {
		t.Errorf("tcp adjusted: %+v", tcp)
	}
}

func TestIperfErrorHint(t *testing.T) {
	if got := iperfErrorHint("iperf3: unable to send control message: Bad file descriptor"); !strings.Contains(got, "Ping") {
		t.Errorf("no hint added: %q", got)
	}
	if got := iperfErrorHint("iperf3: some other failure"); got != "iperf3: some other failure" {
		t.Errorf("unrelated error altered: %q", got)
	}
}
