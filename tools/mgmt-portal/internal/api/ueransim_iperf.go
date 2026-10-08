package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// iperf3 throughput test from a UERANSIM UE (backlog UERAN-002, portal side).
//
// Mirrors scripts/ueransim-iperf.sh for a single UE session:
//
//	UE uesimtunN --GTP-U/N3--> gNB --> UPF (MASQUERADE) --N6--> throw-away iperf3 -s
//
// The client is bound to the session's tun address (-B), which UERANSIM maps to
// the uesimtunN routing table, so the traffic is forced through the tunnel. The
// server runs in a throw-away container on the DNN's N6 Docker network and is
// always removed. The test only measures: nothing in the UPF/SMF is touched.
const (
	iperfServerImageDefault = "nicolaka/netshoot"
	iperfUPFContainer       = "upf"
	iperfMaxDurationSec     = 30
	iperfDefaultDurationSec = 5
	iperfMaxStreams         = 8
	iperfDefaultPort        = 5201
)

// iperfNetworks is the allowlist of N6 networks a server may be started on.
var iperfNetworks = map[string]bool{"5gc-n6": true, "5gc-n6-ims": true}

var iperfBandwidthRe = regexp.MustCompile(`^[1-9][0-9]{0,4}[KMG]?$`)

// iperfRequest is the body for POST /api/v1/ueransim/iperf.
type iperfRequest struct {
	Container  string `json:"container"`
	UEIP       string `json:"ue_ip"`       // PDU session address (uesimtunN), passed to iperf3 -B
	Network    string `json:"network"`     // N6 Docker network: 5gc-n6 (default) or 5gc-n6-ims
	Protocol   string `json:"protocol"`    // "tcp" (default) or "udp"
	Direction  string `json:"direction"`   // "ul" (UE -> server, default) or "dl" (server -> UE, iperf3 -R)
	Duration   int    `json:"duration"`    // seconds, clamped to [1, 30]
	Bandwidth  string `json:"bandwidth"`   // target bitrate (iperf3 -b), e.g. "10M"; UDP default 10M, TCP empty = unlimited
	ServerIP   string `json:"server_ip"`   // external iperf3 server (IPv4); empty = throw-away container on Network
	ServerPort int    `json:"server_port"` // iperf3 server port; default 5201
	Streams    int    `json:"streams"`     // parallel streams (-P), clamped to [1, 8]
}

// iperfSummary is the parsed result of one iperf3 run.
type iperfSummary struct {
	Mbps        float64  `json:"mbps"`                   // delivered rate (UDP uplink: offered rate minus loss)
	OfferedMbps *float64 `json:"offered_mbps,omitempty"` // UDP uplink: rate the client sent
	Retransmits *int     `json:"retransmits,omitempty"`  // TCP, sender side
	JitterMs    *float64 `json:"jitter_ms,omitempty"`    // UDP
	LossPercent *float64 `json:"loss_percent,omitempty"`
	Packets     *int     `json:"packets,omitempty"`
	Seconds     float64  `json:"seconds"`
}

// iperfResponse is returned to the portal UI.
type iperfResponse struct {
	OK          bool          `json:"ok"`
	Error       string        `json:"error,omitempty"`
	Container   string        `json:"container"`
	UEIP        string        `json:"ue_ip"`
	Network     string        `json:"network"`
	ServerIP    string        `json:"server_ip"`
	ServerPort  int           `json:"server_port"`
	ServerMode  string        `json:"server_mode"` // "auto" (throw-away container) or "external"
	Protocol    string        `json:"protocol"`
	Direction   string        `json:"direction"`
	Duration    int           `json:"duration"`
	Streams     int           `json:"streams"`
	Bandwidth   string        `json:"bandwidth,omitempty"`
	Summary     *iperfSummary `json:"summary,omitempty"`
	UPFN6IP     string        `json:"upf_n6_ip,omitempty"`
	ServerPeer  string        `json:"server_peer,omitempty"` // client address the server saw
	PathChecked bool          `json:"path_checked"`          // false when the UPF N6 IP or server peer is unknown
	PathOK      bool          `json:"path_ok"`               // peer == UPF N6 IP: traffic really crossed the UPF
	ClientMode  string        `json:"client_mode,omitempty"` // "ue" (iperf3 in the UE image) or "netshoot"
	RawOutput   string        `json:"raw_output,omitempty"`  // iperf3 stdout/stderr when it failed to produce JSON
}

// normalize validates req and applies defaults. It returns a user-facing error
// message ("" when valid).
func (req *iperfRequest) normalize() string {
	if req.Container == "" || req.UEIP == "" {
		return "container and ue_ip are required"
	}
	if !strings.HasPrefix(req.Container, "ueransim-ue") {
		return "container must be a ueransim-ue* container"
	}
	if ip := net.ParseIP(req.UEIP); ip == nil || ip.To4() == nil {
		return "ue_ip must be a valid IPv4 address"
	}
	if req.Network == "" {
		req.Network = "5gc-n6"
	}
	if !iperfNetworks[req.Network] {
		return "network must be 5gc-n6 or 5gc-n6-ims"
	}
	switch req.Protocol {
	case "":
		req.Protocol = "tcp"
	case "tcp", "udp":
	default:
		return "protocol must be tcp or udp"
	}
	switch req.Direction {
	case "":
		req.Direction = "ul"
	case "ul", "dl":
	default:
		return "direction must be ul or dl"
	}
	if req.Duration <= 0 {
		req.Duration = iperfDefaultDurationSec
	}
	if req.Duration > iperfMaxDurationSec {
		req.Duration = iperfMaxDurationSec
	}
	if req.Streams <= 0 {
		req.Streams = 1
	}
	if req.Streams > iperfMaxStreams {
		req.Streams = iperfMaxStreams
	}
	req.Bandwidth = strings.ToUpper(strings.TrimSpace(req.Bandwidth))
	if req.Protocol == "udp" && req.Bandwidth == "" {
		req.Bandwidth = "10M"
	}
	if req.Bandwidth != "" && !iperfBandwidthRe.MatchString(req.Bandwidth) {
		return "bandwidth must look like 500K, 10M or 1G"
	}
	if req.ServerPort == 0 {
		req.ServerPort = iperfDefaultPort
	}
	if req.ServerPort < 1 || req.ServerPort > 65535 {
		return "server_port must be 1-65535"
	}
	req.ServerIP = strings.TrimSpace(req.ServerIP)
	if req.ServerIP != "" {
		ip := net.ParseIP(req.ServerIP)
		if ip == nil || ip.To4() == nil {
			return "server_ip must be a valid IPv4 address"
		}
		if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
			return "server_ip must be a routable unicast address"
		}
	}
	return ""
}

// clientArgs builds the iperf3 client command line.
func (req *iperfRequest) clientArgs(serverIP string) []string {
	args := []string{
		"iperf3", "-c", serverIP, "-B", req.UEIP,
		"-t", fmt.Sprint(req.Duration), "-P", fmt.Sprint(req.Streams),
		"-p", fmt.Sprint(req.ServerPort), "--connect-timeout", "5000", "-J",
	}
	if req.Protocol == "udp" {
		args = append(args, "-u")
	}
	if req.Bandwidth != "" {
		args = append(args, "-b", req.Bandwidth)
	}
	if req.Direction == "dl" {
		args = append(args, "-R")
	}
	return args
}

// parseIperfJSON extracts the summary from `iperf3 -J` output. iperf3 >= 3.11
// reports the receiver in sum_received; older builds only have sum_sent.
func parseIperfJSON(out string) (*iperfSummary, error) {
	// Output may carry non-JSON noise (e.g. a netshoot banner); start at the first '{'.
	if i := strings.Index(out, "{"); i > 0 {
		out = out[i:]
	}
	var doc struct {
		Error string `json:"error"`
		End   struct {
			SumSent *struct {
				Seconds       float64 `json:"seconds"`
				BitsPerSecond float64 `json:"bits_per_second"`
				Retransmits   *int    `json:"retransmits"`
			} `json:"sum_sent"`
			SumReceived *struct {
				Seconds       float64 `json:"seconds"`
				BitsPerSecond float64 `json:"bits_per_second"`
			} `json:"sum_received"`
			Sum *struct {
				Seconds       float64  `json:"seconds"`
				BitsPerSecond float64  `json:"bits_per_second"`
				JitterMs      *float64 `json:"jitter_ms"`
				LostPackets   *int     `json:"lost_packets"`
				Packets       *int     `json:"packets"`
				LostPercent   *float64 `json:"lost_percent"`
			} `json:"sum"`
		} `json:"end"`
	}
	// Decode only the first JSON value: iperf3 can follow it with a plain-text error line.
	if err := json.NewDecoder(strings.NewReader(out)).Decode(&doc); err != nil {
		return nil, fmt.Errorf("unparsable iperf3 JSON: %w", err)
	}
	if doc.Error != "" {
		return nil, fmt.Errorf("iperf3: %s", doc.Error)
	}
	e := doc.End
	switch {
	case e.Sum != nil: // UDP
		return &iperfSummary{
			Mbps: e.Sum.BitsPerSecond / 1e6, JitterMs: e.Sum.JitterMs,
			LossPercent: e.Sum.LostPercent, Packets: e.Sum.Packets, Seconds: e.Sum.Seconds,
		}, nil
	case e.SumReceived != nil && e.SumSent != nil: // TCP
		return &iperfSummary{
			Mbps: e.SumReceived.BitsPerSecond / 1e6, Retransmits: e.SumSent.Retransmits, Seconds: e.SumReceived.Seconds,
		}, nil
	case e.SumSent != nil:
		return &iperfSummary{
			Mbps: e.SumSent.BitsPerSecond / 1e6, Retransmits: e.SumSent.Retransmits, Seconds: e.SumSent.Seconds,
		}, nil
	}
	// iperf3 3.9 reports failures as a text line on stderr and leaves "end" empty.
	if m := iperfErrorLineRe.FindStringSubmatch(out); m != nil {
		return nil, fmt.Errorf("iperf3: %s", strings.TrimSpace(m[1]))
	}
	return nil, fmt.Errorf("iperf3 JSON has no end summary")
}

var iperfErrorLineRe = regexp.MustCompile(`(?m)^iperf3: error - (.*)$`)

var iperfAcceptedRe = regexp.MustCompile(`Accepted connection from ([0-9.]+),`)

// parseIperfServerPeer returns the client address recorded in the server log
// ("Accepted connection from X, port N"), "" when absent.
func parseIperfServerPeer(serverLog string) string {
	if m := iperfAcceptedRe.FindStringSubmatch(serverLog); m != nil {
		return m[1]
	}
	return ""
}

func randSuffix() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// handleUERANSIMIperf runs one iperf3 test from a UE's PDU session toward a
// throw-away server on the N6 network, and reports throughput plus a path check
// (the server must see the UPF's N6 address, proving the traffic crossed the UPF).
func (d Deps) handleUERANSIMIperf(w http.ResponseWriter, r *http.Request) {
	var req iperfRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if msg := req.normalize(); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	if d.Docker == nil {
		writeError(w, http.StatusServiceUnavailable, "docker not available")
		return
	}

	// Server start + client run + slack for image start and teardown.
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(req.Duration+40)*time.Second)
	defer cancel()

	resp := iperfResponse{
		Container: req.Container, UEIP: req.UEIP, Network: req.Network,
		Protocol: req.Protocol, Direction: req.Direction, Duration: req.Duration,
		Streams: req.Streams, Bandwidth: req.Bandwidth,
	}

	image := d.IperfImage
	if image == "" {
		image = iperfServerImageDefault
	}
	suffix := randSuffix()
	srvName := "5gc-portal-iperf-srv-" + suffix
	external := req.ServerIP != ""
	srvIP := req.ServerIP
	resp.ServerPort = req.ServerPort
	if external {
		// The user runs `iperf3 -s -p <port>` on that host; nothing to start or remove.
		resp.ServerMode = "external"
		resp.ServerIP = srvIP
	} else {
		resp.ServerMode = "auto"
		ip, err := d.Docker.StartDetached(ctx, srvName, image, req.Network,
			[]string{"iperf3", "-s", "-1", "-p", fmt.Sprint(req.ServerPort), "--forceflush"})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "start iperf3 server on "+req.Network+": "+err.Error())
			return
		}
		defer func() { _ = d.Docker.ForceRemove(context.Background(), srvName) }()
		srvIP = ip
		resp.ServerIP = srvIP
		resp.UPFN6IP = d.Docker.IPOnNetwork(ctx, iperfUPFContainer, req.Network)

		// Let the server bind its port; the client also retries within --connect-timeout.
		select {
		case <-ctx.Done():
			writeError(w, http.StatusGatewayTimeout, ctx.Err().Error())
			return
		case <-time.After(time.Second):
		}
	}

	args := req.clientArgs(srvIP)
	// Prefer iperf3 inside the UE image (rebuilt tools/ueransim/Dockerfile); older
	// UE containers fall back to a throw-away client sharing the UE's netns.
	var out string
	probe, perr := d.Docker.Exec(ctx, req.Container, []string{"sh", "-c", "command -v iperf3"})
	if perr == nil && probe.ExitCode == 0 {
		resp.ClientMode = "ue"
		res, err := d.Docker.Exec(ctx, req.Container, args)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		out = res.Output
	} else {
		resp.ClientMode = "netshoot"
		res, err := d.Docker.RunOnce(ctx, "5gc-portal-iperf-cli-"+suffix, image,
			"container:"+req.Container, args)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		out = res.Output
	}

	sum, err := parseIperfJSON(out)
	if err != nil {
		resp.Error = iperfErrorHint(err.Error())
		resp.RawOutput = strings.TrimSpace(out)
		if len(resp.RawOutput) > 2000 {
			resp.RawOutput = resp.RawOutput[:2000] + "…"
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}
	adjustUDPUplink(&req, sum)
	resp.Summary = sum
	resp.OK = true

	if !external {
		if logs, lerr := d.Docker.ContainerLogs(context.Background(), srvName); lerr == nil {
			resp.ServerPeer = parseIperfServerPeer(logs)
		}
	}
	if resp.UPFN6IP != "" && resp.ServerPeer != "" {
		resp.PathChecked = true
		resp.PathOK = resp.ServerPeer == resp.UPFN6IP
		if !resp.PathOK {
			resp.OK = false
			resp.Error = fmt.Sprintf("path check failed: server saw %s, expected the UPF N6 address %s (traffic bypassed the UPF)",
				resp.ServerPeer, resp.UPFN6IP)
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// adjustUDPUplink corrects the headline rate of a UDP uplink run. iperf3 3.9
// reports the SENDER's bitrate in a UDP client summary, so bits_per_second is
// the offered rate, not what reached the server. It keeps the offered rate in
// OfferedMbps and sets Mbps to the delivered rate (offered minus loss).
func adjustUDPUplink(req *iperfRequest, sum *iperfSummary) {
	if req.Protocol != "udp" || req.Direction != "ul" || sum.LossPercent == nil {
		return
	}
	offered := sum.Mbps
	sum.OfferedMbps = &offered
	sum.Mbps = offered * (1 - *sum.LossPercent/100)
}

// iperfErrorHint appends guidance to the cryptic connect failures iperf3 prints
// when the server cannot be reached through the UE's PDU session.
func iperfErrorHint(msg string) string {
	for _, marker := range []string{"unable to send control message", "unable to connect", "Connection timed out", "Connection refused", "No route to host", "Network is unreachable"} {
		if strings.Contains(msg, marker) {
			return msg + " — the server could not be reached through this PDU session: check the session's user plane with Ping, and the server IP/port"
		}
	}
	return msg
}
