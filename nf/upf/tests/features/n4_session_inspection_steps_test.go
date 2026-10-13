//go:build functional

// N4SessionInspection (task MCP-012, UPF side) step definitions: the read-only
// admin view GET /admin/v1/n4-sessions over the PFCP SessionTable. Everything
// runs in-process on loopback:
//
//   - the PFCP side reuses the in-process UPF (pfcp.Server on loopback UDP +
//     gtpu.Server sharing one SessionTable) owned by ambrWorld.ensure; the test
//     plays the SMF over ONE persistent UDP socket, so any unsolicited PFCP
//     message the UPF might send to the SMF address (learned from the
//     Establishment source) would arrive on that socket;
//   - the admin handler (admin.NewN4SessionsHandler) is wrapped in an
//     httptest.Server and reads that same table through a counting
//     SessionDescriber, so "Describe was not called" is observable;
//   - the metrics-server scenarios build metrics.MetricsServerWithAdmin and
//     serve its Handler through httptest;
//   - the handler logs to the same JSON sink as the UPF (nf=UPF base attribute,
//     as in cmd/upf/main.go).
//
// Registration: registerN4Steps is called by InitializeScenario BEFORE
// registerAmbrSteps, because godog runs the first matching step and the
// generic AmbrEnforcement steps ("the SMF sends a PFCP Session Modification
// Request with (.+)", "... Deletion Request") use a different fixture SEID.
// The steps shared by both features dispatch on n4World.active and delegate to
// the ambrWorld implementation when the AmbrEnforcement feature is running.
//
// Scenarios tagged @e2e @manual are skipped (godog.ErrSkip) unless E2E_TEST=1,
// via the shared e2e helpers of downlink_checksum_steps_test.go.
package features

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cucumber/godog"
	pfcpie "github.com/wmnsk/go-pfcp/ie"
	pfcpmsg "github.com/wmnsk/go-pfcp/message"

	"github.com/francurieses/claudia-5gc/nf/upf/internal/admin"
	"github.com/francurieses/claudia-5gc/nf/upf/internal/pfcp"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

const (
	n4Path     = "/admin/v1/n4-sessions"
	n4SeidS    = uint64(9)
	n4TeidS    = uint32(0x1001)
	n4UEIPS    = "10.60.0.7"
	n4OrigLvl  = "ORIGINAL-LOG-LEVEL-HANDLER"
	n4CustomLv = "CUSTOM-HANDLER"
)

// n4CountDesc counts Describe calls made through the admin handler.
type n4CountDesc struct {
	src admin.SessionDescriber
	n   atomic.Int64
}

func (c *n4CountDesc) Describe(f pfcp.DescribeFilter) []pfcp.SessionDescription {
	c.n.Add(1)
	return c.src.Describe(f)
}

type n4World struct {
	a      *ambrWorld
	active bool

	adm  *httptest.Server
	met  *httptest.Server
	base string
	desc *n4CountDesc
	smf  *net.UDPConn
	seq  uint32

	// last HTTP response
	status   int
	hdr      http.Header
	body     []byte
	doc      map[string]any
	sessions []map[string]any

	// scenario data
	keptJSON   string
	kept       []pfcp.SessionDescription
	origJSON   string
	buildPanic bool
	logSel     map[string]any
	logRaw     string
	raceErr    error
}

func (n *n4World) reset() {
	for _, s := range []*httptest.Server{n.adm, n.met} {
		if s != nil {
			s.Close()
		}
	}
	if n.smf != nil {
		_ = n.smf.Close()
	}
	*n = n4World{a: n.a}
}

// ---------- PFCP (the test plays the SMF) ----------

func (n *n4World) conn() (*net.UDPConn, error) {
	if n.smf != nil {
		return n.smf, nil
	}
	if err := n.a.ensure(); err != nil {
		return nil, err
	}
	ra, err := net.ResolveUDPAddr("udp", n.a.pfcpAdr)
	if err != nil {
		return nil, err
	}
	c, err := net.DialUDP("udp", nil, ra)
	if err != nil {
		return nil, err
	}
	n.smf = c
	return c, nil
}

// exchange sends msg on the persistent SMF socket and records Kind/Cause in the
// ambrWorld fields read by the shared "PFCP Session ... Response has Cause" step.
func (n *n4World) exchange(msg pfcpmsg.Message) error {
	c, err := n.conn()
	if err != nil {
		return err
	}
	b := make([]byte, msg.MarshalLen())
	if err := msg.MarshalTo(b); err != nil {
		return err
	}
	if _, err := c.Write(b); err != nil {
		return err
	}
	_ = c.SetReadDeadline(time.Now().Add(recvTimeout))
	buf := make([]byte, 4096)
	k, err := c.Read(buf)
	if err != nil {
		return fmt.Errorf("no PFCP response: %w", err)
	}
	resp, err := pfcpmsg.Parse(buf[:k])
	if err != nil {
		return err
	}
	var cause *pfcpie.IE
	n.a.lastKind = ""
	switch r := resp.(type) {
	case *pfcpmsg.SessionEstablishmentResponse:
		n.a.lastKind, cause = "Establishment", r.Cause
	case *pfcpmsg.SessionModificationResponse:
		n.a.lastKind, cause = "Modification", r.Cause
	case *pfcpmsg.SessionDeletionResponse:
		n.a.lastKind, cause = "Deletion", r.Cause
	default:
		return fmt.Errorf("unexpected PFCP response %s", resp.MessageTypeName())
	}
	if cause == nil {
		return errors.New("PFCP response carries no Cause IE")
	}
	code, err := cause.Cause()
	if err != nil {
		return err
	}
	n.a.lastCode = code
	return nil
}

func n4PDR(p pdrSpec, teid uint32, ueip string) *pfcpie.IE {
	pdi := []*pfcpie.IE{pfcpie.NewSourceInterface(pfcpie.SrcInterfaceAccess)}
	if p.full {
		pdi = append(pdi,
			pfcpie.NewFTEID(0x01, teid, net.ParseIP("127.0.0.1"), nil, 0),
			pfcpie.NewUEIPAddress(0x02, ueip, "", 0, 0),
			pfcpie.NewNetworkInstance("internet"))
	}
	ies := []*pfcpie.IE{pfcpie.NewPDRID(p.id), pfcpie.NewPrecedence(p.prec), pfcpie.NewPDI(pdi...),
		pfcpie.NewOuterHeaderRemoval(0, 0), pfcpie.NewFARID(1)}
	for _, q := range p.qers {
		ies = append(ies, pfcpie.NewQERID(q))
	}
	return pfcpie.NewCreatePDR(ies...)
}

// n4BuildEstablish builds a Session Establishment Request. urr may be nil.
func n4BuildEstablish(seq uint32, seid uint64, ueip string, teid uint32, pdrs []pdrSpec, qers []qerSpec, urr *pfcpie.IE) pfcpmsg.Message {
	ies := []*pfcpie.IE{
		pfcpie.NewNodeID("", "", "smf"),
		pfcpie.NewFSEID(seid, net.ParseIP("127.0.0.1"), nil),
	}
	for _, p := range pdrs {
		ies = append(ies, n4PDR(p, teid, ueip))
	}
	ies = append(ies, pfcpie.NewCreateFAR(pfcpie.NewFARID(1), pfcpie.NewApplyAction(0x02)))
	for _, q := range qers {
		ies = append(ies, pfcpie.NewCreateQER(qerChildren(q)...))
	}
	if urr != nil {
		ies = append(ies, urr)
	}
	return pfcpmsg.NewSessionEstablishmentRequest(0, 0, 0, seq, 0, ies...)
}

func (n *n4World) establish(seid uint64, ueip string, teid uint32, pdrs []pdrSpec, qers []qerSpec, urr *pfcpie.IE) error {
	n.seq++
	if err := n.exchange(n4BuildEstablish(n.seq, seid, ueip, teid, pdrs, qers, urr)); err != nil {
		return err
	}
	if n.a.lastCode != 1 {
		return fmt.Errorf("Session Establishment rejected with Cause %d, want 1", n.a.lastCode)
	}
	return nil
}

// defaultRules is the fixture of the feature: PDR 1 -> QER 1, 2; QER 1 is the
// Session-AMBR (MBR 8000/8000, no QFI); QER 2 carries QFI 1 (no MBR).
func defaultRules() ([]pdrSpec, []qerSpec) {
	return []pdrSpec{{id: 1, prec: 100, qers: []uint32{1, 2}, full: true}},
		[]qerSpec{
			{id: 1, gate: gateOpen(), mbr: &[2]uint64{8000, 8000}},
			{id: 2, gate: gateOpen(), qfi: u8p(1)},
		}
}

func (n *n4World) givenSessionAMBR(urrText, threshold string) error {
	pdrs, qers := defaultRules()
	var urr *pfcpie.IE
	if urrText != "" {
		ies := []*pfcpie.IE{pfcpie.NewURRID(1), pfcpie.NewMeasurementMethod(0, 1, 0)}
		if threshold != "" {
			v, err := strconv.ParseUint(threshold, 10, 64)
			if err != nil {
				return err
			}
			ies = append(ies, pfcpie.NewReportingTriggers(0x0200), // VOLTH = bit 2 of octet 1 (high byte)
				pfcpie.NewVolumeThreshold(0x01, v, 0, 0))
		}
		urr = pfcpie.NewCreateURR(ies...)
	}
	return n.establish(n4SeidS, n4UEIPS, n4TeidS, pdrs, qers, urr)
}

func (n *n4World) givenTable(tbl *godog.Table) error {
	if len(tbl.Rows) < 2 {
		return errors.New("empty table")
	}
	var hdr []string
	for _, c := range tbl.Rows[0].Cells {
		hdr = append(hdr, strings.TrimSpace(c.Value))
	}
	var pdrs []pdrSpec
	var qers []qerSpec
	for _, r := range tbl.Rows[1:] {
		row := map[string]string{}
		for i, c := range r.Cells {
			row[hdr[i]] = c.Value
		}
		id, err := strconv.ParseUint(cell(row, "id"), 10, 32)
		if err != nil {
			return fmt.Errorf("row id: %w", err)
		}
		switch cell(row, "rule") {
		case "Create PDR":
			p := pdrSpec{id: uint16(id), prec: 100, full: len(pdrs) == 0}
			for _, s := range strings.Split(cell(row, "pdr_qer_ids"), ",") {
				if s = strings.TrimSpace(s); s == "" {
					continue
				}
				v, err := strconv.ParseUint(s, 10, 32)
				if err != nil {
					return err
				}
				p.qers = append(p.qers, uint32(v))
			}
			pdrs = append(pdrs, p)
		case "Create QER":
			q := qerSpec{id: uint32(id)}
			if gu, gd := cell(row, "gate_ul"), cell(row, "gate_dl"); gu != "" {
				ul, err := gateBits(gu)
				if err != nil {
					return err
				}
				dl, err := gateBits(gd)
				if err != nil {
					return err
				}
				q.gate = &[2]uint8{ul, dl}
			}
			if mu, md := cell(row, "mbr_ul_kbps"), cell(row, "mbr_dl_kbps"); mu != "" && mu != "absent" {
				m, err := mbrPair(mu, md)
				if err != nil {
					return err
				}
				q.mbr = m
			}
			if f := cell(row, "qfi"); f != "" && f != "absent" {
				v, err := strconv.ParseUint(f, 10, 8)
				if err != nil {
					return err
				}
				q.qfi = u8p(uint8(v))
			}
			qers = append(qers, q)
		default:
			return fmt.Errorf("unknown rule %q", cell(row, "rule"))
		}
	}
	return n.establish(n4SeidS, n4UEIPS, n4TeidS, pdrs, qers, nil)
}

func (n *n4World) givenSecond(seidS, ip string) error {
	seid, err := strconv.ParseUint(seidS, 0, 64)
	if err != nil {
		return err
	}
	pdrs, qers := defaultRules()
	return n.establish(seid, ip, n4TeidS+1, pdrs, qers, nil)
}

var reUpdFAR = regexp.MustCompile(`Update FAR Outer Header Creation TEID (0x[0-9a-fA-F]+) and gNB address "([^"]*)"`)

// modify sends a Session Modification Request for the fixture session S; when
// the AmbrEnforcement feature is running it delegates to that feature's step.
func (n *n4World) modify(text string) error {
	if !n.active {
		return n.a.whenModify(text)
	}
	var ies []*pfcpie.IE
	for _, m := range reUpdFAR.FindAllStringSubmatch(text, -1) {
		teid, err := strconv.ParseUint(m[1], 0, 32)
		if err != nil {
			return err
		}
		ies = append(ies, pfcpie.NewUpdateFAR(pfcpie.NewFARID(1), pfcpie.NewApplyAction(0x02),
			pfcpie.NewUpdateForwardingParameters(
				pfcpie.NewOuterHeaderCreation(0x0100, uint32(teid), m[2], "", 0, 0, 0))))
	}
	for _, m := range reUpdMBR.FindAllStringSubmatch(text, -1) {
		mbr, err := mbrPair(m[2], m[3])
		if err != nil {
			return err
		}
		ies = append(ies, pfcpie.NewUpdateQER(pfcpie.NewQERID(atou(m[1])), pfcpie.NewMBR(mbr[0], mbr[1])))
	}
	for _, m := range reUpdGate.FindAllStringSubmatch(text, -1) {
		ul, _ := gateBits(m[2])
		dl, _ := gateBits(m[3])
		ies = append(ies, pfcpie.NewUpdateQER(pfcpie.NewQERID(atou(m[1])), pfcpie.NewGateStatus(ul, dl)))
	}
	for _, m := range reUpdSpare.FindAllStringSubmatch(text, -1) {
		dl, _ := gateBits(m[3])
		ies = append(ies, pfcpie.NewUpdateQER(pfcpie.NewQERID(atou(m[1])), pfcpie.NewGateStatus(uint8(atou(m[2])), dl)))
	}
	if len(ies) == 0 {
		return fmt.Errorf("no supported Modification clause in %q", text)
	}
	n.seq++
	return n.exchange(pfcpmsg.NewSessionModificationRequest(0, 0, n4SeidS, n.seq, 0, ies...))
}

func (n *n4World) deleteSession() error {
	if !n.active {
		return n.a.whenDelete()
	}
	n.seq++
	return n.exchange(pfcpmsg.NewSessionDeletionRequest(0, 0, n4SeidS, n.seq, 0))
}

// ---------- direct SessionTable inserts ----------

func (n *n4World) insertSEIDs(a, b, c string) error {
	if err := n.a.ensure(); err != nil {
		return err
	}
	for i, s := range []string{a, b, c} {
		v, err := strconv.ParseUint(s, 0, 64)
		if err != nil {
			return err
		}
		n.a.table.Add(&pfcp.Session{CPSEID: v, UPSEID: v, ULTEID: 0x7000 + uint32(i),
			UEIP: net.ParseIP(fmt.Sprintf("10.60.1.%d", 10+i)).To4(), DNN: "internet"})
	}
	return nil
}

func (n *n4World) insertCPUP(cp, up string) error {
	if err := n.a.ensure(); err != nil {
		return err
	}
	c, err := strconv.ParseUint(cp, 0, 64)
	if err != nil {
		return err
	}
	u, err := strconv.ParseUint(up, 0, 64)
	if err != nil {
		return err
	}
	n.a.table.Add(&pfcp.Session{CPSEID: c, UPSEID: u, ULTEID: 0x7100,
		UEIP: net.ParseIP("10.60.1.50").To4(), DNN: "internet"})
	return nil
}

func (n *n4World) insertV6(seid, ip string) error {
	if err := n.a.ensure(); err != nil {
		return err
	}
	v, err := strconv.ParseUint(seid, 0, 64)
	if err != nil {
		return err
	}
	p := net.ParseIP(ip)
	if p == nil {
		return fmt.Errorf("bad IPv6 %q", ip)
	}
	n.a.table.Add(&pfcp.Session{CPSEID: v, UPSEID: v, UEIPv6: p, DNN: "internet"})
	return nil
}

// ---------- HTTP client ----------

func (n *n4World) startAdmin() error {
	if err := n.a.ensure(); err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(n.a.logs, &slog.HandlerOptions{Level: slog.LevelInfo})).With("nf", "UPF")
	n.desc = &n4CountDesc{src: n.a.table}
	mux := http.NewServeMux()
	mux.Handle(n4Path, admin.NewN4SessionsHandler(n.desc, log))
	n.adm = httptest.NewServer(mux)
	n.base = n.adm.URL
	return nil
}

func (n *n4World) request(method, path, body string, hdr map[string]string) error {
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, n.base+path, rd)
	if err != nil {
		return err
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	cl := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	resp, err := cl.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	n.status, n.hdr, n.body, n.doc, n.sessions = resp.StatusCode, resp.Header, b, nil, nil
	if method == http.MethodGet && strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		var d map[string]any
		if err := json.Unmarshal(b, &d); err != nil {
			return fmt.Errorf("response is not JSON: %w: %s", err, b)
		}
		n.doc = d
		if arr, ok := d["sessions"].([]any); ok {
			for _, e := range arr {
				if m, ok := e.(map[string]any); ok {
					n.sessions = append(n.sessions, m)
				}
			}
		}
	}
	return nil
}

func (n *n4World) send(method, path string) error { return n.request(method, path, "", nil) }

func (n *n4World) sendBody(path, body string) error {
	return n.request(http.MethodGet, path, strings.ReplaceAll(body, `\"`, `"`), nil)
}

func (n *n4World) sendHeader(path, k, v string) error {
	return n.request(http.MethodGet, path, "", map[string]string{k: v})
}

// ---------- assertions on the response ----------

func (n *n4World) thenStatus(code int) error {
	if n.status != code {
		return fmt.Errorf("response status = %d, want %d (body %s)", n.status, code, n.body)
	}
	return nil
}

func (n *n4World) thenStatusCT(code int, ct string) error {
	if err := n.thenStatus(code); err != nil {
		return err
	}
	if got := n.hdr.Get("Content-Type"); got != ct {
		return fmt.Errorf("Content-Type = %q, want %q", got, ct)
	}
	return nil
}

func (n *n4World) thenCount(want int) error {
	if n.doc == nil {
		return fmt.Errorf("no JSON document in the response (status %d, body %s)", n.status, n.body)
	}
	got, ok := n.doc["count"].(float64)
	if !ok || int(got) != want {
		return fmt.Errorf("count = %v, want %d", n.doc["count"], want)
	}
	if len(n.sessions) != want {
		return fmt.Errorf("sessions has %d elements, want %d", len(n.sessions), want)
	}
	return nil
}

func (n *n4World) thenCountElems(c, e int) error {
	if err := n.thenCount(c); err != nil {
		return err
	}
	if len(n.sessions) != e {
		return fmt.Errorf("sessions has %d elements, want %d", len(n.sessions), e)
	}
	return nil
}

func (n *n4World) thenCountEmpty(c int) error {
	if err := n.thenCount(c); err != nil {
		return err
	}
	if arr, ok := n.doc["sessions"].([]any); !ok || len(arr) != 0 {
		return fmt.Errorf(`"sessions" = %v, want an empty JSON array`, n.doc["sessions"])
	}
	return nil
}

func (n *n4World) first() (map[string]any, error) {
	if len(n.sessions) == 0 {
		return nil, errors.New("the response lists no session")
	}
	return n.sessions[0], nil
}

// checkClauses verifies "key value and key "text" and no key" against a JSON object.
func checkClauses(obj map[string]any, text string) error {
	for _, c := range strings.Split(text, " and ") {
		c = strings.TrimSpace(c)
		if key, ok := strings.CutPrefix(c, "no "); ok {
			if v, present := obj[key]; present {
				return fmt.Errorf("field %q is present (%v), want absent", key, v)
			}
			continue
		}
		key, val, _ := strings.Cut(c, " ")
		got, present := obj[key]
		if !present {
			return fmt.Errorf("field %q is absent, want %s", key, val)
		}
		switch {
		case strings.HasPrefix(val, `"`):
			want := strings.Trim(val, `"`)
			if s, ok := got.(string); !ok || s != want {
				return fmt.Errorf("%s = %v, want %q", key, got, want)
			}
		case val == "true" || val == "false":
			if b, ok := got.(bool); !ok || strconv.FormatBool(b) != val {
				return fmt.Errorf("%s = %v, want %s", key, got, val)
			}
		default:
			want, err := strconv.ParseUint(val, 0, 64)
			if err != nil {
				return fmt.Errorf("clause %q: %w", c, err)
			}
			f, ok := got.(float64)
			if !ok || uint64(f) != want {
				return fmt.Errorf("%s = %v, want %d", key, got, want)
			}
		}
	}
	return nil
}

var reAmbrDLTunnel = regexp.MustCompile(`^DL TEID (0x[0-9a-fA-F]+) and gNB address "([^"]*)"$`)

func (n *n4World) thenSessionHas(text string) error {
	if !n.active { // "the session has DL TEID ... and gNB address ..." belongs to ambr_enforcement.feature
		if m := reAmbrDLTunnel.FindStringSubmatch(text); m != nil {
			return n.a.givenDLTunnel(m[1], m[2])
		}
		return fmt.Errorf("undefined step: the session has %s", text)
	}
	s, err := n.first()
	if err != nil {
		return err
	}
	return checkClauses(s, text)
}

func (n *n4World) thenSessionNoField(k string) error {
	s, err := n.first()
	if err != nil {
		return err
	}
	if v, ok := s[k]; ok {
		return fmt.Errorf("field %q is present (%v), want absent", k, v)
	}
	return nil
}

func (n *n4World) thenCountSession(c, cp, up int) error {
	if err := n.thenCount(c); err != nil {
		return err
	}
	return n.thenSessionHas(fmt.Sprintf("cp_seid %d and up_seid %d", cp, up))
}

func sessQER(s map[string]any, id int) (map[string]any, error) {
	arr, _ := s["qers"].([]any)
	for _, e := range arr {
		if m, ok := e.(map[string]any); ok {
			if f, ok := m["qer_id"].(float64); ok && int(f) == id {
				return m, nil
			}
		}
	}
	return nil, fmt.Errorf("QER %d is not listed in %v", id, s["qers"])
}

func (n *n4World) thenQER(id int, text string) error {
	s, err := n.first()
	if err != nil {
		return err
	}
	q, err := sessQER(s, id)
	if err != nil {
		return err
	}
	return checkClauses(q, text)
}

func (n *n4World) thenBothQERs(a, b int, text string) error {
	for _, id := range []int{a, b} {
		if err := n.thenQER(id, text); err != nil {
			return err
		}
	}
	return nil
}

func (n *n4World) thenQERsSorted(count int) error {
	s, err := n.first()
	if err != nil {
		return err
	}
	arr, _ := s["qers"].([]any)
	if len(arr) != count {
		return fmt.Errorf("session lists %d QERs, want %d", len(arr), count)
	}
	last := -1.0
	for _, e := range arr {
		id := e.(map[string]any)["qer_id"].(float64)
		if id <= last {
			return fmt.Errorf("QERs not sorted by qer_id: %v", arr)
		}
		last = id
	}
	return nil
}

func (n *n4World) thenPDR(id int, src string, q1, q2 int) error {
	s, err := n.first()
	if err != nil {
		return err
	}
	arr, _ := s["pdrs"].([]any)
	for _, e := range arr {
		m := e.(map[string]any)
		if f, ok := m["pdr_id"].(float64); !ok || int(f) != id {
			continue
		}
		if m["source_interface"] != src {
			return fmt.Errorf("PDR %d source_interface = %v, want %q", id, m["source_interface"], src)
		}
		ids, _ := m["qer_ids"].([]any)
		if len(ids) != 2 || ids[0].(float64) != float64(q1) || ids[1].(float64) != float64(q2) {
			return fmt.Errorf("PDR %d qer_ids = %v, want [%d %d]", id, ids, q1, q2)
		}
		return nil
	}
	return fmt.Errorf("PDR %d is not listed in %v", id, s["pdrs"])
}

func (n *n4World) thenURR(text string) error {
	s, err := n.first()
	if err != nil {
		return err
	}
	u, ok := s["urr"].(map[string]any)
	if !ok {
		return errors.New(`session has no "urr" object`)
	}
	return checkClauses(u, text)
}

func (n *n4World) thenOrder(a, b, c int) error {
	want := []int{a, b, c}
	if len(n.sessions) != len(want) {
		return fmt.Errorf("%d sessions listed, want %d", len(n.sessions), len(want))
	}
	for i, w := range want {
		if f, _ := n.sessions[i]["up_seid"].(float64); int(f) != w {
			return fmt.Errorf("session %d has up_seid %v, want %d", i, n.sessions[i]["up_seid"], w)
		}
	}
	return nil
}

func (n *n4World) thenProblemCause(c string) error {
	var pd map[string]any
	if err := json.Unmarshal(n.body, &pd); err != nil {
		return fmt.Errorf("body is not JSON: %w: %s", err, n.body)
	}
	if pd["cause"] != c {
		return fmt.Errorf("problem cause = %v, want %q", pd["cause"], c)
	}
	return nil
}

func (n *n4World) thenProblemParam(p string) error {
	var pd struct {
		InvalidParams []struct {
			Param string `json:"param"`
		} `json:"invalidParams"`
	}
	if err := json.Unmarshal(n.body, &pd); err != nil {
		return err
	}
	for _, ip := range pd.InvalidParams {
		if ip.Param == p {
			return nil
		}
	}
	return fmt.Errorf("invalidParams %s does not contain param %q", n.body, p)
}

func (n *n4World) thenDescribeNotCalled() error {
	if n.desc == nil {
		return errors.New("admin endpoint not running")
	}
	if c := n.desc.n.Load(); c != 0 {
		return fmt.Errorf("SessionTable.Describe was called %d time(s), want 0", c)
	}
	return nil
}

func (n *n4World) thenHeader(k, v string) error {
	if got := n.hdr.Get(k); got != v {
		return fmt.Errorf("response header %s = %q, want %q", k, got, v)
	}
	return nil
}

func (n *n4World) thenHolds(c int) error {
	if got := len(n.a.table.Snapshot()); got != c {
		return fmt.Errorf("SessionTable holds %d sessions, want %d", got, c)
	}
	return nil
}

// ---------- update / deep-copy / counters ----------

func (n *n4World) sawQER1DL(path string, dl int) error {
	if err := n.send(http.MethodGet, path); err != nil {
		return err
	}
	return n.thenQER(1, fmt.Sprintf("mbr_dl_kbps %d", dl))
}

func (n *n4World) describeAndMutate() error {
	d := n.a.table.Describe(pfcp.DescribeFilter{})
	b, err := json.Marshal(d)
	if err != nil {
		return err
	}
	n.origJSON = string(b)
	for i := range d {
		for j := range d[i].PDRs {
			for k := range d[i].PDRs[j].QERIDs {
				d[i].PDRs[j].QERIDs[k] = 99
			}
			d[i].PDRs[j].QERIDs = nil
			d[i].PDRs[j].SourceInterface = "MUTATED"
		}
		for j := range d[i].QERs {
			d[i].QERs[j].MBRULKbps = 1
			if d[i].QERs[j].QFI != nil {
				*d[i].QERs[j].QFI = 77
			}
			d[i].QERs[j].GateUL = "MUTATED"
		}
		d[i].PDRs, d[i].QERs = d[i].PDRs[:0], d[i].QERs[:0]
		d[i].UEIPv4, d[i].GNBN3IP, d[i].DNN = "9.9.9.9", "9.9.9.9", "mutated"
	}
	return nil
}

func (n *n4World) describeAgain() error {
	b, err := json.Marshal(n.a.table.Describe(pfcp.DescribeFilter{}))
	if err != nil {
		return err
	}
	n.keptJSON = string(b)
	return nil
}

func (n *n4World) thenSecondEqualsFirst() error {
	if n.origJSON == "" || n.keptJSON != n.origJSON {
		return fmt.Errorf("second description differs from the original:\nfirst : %s\nsecond: %s", n.origJSON, n.keptJSON)
	}
	return nil
}

func (n *n4World) thenLiveQER1() error {
	if n.a.pfcpSrv == nil {
		return errors.New("no UPF running")
	}
	info, ok := n.a.pfcpSrv.SessionQoS(n4SeidS)
	if !ok {
		return errors.New("UPF has no session S")
	}
	q, ok := info.QERs[1]
	if !ok || !q.HasMBR || q.MBRULKbps != 8000 || q.MBRDLKbps != 8000 || q.HasQFI {
		return fmt.Errorf("live QER 1 = %+v, want MBR 8000/8000 and no QFI", q)
	}
	return nil
}

func (n *n4World) thenLivePDR1() error {
	info, ok := n.a.pfcpSrv.SessionQoS(n4SeidS)
	if !ok {
		return errors.New("UPF has no session S")
	}
	p, ok := info.PDRs[1]
	if !ok || len(p.QERIDs) != 2 || p.QERIDs[0] != 1 || p.QERIDs[1] != 2 {
		return fmt.Errorf("live PDR 1 = %+v, want QER IDs [1 2]", p)
	}
	return nil
}

func (n *n4World) keepDescription() error {
	n.kept = n.a.table.Describe(pfcp.DescribeFilter{})
	return nil
}

func (n *n4World) thenKeptShows() error {
	if len(n.kept) != 1 {
		return fmt.Errorf("kept description has %d sessions, want 1", len(n.kept))
	}
	for _, q := range n.kept[0].QERs {
		if q.QERID == 1 {
			if q.MBRULKbps != 8000 || q.MBRDLKbps != 8000 {
				return fmt.Errorf("kept QER 1 MBR = %d/%d, want 8000/8000", q.MBRULKbps, q.MBRDLKbps)
			}
			return nil
		}
	}
	return errors.New("kept description lacks QER 1")
}

func (n *n4World) account(ulN, ulB, dlN, dlB int) error {
	s := n.a.table.GetByULTEID(n4TeidS)
	if s == nil {
		return errors.New("no session S in the table")
	}
	for i := 0; i < ulN; i++ {
		s.AddULVolume(ulB / ulN)
	}
	for i := 0; i < dlN; i++ {
		s.AddDLVolume(dlB / dlN)
	}
	return nil
}

func (n *n4World) concurrent() error {
	const (
		accountN = 2000
		perPkt   = 100
		cycles   = 15
		calls    = 200
	)
	s := n.a.table.GetByULTEID(n4TeidS)
	if s == nil {
		return errors.New("no session S in the table")
	}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	var churnErr atomic.Value
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < accountN; i++ {
				s.AddULVolume(perPkt)
				s.AddDLVolume(perPkt)
			}
		}()
	}
	var churn sync.WaitGroup
	for g := 0; g < 2; g++ {
		churn.Add(1)
		go func(g int) {
			defer churn.Done()
			seid := uint64(0x600 + g)
			pdrs, qers := defaultRules()
			for i := 0; i < cycles; i++ {
				select {
				case <-stop:
					return
				default:
				}
				est := n4BuildEstablish(uint32(1000*(g+1)+2*i), seid, fmt.Sprintf("10.60.0.%d", 100+g), 0x3000+uint32(g), pdrs, qers, nil)
				if _, err := pfcpExchange(n.a.pfcpAdr, est); err != nil {
					churnErr.Store(err)
					return
				}
				del := pfcpmsg.NewSessionDeletionRequest(0, 0, seid, uint32(1000*(g+1)+2*i+1), 0)
				if _, err := pfcpExchange(n.a.pfcpAdr, del); err != nil {
					churnErr.Store(err)
					return
				}
			}
		}(g)
	}
	var derr error
	for i := 0; i < calls; i++ {
		d := n.a.table.Describe(pfcp.DescribeFilter{})
		found := false
		for _, x := range d {
			if x.UPSEID == n4SeidS {
				found = true
			}
		}
		if !found {
			derr = fmt.Errorf("Describe call %d lost session S", i)
			break
		}
	}
	wg.Wait()
	close(stop)
	churn.Wait()
	if derr != nil {
		n.raceErr = derr
		return nil
	}
	if e, _ := churnErr.Load().(error); e != nil {
		n.raceErr = e
		return nil
	}
	d := n.a.table.Describe(pfcp.DescribeFilter{SEID: n4SeidS})
	if len(d) != 1 || d[0].URR.ULVolumeBytes != 4*accountN*perPkt || d[0].URR.ULPackets != 4*accountN {
		n.raceErr = fmt.Errorf("URR counters lost updates: %+v", d)
	}
	return nil
}

func (n *n4World) thenNoRaceErr() error { return n.raceErr }

// ---------- no PFCP message ----------

func (n *n4World) recordPFCP() error {
	c, err := n.conn()
	if err != nil {
		return err
	}
	buf := make([]byte, 4096)
	for { // drain whatever is already queued; there is no response left pending
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
		if _, err := c.Read(buf); err != nil {
			return nil
		}
	}
}

func (n *n4World) thenNoPFCP() error {
	_ = n.smf.SetReadDeadline(time.Now().Add(extraWait))
	buf := make([]byte, 4096)
	k, err := n.smf.Read(buf)
	if err == nil {
		return fmt.Errorf("the UPF sent a PFCP message (%d octets) after the admin GET", k)
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return nil
	}
	return err
}

// ---------- logs ----------

func (n *n4World) logLine(proc, iface, dir, spec string) error {
	if n.a.logs == nil {
		return errors.New("no log sink")
	}
	for _, raw := range strings.Split(n.a.logs.String(), "\n") {
		m := map[string]any{}
		if raw == "" || json.Unmarshal([]byte(raw), &m) != nil {
			continue
		}
		if m["procedure"] == proc && m["interface"] == iface && m["direction"] == dir && (spec == "" || m["spec_ref"] == spec) {
			n.logSel, n.logRaw = m, raw
			return nil
		}
	}
	return fmt.Errorf("no log line with procedure=%q interface=%q direction=%q spec_ref=%q in:\n%s",
		proc, iface, dir, spec, n.a.logs.String())
}

var reLogKV = regexp.MustCompile(`(\w+) ("[^"]*"|\d+)`)

func (n *n4World) thenLogCarries(text string) error {
	if !n.active { // "that log line carries seid, qer_id, ..." belongs to ambr_enforcement.feature
		if text == "seid, qer_id, mbr_ul_kbps and mbr_dl_kbps" {
			return n.a.thenLogKeys()
		}
		return fmt.Errorf("undefined step: that log line carries %s", text)
	}
	if n.logSel == nil {
		return errors.New("no log line selected")
	}
	pairs := reLogKV.FindAllStringSubmatch(text, -1)
	if len(pairs) == 0 {
		return fmt.Errorf("cannot parse %q", text)
	}
	for _, p := range pairs {
		got, ok := n.logSel[p[1]]
		if !ok {
			return fmt.Errorf("log line lacks %q: %s", p[1], n.logRaw)
		}
		if strings.HasPrefix(p[2], `"`) {
			if s, _ := got.(string); s != strings.Trim(p[2], `"`) {
				return fmt.Errorf("log %s = %v, want %s", p[1], got, p[2])
			}
		} else if f, _ := got.(float64); strconv.FormatFloat(f, 'f', -1, 64) != p[2] {
			return fmt.Errorf("log %s = %v, want %s", p[1], got, p[2])
		}
	}
	return nil
}

func (n *n4World) thenLogOnce(key string) error {
	if n.logRaw == "" {
		return errors.New("no log line selected")
	}
	if c := strings.Count(n.logRaw, `"`+key+`":`); c != 1 {
		return fmt.Errorf("log line carries %q %d times, want exactly once: %s", key, c, n.logRaw)
	}
	return nil
}

// ---------- metrics server scenarios ----------

var (
	reMetNil    = regexp.MustCompile(`^the admin route "([^"]*)" with a nil handler$`)
	reMetCustom = regexp.MustCompile(`^the admin route "([^"]*)" with a custom handler$`)
	reMetTwice  = regexp.MustCompile(`^the admin routes "([^"]*)" twice$`)
	reMetOne    = regexp.MustCompile(`^the admin route "([^"]*)"$`)
)

func (n *n4World) buildMetrics(spec string) error {
	if err := n.a.ensure(); err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	real := admin.NewN4SessionsHandler(&n4CountDesc{src: n.a.table}, log)
	logLevel := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, n4OrigLvl) })
	custom := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, n4CustomLv) })

	var routes []metrics.AdminRoute
	switch {
	case reMetNil.MatchString(spec):
		routes = []metrics.AdminRoute{{Pattern: reMetNil.FindStringSubmatch(spec)[1], Handler: nil}}
	case reMetCustom.MatchString(spec):
		routes = []metrics.AdminRoute{{Pattern: reMetCustom.FindStringSubmatch(spec)[1], Handler: custom}}
	case reMetTwice.MatchString(spec):
		p := reMetTwice.FindStringSubmatch(spec)[1]
		routes = []metrics.AdminRoute{{Pattern: p, Handler: real}, {Pattern: p, Handler: real}}
	case reMetOne.MatchString(spec):
		routes = []metrics.AdminRoute{{Pattern: reMetOne.FindStringSubmatch(spec)[1], Handler: real}}
	case spec == "no admin routes":
	default:
		return fmt.Errorf("unsupported metrics-server spec %q", spec)
	}

	var srv *http.Server
	func() {
		defer func() {
			if r := recover(); r != nil {
				n.buildPanic = true
			}
		}()
		srv = metrics.MetricsServerWithAdmin("127.0.0.1:0", logLevel, routes...)
	}()
	if srv == nil {
		return nil
	}
	n.met = httptest.NewServer(srv.Handler)
	n.base = n.met.URL
	return nil
}

func (n *n4World) thenNoPanic() error {
	if n.buildPanic {
		return errors.New("MetricsServerWithAdmin panicked")
	}
	if n.met == nil {
		return errors.New("MetricsServerWithAdmin returned no server")
	}
	return nil
}

func (n *n4World) thenOriginalLogLevel() error {
	if string(n.body) != n4OrigLvl {
		return fmt.Errorf("GET /admin/v1/log-level body = %q, want the original handler's %q", n.body, n4OrigLvl)
	}
	return nil
}

// ---------- wiring ----------

// registerN4Steps registers the N4SessionInspection steps; it must run before
// registerAmbrSteps (see the file comment).
func registerN4Steps(sc *godog.ScenarioContext, a *ambrWorld) {
	n := &n4World{a: a}
	sc.Before(func(ctx context.Context, s *godog.Scenario) (context.Context, error) {
		n.active = strings.HasSuffix(s.Uri, "n4_session_inspection.feature")
		return ctx, nil
	})
	sc.After(func(ctx context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
		n.reset()
		return ctx, nil
	})

	// Background
	sc.Step(`^a UPF PFCP server with an empty SessionTable$`, func() error { return a.ensure() })
	sc.Step(`^the N4 session admin endpoint "[^"]*" is served over HTTP from the same SessionTable$`, n.startAdmin)

	// Sessions established through real PFCP
	sc.Step(`^the SMF has established PFCP session "S" with$`, n.givenTable)
	sc.Step(`^the SMF has established PFCP session "S" with the Session-AMBR QER 1 and the flow QER 2(?: and (URR 1 with Measurement Method VOLUM)(?: and Reporting Triggers VOLTH and Volume Threshold (\d+) bytes)?)?$`,
		n.givenSessionAMBR)
	sc.Step(`^a second PFCP session with SEID (0x[0-9a-fA-F]+) and UE IPv4 "([^"]*)" exists$`, n.givenSecond)

	// Shared with ambr_enforcement.feature: dispatched on the active feature.
	sc.Step(`^the SMF sends a PFCP Session Modification Request with (.+)$`, n.modify)
	sc.Step(`^the SMF sends a PFCP Session Deletion Request$`, n.deleteSession)

	// Direct inserts
	sc.Step(`^sessions with UP SEID (0x[0-9a-fA-F]+), (0x[0-9a-fA-F]+) and (0x[0-9a-fA-F]+) were inserted directly into the SessionTable$`, n.insertSEIDs)
	sc.Step(`^a session with CP SEID (0x[0-9a-fA-F]+) and UP SEID (0x[0-9a-fA-F]+) was inserted directly into the SessionTable$`, n.insertCPUP)
	sc.Step(`^a session with SEID (0x[0-9a-fA-F]+) and delegated UE IPv6 "([^"]*)" was inserted directly into the SessionTable$`, n.insertV6)

	// HTTP client
	sc.Step(`^the client sends GET "([^"]*)" with a JSON body "(.*)"$`, n.sendBody)
	sc.Step(`^the client sends GET "([^"]*)" with header "([^"]*)" "([^"]*)"$`, n.sendHeader)
	sc.Step(`^the client sends (GET|POST|PUT|DELETE|PATCH|HEAD) "([^"]*)"$`, n.send)
	sc.Step(`^the client sent GET "([^"]*)" and saw QER 1 with mbr_dl_kbps (\d+)$`, n.sawQER1DL)

	// Response assertions
	sc.Step(`^the response status is (\d+) and Content-Type is "([^"]*)"$`, n.thenStatusCT)
	sc.Step(`^the response status is (\d+)$`, n.thenStatus)
	sc.Step(`^the response has count (\d+) and (\d+) elements? in "sessions"$`, n.thenCountElems)
	sc.Step(`^the response has count (\d+) and "sessions" is an empty JSON array$`, n.thenCountEmpty)
	sc.Step(`^the response has count (\d+) and the session has cp_seid (\d+) and up_seid (\d+)$`, n.thenCountSession)
	sc.Step(`^the response has count (\d+)$`, n.thenCount)
	sc.Step(`^the response header "([^"]*)" is "([^"]*)"$`, n.thenHeader)
	sc.Step(`^the session has no field "([^"]*)"$`, n.thenSessionNoField)
	sc.Step(`^the session has (.+)$`, n.thenSessionHas)
	sc.Step(`^the session lists (\d+) QERs sorted by qer_id$`, n.thenQERsSorted)
	sc.Step(`^QER (\d+) and QER (\d+) have (.+)$`, n.thenBothQERs)
	sc.Step(`^QER (\d+) has (.+)$`, n.thenQER)
	sc.Step(`^PDR (\d+) has source_interface "([^"]*)" and qer_ids (\d+),(\d+) in that order$`, n.thenPDR)
	sc.Step(`^the session urr has (.+)$`, n.thenURR)
	sc.Step(`^the sessions are listed in the order of up_seid (\d+), (\d+), (\d+)$`, n.thenOrder)
	sc.Step(`^the problem cause is "([^"]*)"$`, n.thenProblemCause)
	sc.Step(`^the problem invalidParams contains param "([^"]*)"$`, n.thenProblemParam)
	sc.Step(`^SessionTable\.Describe was not called$`, n.thenDescribeNotCalled)
	sc.Step(`^the live SessionTable still holds (\d+) sessions?$`, n.thenHolds)

	// Deep copy, snapshots, counters, concurrency
	sc.Step(`^SessionTable\.Describe is called and the returned QER IDs, QER list, PDR list and address strings are modified$`, n.describeAndMutate)
	sc.Step(`^SessionTable\.Describe is called again$`, n.describeAgain)
	sc.Step(`^the second description equals the first original description$`, n.thenSecondEqualsFirst)
	sc.Step(`^the live session still stores QER 1 with MBR UL 8000 kbps and MBR DL 8000 kbps and no QFI$`, n.thenLiveQER1)
	sc.Step(`^PDR 1 still references QER IDs 1 and 2 in that order$`, n.thenLivePDR1)
	sc.Step(`^SessionTable\.Describe was called and the result kept$`, n.keepDescription)
	sc.Step(`^the kept description still shows QER 1 with mbr_ul_kbps 8000 and mbr_dl_kbps 8000$`, n.thenKeptShows)
	sc.Step(`^(\d+) uplink packets totalling (\d+) bytes and (\d+) downlink packets totalling (\d+) bytes were accounted to the session$`, n.account)
	sc.Step(`^4 goroutines account URR volume and 2 goroutines store and delete other sessions while Describe is called 200 times$`, n.concurrent)
	sc.Step(`^every Describe call returns without error and without a data race$`, n.thenNoRaceErr)

	// No PFCP traffic
	sc.Step(`^the count of PFCP messages sent by the UPF is recorded$`, n.recordPFCP)
	sc.Step(`^the UPF sent no PFCP message since the count was recorded$`, n.thenNoPFCP)

	// Logs
	sc.Step(`^the UPF logs a line with procedure "([^"]*)", interface "([^"]*)"(?:,| and) direction "([^"]*)"(?: and spec_ref "([^"]*)")?$`, n.logLine)
	sc.Step(`^that log line carries the "([^"]*)" key exactly once$`, n.thenLogOnce)
	sc.Step(`^that log line carries (.+)$`, n.thenLogCarries)

	// Metrics server
	sc.Step(`^a metrics server built with MetricsServerWithAdmin and (.+)$`, n.buildMetrics)
	sc.Step(`^building the server did not panic$`, n.thenNoPanic)
	sc.Step(`^the response is served by the original log-level handler$`, n.thenOriginalLogLevel)

	// @e2e @manual: "E2E_TEST is set to "1" and ..." is registered by the
	// DownlinkChecksum steps; the remaining steps skip (E2E_TEST unset) or are
	// pending (E2E_TEST=1: live assertions are driven through the MCP tools).
	for _, re := range []string{
		`^GET "http://upf:9107/admin/v1/n4-sessions" is requested$`,
		`^the response count equals the number of active PDU sessions reported by "ueransim_status"$`,
		`^each session lists 2 QERs: QER 1 with has_mbr true and no qfi, QER 2 with qfi 1 and has_mbr false$`,
		`^every QER has gate_ul "OPEN" and gate_dl "OPEN"$`,
		`^the UPF log shows procedure "N4SessionInspection" with result "OK" and a single "nf" key$`,
		`^"procedure_summary" reports zero failures for the run$`,
		`^the current Session-AMBR of the slice and the UPF QER 1 mbr_dl_kbps were recorded$`,
		`^the Session-AMBR downlink is set to "30 Mbps" with apply_to_active$`,
		`^GET "http://upf:9107/admin/v1/n4-sessions" shows QER 1 with mbr_dl_kbps 30000$`,
		`^the Session-AMBR is reverted to the recorded value with apply_to_active$`,
		`^GET "http://upf:9107/admin/v1/n4-sessions" shows QER 1 with the originally recorded mbr_dl_kbps$`,
	} {
		sc.Step(re, e2e)
	}
}
