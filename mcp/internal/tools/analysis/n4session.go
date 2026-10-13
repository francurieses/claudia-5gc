package analysis

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/oklog/ulid/v2"

	"github.com/francurieses/claudia-5gc/mcp/internal/clients"
	"github.com/francurieses/claudia-5gc/mcp/internal/mcperr"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/toolutil"
)

// n4SessionsPath is the UPF admin route served on the metrics port. It is a
// project O&M endpoint, not a 3GPP service (docs/procedures/n4-session-inspection.md §4.1).
const n4SessionsPath = "/admin/v1/n4-sessions"

// Role names the SMF management view gives to the two QERs it installs
// (nf/smf/internal/server/qos.go, TS 29.244 §7.5.2.5).
const (
	smfRoleSessionAMBR = "session-ambr"
	smfRoleQoSFlow     = "qos-flow"
)

// n4SessionTool joins the SMF session view with the PFCP session held by the UPF
// and reports every disagreement. It is read-only and sends no PFCP message.
// Ref: TS 29.244 §5.2 (packet forwarding model), §7.5.2.5 / §7.5.4.5 (QER).
type n4SessionTool struct{ d Deps }

func (n4SessionTool) Name() string        { return "n4_session_get" }
func (n4SessionTool) Risk() registry.Risk { return registry.ReadOnly }
func (n4SessionTool) Description() string {
	return "Read the PFCP (N4) session the UPF holds (PDRs, QERs with MBR/QFI/gates, URR counters, TEIDs, UE IP) " +
		"and compare it with the SMF session view. Look up by pdu_session_id (optional supi) or by seid / ue_ip, " +
		"not both. Returns {upf, smf, smf_mismatches:[{field, smf, upf}]}; an empty smf_mismatches means SMF and UPF " +
		"agree. Errors: CONTEXT_NOT_FOUND, AMBIGUOUS_SESSION, N4_SESSION_NOT_FOUND (SMF session without UPF session), " +
		"AMBIGUOUS_N4_SESSION. Read-only. Ref: TS 29.244 §5.2, §7.5.2."
}
func (n4SessionTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{
"pdu_session_id":{"type":"integer","minimum":1,"maximum":15,"description":"PDU session id; selects the SMF lookup path"},
"supi":{"type":"string","description":"imsi-<digits>; disambiguates pdu_session_id at the SMF (only with pdu_session_id)"},
"seid":{"description":"PFCP SEID, decimal integer or 0x-hex string, non-zero (not with pdu_session_id)","oneOf":[{"type":"integer","minimum":1},{"type":"string"}]},
"ue_ip":{"type":"string","description":"UE IPv4 or IPv6 address (not with pdu_session_id)"}}}`)
}
func (n4SessionTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"upf":{"type":"object"},"smf":{"type":"object"},
"smf_mismatches":{"type":"array","items":{"type":"object","properties":{"field":{"type":"string"},"smf":{},"upf":{}}}}},
"required":["upf","smf","smf_mismatches"]}`)
}

// n4Query is the validated lookup request.
type n4Query struct {
	psi  int
	supi string
	seid uint64
	ueIP string
}

func (q n4Query) byPSI() bool { return q.psi != 0 }

func n4Invalid(format string, a ...any) *mcperr.Error {
	return mcperr.Newf(mcperr.CodeInvalidParams, nil, "n4_session_get: "+format, a...)
}

// parseSEID accepts a JSON integer or a decimal / 0x-hex string. Base 0 is not used
// so that "010" is decimal 10 and 0o / 0b prefixes are rejected.
func parseSEID(raw json.RawMessage) (uint64, *mcperr.Error) {
	s := strings.TrimSpace(string(raw))
	if strings.HasPrefix(s, `"`) {
		if err := json.Unmarshal(raw, &s); err != nil {
			return 0, n4Invalid("seid: %v", err)
		}
	}
	var v uint64
	var err error
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		v, err = strconv.ParseUint(s[hexPrefixLen:], 16, 64)
	} else {
		v, err = strconv.ParseUint(s, 10, 64)
	}
	if err != nil || v == 0 {
		return 0, n4Invalid("seid must be a non-zero uint64 (decimal or 0x-hex), got %s", string(raw))
	}
	return v, nil
}

func parseN4Query(in json.RawMessage) (n4Query, *mcperr.Error) {
	var q n4Query
	var m map[string]json.RawMessage
	if len(bytes.TrimSpace(in)) > 0 {
		if err := json.Unmarshal(in, &m); err != nil {
			return q, n4Invalid("args: %v", err)
		}
	}
	present := func(k string) (json.RawMessage, bool) {
		v, ok := m[k]
		if !ok || string(bytes.TrimSpace(v)) == "null" {
			return nil, false
		}
		return v, true
	}
	if v, ok := present("pdu_session_id"); ok {
		if err := json.Unmarshal(v, &q.psi); err != nil {
			return q, n4Invalid("pdu_session_id must be an integer 1-15")
		}
		if perr := toolutil.ValidPSI(q.psi); perr != nil {
			return q, perr
		}
	}
	if v, ok := present("supi"); ok {
		if err := json.Unmarshal(v, &q.supi); err != nil {
			return q, n4Invalid("supi must be a string")
		}
		if perr := toolutil.ValidSUPI(q.supi); perr != nil {
			return q, perr
		}
	}
	if v, ok := present("seid"); ok {
		seid, perr := parseSEID(v)
		if perr != nil {
			return q, perr
		}
		q.seid = seid
	}
	if v, ok := present("ue_ip"); ok {
		if err := json.Unmarshal(v, &q.ueIP); err != nil || net.ParseIP(q.ueIP) == nil {
			return q, n4Invalid("ue_ip must be an IPv4 or IPv6 literal")
		}
	}
	hasB := q.seid != 0 || q.ueIP != ""
	switch {
	case q.psi == 0 && !hasB && q.supi != "":
		return q, n4Invalid("supi alone is not a lookup key: the SMF endpoint is keyed by pdu_session_id")
	case q.psi == 0 && !hasB:
		return q, n4Invalid("one of pdu_session_id, seid or ue_ip is required")
	case q.psi != 0 && hasB:
		return q, n4Invalid("pdu_session_id cannot be combined with seid or ue_ip")
	case q.psi == 0 && q.supi != "":
		return q, n4Invalid("supi is only valid together with pdu_session_id")
	}
	return q, nil
}

// ---- upstream views ---------------------------------------------------------

type smfQER struct {
	QERID  uint32  `json:"qerId"`
	Role   string  `json:"role"`
	QFI    *uint8  `json:"qfi"`
	GateUL string  `json:"gateUl"`
	GateDL string  `json:"gateDl"`
	MBRUl  *uint64 `json:"mbrUlKbps"`
	MBRDl  *uint64 `json:"mbrDlKbps"`
}

type smfSessionView struct {
	Session struct {
		SUPI    string `json:"supi"`
		PSI     int    `json:"pduSessionId"`
		SEID    uint64 `json:"seid"`
		UPFTeid uint32 `json:"upfTeid"`
		UEIP    string `json:"ueIp"`
	} `json:"session"`
	PfcpQers []smfQER `json:"pfcpQers"`
}

type upfQER struct {
	QERID  uint32 `json:"qer_id"`
	QFI    *uint8 `json:"qfi"`
	GateUL string `json:"gate_ul"`
	GateDL string `json:"gate_dl"`
	HasMBR bool   `json:"has_mbr"`
	MBRUL  uint64 `json:"mbr_ul_kbps"`
	MBRDL  uint64 `json:"mbr_dl_kbps"`
}

type upfSession struct {
	CPSEID uint64   `json:"cp_seid"`
	UPSEID uint64   `json:"up_seid"`
	UEIPv4 string   `json:"ue_ipv4"`
	UEIPv6 string   `json:"ue_ipv6"`
	ULTEID uint32   `json:"ul_teid"`
	QERs   []upfQER `json:"qers"`
}

// ---- invoke -----------------------------------------------------------------

func (t n4SessionTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	q, perr := parseN4Query(in)
	if perr != nil {
		return nil, perr
	}
	if t.d.SMF == nil {
		return nil, mcperr.ToolError(errors.New("n4_session_get: SMF client is not configured"),
			map[string]any{"upstream": "smf"})
	}
	if q.byPSI() {
		return t.byPSI(ctx, q)
	}
	return t.bySEIDOrIP(ctx, q)
}

func (t n4SessionTool) byPSI(ctx context.Context, q n4Query) (any, error) {
	rawSMF, view, err := t.getSMF(ctx, q.psi, q.supi)
	if err != nil {
		return nil, err
	}
	addr, err := t.upfAddr(ctx)
	if err != nil {
		return nil, err
	}
	sessions, err := t.queryUPF(ctx, addr, view.Session.SEID, "")
	if err != nil {
		return nil, err
	}
	switch {
	case len(sessions) == 0:
		return nil, n4NotFound(map[string]any{"smf": rawSMF, "seid": view.Session.SEID},
			"SMF holds PDU session %d with seid %d but the UPF has no PFCP session for it", q.psi, view.Session.SEID)
	case len(sessions) > 1:
		return nil, ambiguousN4(sessions)
	}
	return buildN4Result(sessions[0], rawSMF, view), nil
}

func (t n4SessionTool) bySEIDOrIP(ctx context.Context, q n4Query) (any, error) {
	addr, err := t.upfAddr(ctx)
	if err != nil {
		return nil, err
	}
	sessions, err := t.queryUPF(ctx, addr, q.seid, q.ueIP)
	if err != nil {
		return nil, err
	}
	if len(sessions) > 1 {
		return nil, ambiguousN4(sessions)
	}
	key := map[string]any{}
	if q.seid != 0 {
		key["seid"] = q.seid
	}
	if q.ueIP != "" {
		key["ue_ip"] = q.ueIP
	}
	var match upfSession
	if len(sessions) == 1 {
		match = sessions[0].parsed
	}
	psi, supi, found, err := t.findSMFSession(ctx, q, match, len(sessions) == 1)
	if err != nil {
		return nil, err
	}
	if len(sessions) == 0 {
		data := cloneMap(key)
		data["smf"] = nil
		if found {
			if raw, _, gerr := t.getSMF(ctx, psi, supi); gerr == nil {
				data["smf"] = raw
			}
		}
		return nil, n4NotFound(data, "the UPF holds no PFCP session for the query")
	}
	if !found {
		data := cloneMap(key)
		data["upf"] = sessions[0].raw
		return nil, mcperr.Newf(mcperr.CodeToolError, withCode(data, "CONTEXT_NOT_FOUND"),
			"the UPF holds PFCP session seid %d but the SMF has no matching session", match.CPSEID)
	}
	rawSMF, view, err := t.getSMF(ctx, psi, supi)
	if err != nil {
		var me *mcperr.Error
		if errors.As(err, &me) && me.Data != nil && me.Data["code"] == "CONTEXT_NOT_FOUND" {
			data := cloneMap(key)
			data["upf"] = sessions[0].raw
			return nil, mcperr.Newf(mcperr.CodeToolError, withCode(data, "CONTEXT_NOT_FOUND"),
				"the UPF holds PFCP session seid %d but the SMF has no matching session", match.CPSEID)
		}
		return nil, err
	}
	return buildN4Result(sessions[0], rawSMF, view), nil
}

// findSMFSession scans the SMF session list for the session matching the UPF
// session (seid == cp_seid) or, when the UPF has none, the query seid / ue_ip.
func (t n4SessionTool) findSMFSession(ctx context.Context, q n4Query, up upfSession, haveUPF bool) (psi int, supi string, found bool, err error) {
	cctx, cancel := context.WithTimeout(ctx, upstreamTimeout)
	defer cancel()
	raw, lerr := t.d.SMF.ListSessions(cctx)
	if lerr != nil {
		return 0, "", false, mcperr.ToolError(fmt.Errorf("n4_session_get: smf: %w", lerr),
			map[string]any{"upstream": "smf", "status": statusFromErr(lerr)})
	}
	var wrapped struct {
		Sessions []struct {
			SUPI string `json:"supi"`
			PSI  int    `json:"pduSessionId"`
			SEID uint64 `json:"seid"`
			UEIP string `json:"ueIp"`
		} `json:"sessions"`
	}
	if jerr := json.Unmarshal(raw, &wrapped); jerr != nil {
		return 0, "", false, mcperr.ToolError(fmt.Errorf("n4_session_get: smf: decode session list: %w", jerr),
			map[string]any{"upstream": "smf"})
	}
	for _, s := range wrapped.Sessions {
		switch {
		case haveUPF && s.SEID == up.CPSEID:
		case !haveUPF && q.seid != 0 && s.SEID == q.seid:
		case !haveUPF && q.seid == 0 && sameIP(s.UEIP, q.ueIP):
		default:
			continue
		}
		return s.PSI, s.SUPI, true, nil
	}
	return 0, "", false, nil
}

func sameIP(a, b string) bool {
	ia, ib := net.ParseIP(a), net.ParseIP(b)
	return ia != nil && ib != nil && ia.Equal(ib)
}

func cloneMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m)+2)
	for k, v := range m {
		out[k] = v
	}
	return out
}

func withCode(m map[string]any, code string) map[string]any {
	m["code"] = code
	return m
}

func n4NotFound(data map[string]any, format string, a ...any) *mcperr.Error {
	return mcperr.Newf(mcperr.CodeToolError, withCode(data, "N4_SESSION_NOT_FOUND"), format, a...)
}

// getSMF reads one SMF session and maps 404 / 409 / transport errors.
func (t n4SessionTool) getSMF(ctx context.Context, psi int, supi string) (json.RawMessage, *smfSessionView, error) {
	cctx, cancel := context.WithTimeout(ctx, upstreamTimeout)
	defer cancel()
	raw, err := t.d.SMF.GetSession(cctx, psi, supi)
	if err != nil {
		if strings.Contains(err.Error(), "status 409") {
			return nil, nil, mcperr.Newf(mcperr.CodeToolError,
				map[string]any{"code": "AMBIGUOUS_SESSION", "pdu_session_id": psi},
				"several SMF sessions share pdu_session_id %d; pass supi to select one", psi)
		}
		return nil, nil, mcperr.ToolError(fmt.Errorf("n4_session_get: smf: %w", err),
			map[string]any{"upstream": "smf", "status": statusFromErr(err)})
	}
	if raw == nil {
		return nil, nil, mcperr.Newf(mcperr.CodeToolError,
			map[string]any{"code": "CONTEXT_NOT_FOUND", "pdu_session_id": psi},
			"no SMF session with pdu_session_id %d", psi)
	}
	var v smfSessionView
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, nil, mcperr.ToolError(fmt.Errorf("n4_session_get: smf: decode session: %w", err),
			map[string]any{"upstream": "smf"})
	}
	return raw, &v, nil
}

// statusFromErr extracts the HTTP status that the clients package embeds as
// "status NNN" in its error text; 0 when the failure was a transport error.
func statusFromErr(err error) int {
	s := err.Error()
	i := strings.Index(s, "status ")
	if i < 0 || len(s) < i+10 {
		return 0
	}
	n, _ := strconv.Atoi(s[i+7 : i+10])
	return n
}

const (
	// n4UPFTargetLabel is the value of the Prometheus "nf" label of the UPF scrape
	// target; the live prometheus.yml labels NFs in uppercase (nf="UPF").
	n4UPFTargetLabel = "UPF"
	// hexPrefixLen is the length of the "0x"/"0X" prefix of a hex SEID string.
	hexPrefixLen = 2
	// n4MaxUPFBodyBytes bounds the UPF admin response body read (8 MiB).
	n4MaxUPFBodyBytes = 8 << 20
	// correlationHeader carries the ULID that joins the MCP call to the UPF canonical log.
	correlationHeader = "X-Correlation-Id"
)

func (t n4SessionTool) upfAddr(ctx context.Context) (string, error) {
	targets := t.d.Targets
	if targets == nil {
		if t.d.Prom == nil {
			return "", mcperr.ToolError(errors.New("n4_session_get: no Prometheus client to resolve the UPF"),
				map[string]any{"upstream": "prometheus"})
		}
		targets = clients.NewTargets(t.d.Prom, "")
	}
	cctx, cancel := context.WithTimeout(ctx, upstreamTimeout)
	defer cancel()
	addr, err := targets.Addr(cctx, n4UPFTargetLabel)
	if err != nil {
		return "", mcperr.ToolError(fmt.Errorf("n4_session_get: resolve upf target: %w", err),
			map[string]any{"upstream": "prometheus"})
	}
	return addr, nil
}

// n4UPFSession keeps the raw UPF JSON (returned unchanged) next to its typed form.
type n4UPFSession struct {
	raw    json.RawMessage
	parsed upfSession
}

// queryUPF calls GET /admin/v1/n4-sessions on the UPF metrics port.
func (t n4SessionTool) queryUPF(ctx context.Context, addr string, seid uint64, ueIP string) ([]n4UPFSession, error) {
	vals := url.Values{}
	if seid != 0 {
		vals.Set("seid", strconv.FormatUint(seid, 10))
	}
	if ueIP != "" {
		vals.Set("ue_ip", ueIP)
	}
	u := "http://" + addr + n4SessionsPath
	if len(vals) > 0 {
		u += "?" + vals.Encode()
	}
	upErr := func(err error, status int) error {
		return mcperr.ToolError(fmt.Errorf("n4_session_get: upf: %w", err),
			map[string]any{"upstream": "upf", "status": status})
	}
	cctx, cancel := context.WithTimeout(ctx, upstreamTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, upErr(err, 0)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set(correlationHeader, ulid.Make().String())
	hc := t.d.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, upErr(err, 0)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, n4MaxUPFBodyBytes))
	if err != nil {
		return nil, upErr(err, resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, upErr(fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(body))), resp.StatusCode)
	}
	var wrapped struct {
		Sessions []json.RawMessage `json:"sessions"`
	}
	if err := json.Unmarshal(body, &wrapped); err != nil {
		return nil, upErr(fmt.Errorf("decode response: %w", err), resp.StatusCode)
	}
	out := make([]n4UPFSession, 0, len(wrapped.Sessions))
	for _, r := range wrapped.Sessions {
		var s upfSession
		if err := json.Unmarshal(r, &s); err != nil {
			return nil, upErr(fmt.Errorf("decode session: %w", err), resp.StatusCode)
		}
		out = append(out, n4UPFSession{raw: r, parsed: s})
	}
	return out, nil
}

func ambiguousN4(sessions []n4UPFSession) *mcperr.Error {
	seids := make([]uint64, 0, len(sessions))
	for _, s := range sessions {
		seids = append(seids, s.parsed.CPSEID)
	}
	sort.Slice(seids, func(i, j int) bool { return seids[i] < seids[j] })
	return mcperr.Newf(mcperr.CodeToolError, map[string]any{"code": "AMBIGUOUS_N4_SESSION", "seids": seids},
		"the UPF returned %d PFCP sessions for the query; narrow it with seid", len(sessions))
}

// ---- diff -------------------------------------------------------------------

type n4Mismatch struct {
	Field string `json:"field"`
	SMF   any    `json:"smf"`
	UPF   any    `json:"upf"`
}

func buildN4Result(up n4UPFSession, rawSMF json.RawMessage, v *smfSessionView) map[string]any {
	return map[string]any{
		"upf":            up.raw,
		"smf":            rawSMF,
		"smf_mismatches": diffN4(v, &up.parsed),
	}
}

func qfiVal(p *uint8) any {
	if p == nil {
		return nil
	}
	return *p
}

// diffN4 applies the rules of docs/procedures/n4-session-inspection.md §4.5.
// The result is never nil.
func diffN4(v *smfSessionView, u *upfSession) []n4Mismatch {
	out := []n4Mismatch{}
	add := func(field string, smf, upf any) { out = append(out, n4Mismatch{field, smf, upf}) }

	if v.Session.SEID != u.CPSEID {
		add("cp_seid", v.Session.SEID, u.CPSEID)
	}
	if v.Session.UEIP != "" {
		upIP := u.UEIPv4
		if ip := net.ParseIP(v.Session.UEIP); ip != nil && ip.To4() == nil {
			upIP = u.UEIPv6
		}
		if !sameIP(v.Session.UEIP, upIP) {
			var upv any
			if upIP != "" {
				upv = upIP
			}
			add("ue_ip", v.Session.UEIP, upv)
		}
	}
	if v.Session.UPFTeid != u.ULTEID {
		add("ul_teid", v.Session.UPFTeid, u.ULTEID)
	}
	if len(v.PfcpQers) != len(u.QERs) {
		add("qer_count", len(v.PfcpQers), len(u.QERs))
	}

	upByID := map[uint32]upfQER{}
	for _, q := range u.QERs {
		upByID[q.QERID] = q
	}
	smfByID := map[uint32]smfQER{}
	ids := []uint32{}
	for _, q := range v.PfcpQers {
		smfByID[q.QERID] = q
		ids = append(ids, q.QERID)
	}
	for id := range upByID {
		if _, ok := smfByID[id]; !ok {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

	for _, id := range ids {
		sq, sOK := smfByID[id]
		uq, uOK := upByID[id]
		f := func(s string) string { return fmt.Sprintf("qers[%d].%s", id, s) }
		switch {
		case sOK && !uOK:
			add(fmt.Sprintf("qers[%d]", id), "present", nil)
			continue
		case !sOK && uOK:
			add(fmt.Sprintf("qers[%d]", id), nil, "present")
			continue
		}
		if sq.Role == smfRoleSessionAMBR {
			var sUL, sDL, uUL, uDL uint64
			if sq.MBRUl != nil {
				sUL = *sq.MBRUl
			}
			if sq.MBRDl != nil {
				sDL = *sq.MBRDl
			}
			if uq.HasMBR {
				uUL, uDL = uq.MBRUL, uq.MBRDL
			}
			if sUL != uUL {
				add(f("mbr_ul_kbps"), sUL, uUL)
			}
			if sDL != uDL {
				add(f("mbr_dl_kbps"), sDL, uDL)
			}
			// The Session-AMBR QER carries no QFI (rule 5); the SMF reports none.
			if uq.QFI != nil {
				add(f("qfi"), nil, *uq.QFI)
			}
		} else if !ptrEq(sq.QFI, uq.QFI) {
			add(f("qfi"), qfiVal(sq.QFI), qfiVal(uq.QFI))
		}
		if sq.GateUL != uq.GateUL {
			add(f("gate_ul"), sq.GateUL, uq.GateUL)
		}
		if sq.GateDL != uq.GateDL {
			add(f("gate_dl"), sq.GateDL, uq.GateDL)
		}
	}
	return out
}

func ptrEq(a, b *uint8) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}
