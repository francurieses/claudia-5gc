//go:build functional

// godog step definitions for IPv6 / IPv4v6 prefix delegation.
// Run with: go test -tags=functional ./nf/smf/...
// Ref: TS 23.501 §5.8.2.2, TS 24.501 §9.11.4.10.
package server

import (
	"bytes"
	"fmt"
	"net"
	"testing"

	"github.com/cucumber/godog"
	pfcpie "github.com/wmnsk/go-pfcp/ie"

	"github.com/francurieses/claudia-5gc/shared/nas"
)

type ipv6World struct {
	dnnSupportsV6 bool
	v6Pool        *IPv6Pool

	requested *uint8
	granted   uint8
	iid       []byte
	acceptIE  []byte // PDU Address IE value (octet3 onwards), or nil

	// allocation scenarios
	pool       *IPv6Pool
	p1, p2, p3 *net.IPNet
	baseNet    *net.IPNet

	// data-plane scenarios: PFCP Create PDR UE IP Address IE (TS 29.244 §8.2.62)
	sess *Session
	ie   *pfcpie.IE
}

func typeValue(name string) (uint8, error) {
	switch name {
	case "IPv4":
		return nas.PDUSessionTypeIPv4, nil
	case "IPv6":
		return nas.PDUSessionTypeIPv6, nil
	case "IPv4v6":
		return nas.PDUSessionTypeIPv4v6, nil
	default:
		return 0, fmt.Errorf("unknown PDU session type %q", name)
	}
}

func (w *ipv6World) dnnIPv4Only(string) error {
	w.dnnSupportsV6 = false
	w.v6Pool = nil
	return nil
}

func (w *ipv6World) dnnWithV6(_, prefix string) error {
	p, err := NewIPv6Pool(prefix)
	if err != nil {
		return err
	}
	w.v6Pool = p
	w.dnnSupportsV6 = true
	return nil
}

func (w *ipv6World) ueRequests(typeName string) error {
	rt, err := typeValue(typeName)
	if err != nil {
		return err
	}
	w.requested = &rt
	w.granted = selectPDUSessionType(w.requested, w.dnnSupportsV6)

	var v4 net.IP
	if pduTypeNeedsIPv4(w.granted) {
		v4 = net.ParseIP("10.0.0.5")
	}
	if pduTypeNeedsIPv6(w.granted) {
		_, w.iid, err = w.v6Pool.Allocate()
		if err != nil {
			return err
		}
	}
	// Encode the accept body and extract the PDU Address IE value by walking the
	// known structure: octet0 | [2B len + QoS rules] | [1B len + AMBR] | IE.
	body, err := nas.EncodePDUSessionEstablishmentAcceptBodyWithQoSAddr(
		nas.PDUAddressInfo{SessionType: w.granted, IPv4: v4, IPv6IID: w.iid},
		nas.SSCMode1, "internet", 1, 9, 100, 50)
	if err != nil {
		return err
	}
	qosLen := int(body[1])<<8 | int(body[2])
	off := 3 + qosLen
	off += 1 + int(body[off]) // skip AMBR
	if off >= len(body) || body[off] != nas.IEIPDUAddress {
		w.acceptIE = nil
		return nil
	}
	ieLen := int(body[off+1])
	w.acceptIE = append([]byte(nil), body[off+2:off+2+ieLen]...)
	return nil
}

func (w *ipv6World) grantedTypeIs(typeName string) error {
	want, err := typeValue(typeName)
	if err != nil {
		return err
	}
	if w.granted != want {
		return fmt.Errorf("granted type = %d, want %d (%s)", w.granted, want, typeName)
	}
	return nil
}

func (w *ipv6World) ieTypeAndLen(typeOctet string, n int) error {
	if w.acceptIE == nil {
		return fmt.Errorf("no PDU Address IE was encoded")
	}
	var want byte
	if _, err := fmt.Sscanf(typeOctet, "0x%02x", &want); err != nil {
		return err
	}
	if w.acceptIE[0] != want {
		return fmt.Errorf("type octet = 0x%02X, want %s", w.acceptIE[0], typeOctet)
	}
	if got := len(w.acceptIE) - 1; got != n {
		return fmt.Errorf("address octets = %d, want %d", got, n)
	}
	return nil
}

func (w *ipv6World) ieCarriesIID() error {
	if len(w.acceptIE) < 9 {
		return fmt.Errorf("IE too short to carry an 8-octet IID")
	}
	addr := w.acceptIE[1:9]
	if !bytes.Equal(addr, w.iid) {
		return fmt.Errorf("IE address octets % X != assigned IID % X", addr, w.iid)
	}
	return nil
}

func (w *ipv6World) poolOver(prefix string) error {
	p, err := NewIPv6Pool(prefix)
	if err != nil {
		return err
	}
	w.pool = p
	_, w.baseNet, err = net.ParseCIDR(prefix)
	return err
}

func (w *ipv6World) allocateTwo() error {
	var err error
	if w.p1, _, err = w.pool.Allocate(); err != nil {
		return err
	}
	if w.p2, _, err = w.pool.Allocate(); err != nil {
		return err
	}
	return nil
}

func (w *ipv6World) distinctAndInside() error {
	if w.p1.String() == w.p2.String() {
		return fmt.Errorf("prefixes not distinct: %s", w.p1)
	}
	for _, p := range []*net.IPNet{w.p1, w.p2} {
		if ones, _ := p.Mask.Size(); ones != 64 {
			return fmt.Errorf("%s is not a /64", p)
		}
		if !w.baseNet.Contains(p.IP) {
			return fmt.Errorf("%s outside base pool %s", p, w.baseNet)
		}
	}
	return nil
}

func (w *ipv6World) releaseFirstAllocThird() error {
	w.pool.Release(w.p1)
	var err error
	w.p3, _, err = w.pool.Allocate()
	return err
}

func (w *ipv6World) thirdReusesReleased() error {
	if w.p3.String() != w.p1.String() {
		return fmt.Errorf("third %s did not reuse released %s", w.p3, w.p1)
	}
	return nil
}

// --- Data plane (SMF-002): PFCP Create PDR UE IP Address IE, TS 29.244 §8.2.62 ---

func (w *ipv6World) sessionGrantedIPv4Only(typeName, v4 string) error {
	t, err := typeValue(typeName)
	if err != nil {
		return err
	}
	w.sess = &Session{PDUSessionType: t, UEIP: net.ParseIP(v4)}
	if w.sess.UEIP == nil {
		return fmt.Errorf("invalid IPv4 address %q", v4)
	}
	return nil
}

func (w *ipv6World) sessionGrantedIPv6Only(typeName, prefix string) error {
	t, err := typeValue(typeName)
	if err != nil {
		return err
	}
	w.sess = &Session{PDUSessionType: t, UEIPv6Prefix: prefix}
	return nil
}

func (w *ipv6World) sessionGrantedIPv4v6(typeName, v4, prefix string) error {
	t, err := typeValue(typeName)
	if err != nil {
		return err
	}
	ip := net.ParseIP(v4)
	if ip == nil {
		return fmt.Errorf("invalid IPv4 address %q", v4)
	}
	w.sess = &Session{PDUSessionType: t, UEIP: ip, UEIPv6Prefix: prefix}
	return nil
}

// buildPFCPUEIPAddressIE calls the real production helper (buildUEIPAddressIE,
// same package) so the scenario proves the wire encoding the SMF actually
// sends to the UPF over N4 — not a re-implementation of the logic.
func (w *ipv6World) buildPFCPUEIPAddressIE() error {
	ie, _, err := buildUEIPAddressIE(w.sess)
	if err != nil {
		return err
	}
	w.ie = ie
	return nil
}

func (w *ipv6World) ieFlagsAre(flagStr string) error {
	var want byte
	if _, err := fmt.Sscanf(flagStr, "0x%02x", &want); err != nil {
		return err
	}
	fields, err := w.ie.UEIPAddress()
	if err != nil {
		return err
	}
	if fields.Flags != want {
		return fmt.Errorf("UE IP Address IE flags = 0x%02x, want 0x%02x", fields.Flags, want)
	}
	return nil
}

func (w *ipv6World) ieCarriesIPv4OnlyNoIPv6(v4 string) error {
	fields, err := w.ie.UEIPAddress()
	if err != nil {
		return err
	}
	want := net.ParseIP(v4)
	if fields.IPv4Address == nil || !fields.IPv4Address.Equal(want) {
		return fmt.Errorf("IE IPv4Address = %s, want %s", fields.IPv4Address, want)
	}
	if fields.IPv6Address != nil {
		return fmt.Errorf("expected no IPv6Address in the IE, got %s", fields.IPv6Address)
	}
	return nil
}

func (w *ipv6World) ieCarriesIPv6OnlyNoIPv4(v6 string) error {
	fields, err := w.ie.UEIPAddress()
	if err != nil {
		return err
	}
	want := net.ParseIP(v6)
	if fields.IPv6Address == nil || !fields.IPv6Address.Equal(want) {
		return fmt.Errorf("IE IPv6Address = %s, want %s", fields.IPv6Address, want)
	}
	if fields.IPv4Address != nil {
		return fmt.Errorf("expected no IPv4Address in the IE, got %s", fields.IPv4Address)
	}
	return nil
}

func (w *ipv6World) ieCarriesBothAddresses(v4, v6 string) error {
	fields, err := w.ie.UEIPAddress()
	if err != nil {
		return err
	}
	wantV4 := net.ParseIP(v4)
	wantV6 := net.ParseIP(v6)
	if fields.IPv4Address == nil || !fields.IPv4Address.Equal(wantV4) {
		return fmt.Errorf("IE IPv4Address = %s, want %s", fields.IPv4Address, wantV4)
	}
	if fields.IPv6Address == nil || !fields.IPv6Address.Equal(wantV6) {
		return fmt.Errorf("IE IPv6Address = %s, want %s", fields.IPv6Address, wantV6)
	}
	return nil
}

// ieBytesUnchanged proves the IPv4-only PFCP UE IP Address IE wire encoding
// is byte-identical to the pre-IPv6 reference (flags 0x02, no V6 field) —
// zero regression for the default UERANSIM flow.
func (w *ipv6World) ieBytesUnchanged() error {
	got, err := w.ie.Marshal()
	if err != nil {
		return err
	}
	ref := pfcpie.NewUEIPAddress(0x02, w.sess.UEIP.String(), "", 0, 0)
	want, err := ref.Marshal()
	if err != nil {
		return err
	}
	if !bytes.Equal(got, want) {
		return fmt.Errorf("UE IP Address IE bytes changed: got % x, want % x", got, want)
	}
	return nil
}

func InitializeScenario(ctx *godog.ScenarioContext) {
	w := &ipv6World{}
	ctx.Step(`^a DNN "([^"]*)" with an IPv4 pool and no IPv6 prefix$`, w.dnnIPv4Only)
	ctx.Step(`^a DNN "([^"]*)" with an IPv4 pool and an IPv6 prefix "([^"]*)"$`, w.dnnWithV6)
	ctx.Step(`^a UE requests PDU session type "([^"]*)"$`, w.ueRequests)
	ctx.Step(`^the granted PDU session type is "([^"]*)"$`, w.grantedTypeIs)
	ctx.Step(`^the PDU Address IE has type octet "([^"]*)" and (\d+) address octets$`, w.ieTypeAndLen)
	ctx.Step(`^the PDU Address IE address octets carry the interface identifier, not the /64 prefix$`, w.ieCarriesIID)
	ctx.Step(`^an IPv6 pool over "([^"]*)"$`, w.poolOver)
	ctx.Step(`^two /64 prefixes are allocated$`, w.allocateTwo)
	ctx.Step(`^the two prefixes are distinct and inside the pool$`, w.distinctAndInside)
	ctx.Step(`^the first prefix is released and a third is allocated$`, w.releaseFirstAllocThird)
	ctx.Step(`^the third prefix reuses the released /64$`, w.thirdReusesReleased)

	// Data plane: PFCP Create PDR UE IP Address IE (TS 29.244 §8.2.62, SMF-002).
	ctx.Step(`^a PDU session granted type "([^"]*)" with UE IPv4 "([^"]*)" and UE IPv6 prefix "([^"]*)"$`, w.sessionGrantedIPv4v6)
	ctx.Step(`^a PDU session granted type "([^"]*)" with UE IPv4 "([^"]*)"$`, w.sessionGrantedIPv4Only)
	ctx.Step(`^a PDU session granted type "([^"]*)" with UE IPv6 prefix "([^"]*)"$`, w.sessionGrantedIPv6Only)
	ctx.Step(`^the SMF builds the PFCP UE IP Address IE for the session$`, w.buildPFCPUEIPAddressIE)
	ctx.Step(`^the UE IP Address IE flags are "([^"]*)"$`, w.ieFlagsAre)
	ctx.Step(`^the UE IP Address IE carries IPv4 address "([^"]*)" and no IPv6 address$`, w.ieCarriesIPv4OnlyNoIPv6)
	ctx.Step(`^the UE IP Address IE carries IPv6 address "([^"]*)" and no IPv4 address$`, w.ieCarriesIPv6OnlyNoIPv4)
	ctx.Step(`^the UE IP Address IE carries IPv4 address "([^"]*)" and IPv6 address "([^"]*)"$`, w.ieCarriesBothAddresses)
	ctx.Step(`^the UE IP Address IE bytes are unchanged from the pre-IPv6 wire encoding$`, w.ieBytesUnchanged)
}

func TestIPv6Features(t *testing.T) {
	suite := godog.TestSuite{
		ScenarioInitializer: InitializeScenario,
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{"../../tests/features/ipv6_prefix_delegation.feature"},
			TestingT: t,
		},
	}
	if suite.Run() != 0 {
		t.Fatal("godog scenarios failed")
	}
}
