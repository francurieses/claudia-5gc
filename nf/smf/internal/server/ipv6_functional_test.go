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
