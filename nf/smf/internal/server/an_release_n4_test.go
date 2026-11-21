package server

import (
	"bytes"
	"testing"

	pfcpie "github.com/wmnsk/go-pfcp/ie"
)

// applyActionOf returns the Apply Action octet and whether the Update FAR carries
// Update Forwarding Parameters or a BAR ID, parsed from the marshalled Update FAR.
func applyActionOf(t *testing.T, far []byte) (aa byte, hasFwd bool, hasBAR bool) {
	t.Helper()
	ie, err := pfcpie.Parse(far)
	if err != nil {
		t.Fatalf("parse Update FAR: %v", err)
	}
	children, err := ie.UpdateFAR()
	if err != nil {
		t.Fatalf("UpdateFAR children: %v", err)
	}
	for _, c := range children {
		switch c.Type {
		case pfcpie.ApplyAction:
			aa = c.Payload[0]
		case pfcpie.UpdateForwardingParameters:
			hasFwd = true
		case pfcpie.BARID:
			hasBAR = true
		}
	}
	return aa, hasFwd, hasBAR
}

// TestBuildDLBuffNocpFAR: AN release Update FAR is BUFF|NOCP (0x0C), no forwarding, no BAR.
// Ref: TS 23.502 §4.2.6 step 6a; TS 29.244 §8.2.26.
func TestBuildDLBuffNocpFAR(t *testing.T) {
	aa, fwd, bar := applyActionOf(t, farBytes(t, buildDLBuffNocpFAR()))
	if aa != 0x0C || fwd || bar {
		t.Fatalf("apply action=%#x fwd=%v bar=%v, want 0x0c false false", aa, fwd, bar)
	}
	if dropAA, _, _ := applyActionOf(t, farBytes(t, buildDLDropFAR())); dropAA != 0x01 {
		t.Fatalf("DROP FAR apply action = %#x, want 0x01", dropAA)
	}
}

// TestAnReleaseSendsBuffNocp: the AN release N4 leg carries 0x0C on the wire, while the
// handover/deactivate path (pfcpDeactivateDL) still emits DROP 0x01.
func TestAnReleaseSendsBuffNocp(t *testing.T) {
	s, sess, upf := hoRespFixture(t)
	s.sendPFCPSessionDeactivation(t.Context(), sess)
	reqs := upf.requests()
	if len(reqs) != 1 {
		t.Fatalf("PFCP requests = %d, want 1", len(reqs))
	}
	if aa, fwd, _ := applyActionOf(t, reqs[0].far); aa != 0x0C || fwd {
		t.Fatalf("AN release apply action=%#x fwd=%v, want 0x0c false", aa, fwd)
	}
	if !bytes.Equal(reqs[0].far, farBytes(t, buildDLBuffNocpFAR())) {
		t.Fatal("wire FAR differs from buildDLBuffNocpFAR")
	}

	if _, err := s.pfcpDeactivateDL(t.Context(), s.logger, "N2Handover", sess); err != nil {
		t.Fatalf("pfcpDeactivateDL: %v", err)
	}
	reqs = upf.requests()
	if len(reqs) != 2 {
		t.Fatalf("PFCP requests = %d, want 2", len(reqs))
	}
	if aa, _, _ := applyActionOf(t, reqs[1].far); aa != 0x01 {
		t.Fatalf("handover deactivate apply action = %#x, want 0x01", aa)
	}
}
