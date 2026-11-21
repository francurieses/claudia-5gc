package procedures

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"testing"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

func TestParseCipheringOrder(t *testing.T) {
	for name, tc := range map[string]struct {
		in      string
		want    []byte
		wantErr bool
	}{
		"default":        {in: DefaultCipheringOrder, want: []byte{2, 1, 3, 0}},
		"lower + spaces": {in: " nea3 ,nea2", want: []byte{3, 2}},
		"single":         {in: "NEA0", want: []byte{0}},
		"empty":          {in: "", wantErr: true},
		"blank tokens":   {in: " , ", wantErr: true},
		"unknown":        {in: "NEA2, AES", wantErr: true},
		"NEA4":           {in: "NEA4", wantErr: true},
		"duplicate":      {in: "NEA2, NEA1, NEA2", wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := ParseCipheringOrder(tc.in)
			if (err != nil) != tc.wantErr || !bytes.Equal(got, tc.want) {
				t.Fatalf("got %v, %v; want %v err=%v", got, err, tc.want, tc.wantErr)
			}
		})
	}
}

func TestResolveCipheringOrderEnv(t *testing.T) {
	t.Setenv(EnvCipheringOrder, "")
	if o, err := ResolveCipheringOrder(""); err != nil || !bytes.Equal(o, []byte{2, 1, 3, 0}) {
		t.Fatalf("default: %v %v", o, err)
	}
	t.Setenv(EnvCipheringOrder, "NEA3, NEA1")
	if o, err := ResolveCipheringOrder("NEA2"); err != nil || !bytes.Equal(o, []byte{3, 1}) {
		t.Fatalf("env override: %v %v", o, err)
	}
	t.Setenv(EnvCipheringOrder, "NEA9")
	if _, err := ResolveCipheringOrder("NEA2"); err == nil {
		t.Fatal("invalid env accepted")
	}
}

// TestSelectSecurityAlgorithmsCiphering: table of order x UE capability, and the
// default order reproduces the legacy NEA2 > NEA1 > NEA0 choice for every UE
// capability combination. Ref: TS 33.501 §6.7.1.1, §6.7.2
func TestSelectSecurityAlgorithmsCiphering(t *testing.T) {
	ueWith := func(ea ...int) *amfctx.UEContext {
		ue := &amfctx.UEContext{}
		for _, i := range ea {
			ue.UESecCapEA[i] = true
		}
		ue.UESecCapIA[2] = true
		return ue
	}
	tests := []struct {
		name  string
		order string
		ea    []int
		want  byte
		fail  bool
	}{
		{"default EA0-3", DefaultCipheringOrder, []int{0, 1, 2, 3}, 2, false},
		{"default EA0,1,3", DefaultCipheringOrder, []int{0, 1, 3}, 1, false},
		{"default EA0,3", DefaultCipheringOrder, []int{0, 3}, 3, false},
		{"default EA0", DefaultCipheringOrder, []int{0}, 0, false},
		{"NEA3 first", "NEA3, NEA2", []int{0, 1, 2, 3}, 3, false},
		{"NEA3 first, UE no EA3", "NEA3, NEA2", []int{1, 2}, 2, false},
		{"no common", "NEA3, NEA2", []int{0, 1}, 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			order, err := ParseCipheringOrder(tc.order)
			if err != nil {
				t.Fatal(err)
			}
			h := &RegistrationHandler{}
			h.WithCipheringOrder(order)
			if got, _, ok := h.selectSecurityAlgorithms(ueWith(tc.ea...)); got != tc.want || ok == tc.fail {
				t.Fatalf("cipher = %d, want %d", got, tc.want)
			}
		})
	}
	// Default order over all 16 EA0..EA3 masks: NEA2 > NEA1 > NEA3 > NEA0, and
	// no EA at all is a failure (never NEA0). Rows are the full expected table.
	wantByMask := [16]struct {
		alg byte
		ok  bool
	}{
		0b0000: {0, false}, 0b0001: {0, true}, 0b0010: {1, true}, 0b0011: {1, true},
		0b0100: {2, true}, 0b0101: {2, true}, 0b0110: {2, true}, 0b0111: {2, true},
		0b1000: {3, true}, 0b1001: {3, true}, 0b1010: {1, true}, 0b1011: {1, true},
		0b1100: {2, true}, 0b1101: {2, true}, 0b1110: {2, true}, 0b1111: {2, true},
	}
	h := &RegistrationHandler{}
	for m := 0; m < 16; m++ {
		ue := &amfctx.UEContext{}
		ue.UESecCapIA[2] = true // integrity is selected first (SEC-007)
		for i := 0; i < 4; i++ {
			ue.UESecCapEA[i] = m&(1<<i) != 0
		}
		got, _, ok := h.selectSecurityAlgorithms(ue)
		if got != wantByMask[m].alg || ok != wantByMask[m].ok {
			t.Fatalf("mask %04b: got (%d,%v), want (%d,%v)", m, got, ok, wantByMask[m].alg, wantByMask[m].ok)
		}
	}
}

// TestSelectSecurityAlgorithmsNoCommonFails: nothing in common with the operator
// list reports failure (never NEA0), also on the path that bypasses Phase1's
// acceptableUESecurityCapability check. Ref: TS 24.501 §5.5.1.2.8 i)
func TestSelectSecurityAlgorithmsNoCommonFails(t *testing.T) {
	h := &RegistrationHandler{}
	o, _ := ParseCipheringOrder("NEA3, NEA2")
	h.WithCipheringOrder(o)
	ue := &amfctx.UEContext{}
	ue.UESecCapEA[0], ue.UESecCapEA[1] = true, true
	ue.UESecCapIA[2] = true
	if _, _, ok := h.selectSecurityAlgorithms(ue); ok {
		t.Fatal("no common cipher must fail")
	}
}

// TestPhase2NoCommonCipherRejects: Phase2 rejects with 5GMM #23 and does not
// start a pending security context when no cipher matches.
func TestPhase2NoCommonCipherRejects(t *testing.T) {
	h := newCountTestHandler()
	o, _ := ParseCipheringOrder("NEA3, NEA2")
	h.WithCipheringOrder(o)
	ue := h.mgr.AllocateUEContext(1)
	ue.UESecCapEA[0], ue.UESecCapEA[1] = true, true
	ue.UESecCapIA[2] = true
	_, _, err := h.Phase2_ProcessAuthResponse(context.Background(), ue,
		&nas.AuthenticationResponse{RES: []byte{1, 2, 3, 4}})
	var rc *ErrRejectCause
	if !errors.As(err, &rc) || rc.Cause != UESecCapRejectCause {
		t.Fatalf("err = %v, want reject cause %d", err, UESecCapRejectCause)
	}
	if ue.SecurityCtx.Active {
		t.Fatal("security context activated despite rejection")
	}
}

func TestCipheringOrderNamesAndWarning(t *testing.T) {
	if got := CipheringOrderNames([]byte{2, 1, 3, 0}); got != "NEA2,NEA1,NEA3,NEA0" {
		t.Fatalf("names = %q", got)
	}
	for in, warn := range map[string]bool{"NEA2,NEA0": false, "NEA0,NEA2": true, "NEA0": true, "NEA1": false} {
		o, _ := ParseCipheringOrder(in)
		if (CipheringOrderWarning(o) != "") != warn {
			t.Errorf("%q warn=%v want %v", in, !warn, warn)
		}
	}
}

func TestResolveCipheringOrderWhitespaceEnvIsUnset(t *testing.T) {
	t.Setenv(EnvCipheringOrder, "   ")
	o, err := ResolveCipheringOrder("NEA3")
	if err != nil || !bytes.Equal(o, []byte{3}) {
		t.Fatalf("got %v %v, want YAML value", o, err)
	}
}

// TestSMCSecurityAlgorithmsGolden: default order, UE NEA0-3 + NIA1-2 -> the SMC
// selected-algorithms octet is 0x22 (NEA2 high nibble, NIA2 low nibble).
// Ref: TS 24.501 §9.11.3.34
func TestSMCSecurityAlgorithmsGolden(t *testing.T) {
	h := newCountTestHandler()
	ue := h.mgr.AllocateUEContext(1)
	for i := 0; i < 4; i++ {
		ue.UESecCapEA[i] = true
	}
	ue.UESecCapIA[1], ue.UESecCapIA[2] = true, true
	smc, _, err := h.Phase2_ProcessAuthResponse(context.Background(), ue,
		&nas.AuthenticationResponse{RES: []byte{1, 2, 3, 4}})
	if err != nil {
		t.Fatal(err)
	}
	if smc.SelectedNASSecurityAlgorithms.CipheringAlgorithmID != 2 || smc.SelectedNASSecurityAlgorithms.IntegrityAlgorithmID != 2 {
		t.Fatalf("selected = %+v, want cipher 2 integrity 2", smc.SelectedNASSecurityAlgorithms)
	}
	if got := smc.SelectedNASSecurityAlgorithms.Encode(); got != 0x22 {
		t.Fatalf("algorithms octet = %#02x, want 0x22", got)
	}
	body, err := nas.EncodeSecurityModeCommand(&nas.SecurityModeCommand{
		SelectedNASSecurityAlgorithms:  smc.SelectedNASSecurityAlgorithms,
		NGKSI:                          nas.NGKSI{},
		ReplayedUESecurityCapabilities: nas.UESecurityCapability{EA0: true, EA1: true, EA2: true, EA3: true, IA1: true, IA2: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(body); got != "220002f060" {
		t.Fatalf("SMC body = %s", got)
	}
}

func TestAcceptableUESecurityCapabilityOrder(t *testing.T) {
	sc := &nas.UESecurityCapability{EA0: true, EA1: true, IA2: true}
	n32, _ := ParseCipheringOrder("NEA3, NEA2")
	n3, _ := ParseCipheringOrder("NEA3, NEA1")
	if acceptableUESecurityCapability(sc, n32, defaultIntegrityOrderIDs) {
		t.Error("no common EA must be rejected (cause 23)")
	}
	if !acceptableUESecurityCapability(sc, n3, defaultIntegrityOrderIDs) {
		t.Error("NEA1 in common must be accepted")
	}
	if !acceptableUESecurityCapability(&nas.UESecurityCapability{EA3: true, IA2: true}, n32, defaultIntegrityOrderIDs) {
		t.Error("EA3-only UE must be accepted when NEA3 is configured")
	}
}

// TestPhase2SMCCipheringField: the SMC carries the selected NEA; default order
// with EA0-3 gives NEA2, byte-identical to the legacy SMC. Ref: TS 24.501 §9.11.3.34
func TestPhase2SMCCipheringField(t *testing.T) {
	for _, tc := range []struct {
		order string
		want  byte
	}{{DefaultCipheringOrder, 2}, {"NEA3, NEA2, NEA1, NEA0", 3}, {"NEA1, NEA2", 1}} {
		h := newCountTestHandler()
		o, _ := ParseCipheringOrder(tc.order)
		h.WithCipheringOrder(o)
		ue := h.mgr.AllocateUEContext(1)
		for i := 0; i < 4; i++ {
			ue.UESecCapEA[i], ue.UESecCapIA[i] = true, true
		}
		smc, _, err := h.Phase2_ProcessAuthResponse(context.Background(), ue,
			&nas.AuthenticationResponse{RES: []byte{1, 2, 3, 4}})
		if err != nil {
			t.Fatal(err)
		}
		if smc.SelectedNASSecurityAlgorithms.CipheringAlgorithmID != tc.want || ue.SecurityCtx.CipheringAlgID != tc.want {
			t.Fatalf("order %q: SMC cipher %d ctx %d, want %d", tc.order,
				smc.SelectedNASSecurityAlgorithms.CipheringAlgorithmID, ue.SecurityCtx.CipheringAlgID, tc.want)
		}
		if smc.SelectedNASSecurityAlgorithms.IntegrityAlgorithmID != 2 {
			t.Fatalf("integrity selection changed: %d", smc.SelectedNASSecurityAlgorithms.IntegrityAlgorithmID)
		}
	}
}

// TestNullCipheringRespectsUECapability: null_ciphering picks NEA0 only when the
// UE advertises 5G-EA0 (AMF-009). Ref: TS 33.501 §5.11.1.1, §6.7.2
func TestNullCipheringRespectsUECapability(t *testing.T) {
	tests := []struct {
		name         string
		ea           [4]bool
		wantCipher   byte
		wantOK       bool
		wantFallback bool
	}{
		{"EA0 advertised", [4]bool{true, true, true, false}, 0, true, false},
		{"EA0 not advertised", [4]bool{false, true, true, false}, 2, true, true},
		{"EA0 not advertised, no common", [4]bool{false, false, false, false}, 0, false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := &RegistrationHandler{nullSecurity: true}
			ue := &amfctx.UEContext{}
			ue.UESecCapIA[2] = true
			copy(ue.UESecCapEA[:], tc.ea[:])
			c, integ, ok, fb := h.selectSecurityAlgorithmsNull(ue)
			if ok && integ != 2 {
				t.Fatalf("integrity = %d, want NIA2 (never NIA0)", integ)
			}
			if c != tc.wantCipher || ok != tc.wantOK || fb != tc.wantFallback {
				t.Fatalf("got (%d,%v,%v), want (%d,%v,%v)", c, ok, fb, tc.wantCipher, tc.wantOK, tc.wantFallback)
			}
		})
	}
}
