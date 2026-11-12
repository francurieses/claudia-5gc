package nas_test

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/nas"
)

func TestServiceAreaList_Vectors(t *testing.T) {
	tests := []struct {
		name string
		in   nas.ServiceAreaList
		want string // TLV hex
	}{
		{"type00 allowed", nas.ServiceAreaList{Partial: []nas.PartialServiceAreaList{
			{TypeOfList: 0, MCC: "001", MNC: "01", TACs: []uint32{1, 2}}}}, "270a" + "0100f110" + "000001" + "000002"},
		{"type01 consecutive", nas.ServiceAreaList{Partial: []nas.PartialServiceAreaList{
			{TypeOfList: 1, MCC: "001", MNC: "01", TACs: []uint32{0x10, 0x11, 0x12}}}}, "2707" + "2200f110" + "000010"},
		{"type10 different PLMNs", nas.ServiceAreaList{Partial: []nas.PartialServiceAreaList{
			{TypeOfList: 2, TAIs: []nas.ServiceAreaTAI{{"001", "01", 1}, {"310", "410", 2}}}}},
			"270d" + "41" + "00f110" + "000001" + "130014" + "000002"},
		{"type11 all TAIs", nas.ServiceAreaList{Partial: []nas.PartialServiceAreaList{
			{TypeOfList: 3, MCC: "001", MNC: "01"}}}, "2704" + "6000f110"},
		{"type00 non-allowed", nas.ServiceAreaList{Partial: []nas.PartialServiceAreaList{
			{NonAllowed: true, TypeOfList: 0, MCC: "001", MNC: "01", TACs: []uint32{5}}}}, "2707" + "8000f110" + "000005"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := nas.EncodeServiceAreaList(&tc.in)
			if err != nil {
				t.Fatal(err)
			}
			want, _ := hex.DecodeString(tc.want)
			if !bytes.Equal(got, want) {
				t.Fatalf("got %x want %x", got, want)
			}
			dec, err := nas.DecodeServiceAreaListValue(got[2:])
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(*dec, tc.in) {
				t.Fatalf("round trip: got %+v want %+v", *dec, tc.in)
			}
		})
	}
}

func TestServiceAreaList_Errors(t *testing.T) {
	many := make([]uint32, 17)
	for i := range many {
		many[i] = uint32(i)
	}
	p := func(na bool, typ byte, tacs ...uint32) nas.PartialServiceAreaList {
		return nas.PartialServiceAreaList{NonAllowed: na, TypeOfList: typ, MCC: "001", MNC: "01", TACs: tacs}
	}
	tests := []struct {
		name string
		in   *nas.ServiceAreaList
	}{
		{"nil", nil},
		{"empty", &nas.ServiceAreaList{}},
		{"mixed allowed types", &nas.ServiceAreaList{Partial: []nas.PartialServiceAreaList{p(false, 0, 1), p(true, 0, 2)}}},
		{"17 TACs", &nas.ServiceAreaList{Partial: []nas.PartialServiceAreaList{p(false, 0, many...)}}},
		{"16+1 across partials", &nas.ServiceAreaList{Partial: []nas.PartialServiceAreaList{p(false, 0, many[:16]...), p(false, 0, 1)}}},
		{"type11 non-allowed", &nas.ServiceAreaList{Partial: []nas.PartialServiceAreaList{p(true, 3)}}},
		{"non-consecutive in type01", &nas.ServiceAreaList{Partial: []nas.PartialServiceAreaList{p(false, 1, 1, 3)}}},
		{"bad PLMN", &nas.ServiceAreaList{Partial: []nas.PartialServiceAreaList{{TypeOfList: 0, MCC: "1", MNC: "01", TACs: []uint32{1}}}}},
		{"no TACs", &nas.ServiceAreaList{Partial: []nas.PartialServiceAreaList{p(false, 0)}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := nas.EncodeServiceAreaList(tc.in); err == nil {
				t.Fatal("expected error")
			}
		})
	}
	if _, err := nas.DecodeServiceAreaListValue([]byte{0x01, 0x00}); err == nil {
		t.Fatal("expected truncation error")
	}
}

func TestRegistrationAccept_ServiceAreaList(t *testing.T) {
	t3512 := byte(0x21)
	base := &nas.RegistrationAccept{RegistrationResult: 1, T3512Value: &t3512}
	legacy, err := nas.EncodeRegistrationAccept(base)
	if err != nil {
		t.Fatal(err)
	}
	// Golden: nil Service area list leaves the legacy bytes untouched.
	if hex.EncodeToString(legacy) != "01015e0121" {
		t.Fatalf("legacy bytes changed: %x", legacy)
	}
	sal := &nas.ServiceAreaList{Partial: []nas.PartialServiceAreaList{{TypeOfList: 3, MCC: "001", MNC: "01"}}}
	withSAL := *base
	withSAL.ServiceAreaList = sal
	got, err := nas.EncodeRegistrationAccept(&withSAL)
	if err != nil {
		t.Fatal(err)
	}
	// 0x27 sits before T3512 (0x5E).
	if hex.EncodeToString(got) != "0101"+"27046000f110"+"5e0121" {
		t.Fatalf("got %x", got)
	}
	dec, err := nas.DecodeRegistrationAccept(got)
	if err != nil || !reflect.DeepEqual(dec.ServiceAreaList, sal) {
		t.Fatalf("decode: %v %+v", err, dec.ServiceAreaList)
	}
	bad := *base
	bad.ServiceAreaList = &nas.ServiceAreaList{}
	if _, err := nas.EncodeRegistrationAccept(&bad); err == nil {
		t.Fatal("expected error")
	}
}

func TestConfigurationUpdateCommand_ServiceAreaList(t *testing.T) {
	sal := &nas.ServiceAreaList{Partial: []nas.PartialServiceAreaList{{TypeOfList: 3, MCC: "001", MNC: "01"}}}
	got, err := nas.EncodeConfigurationUpdateCommand(&nas.ConfigurationUpdateCommand{ServiceAreaList: sal})
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != "27046000f110" {
		t.Fatalf("got %x", got)
	}
	dec, err := nas.DecodeConfigurationUpdateCommand(got)
	if err != nil || !reflect.DeepEqual(dec.ServiceAreaList, sal) {
		t.Fatalf("decode: %v", err)
	}
}
