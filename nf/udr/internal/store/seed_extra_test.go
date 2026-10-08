package store

import (
	"reflect"
	"testing"
)

func TestParseSeedSUPIs(t *testing.T) {
	tests := []struct {
		name        string
		raw         string
		wantValid   []string
		wantInvalid []string
	}{
		{"empty", "", nil, nil},
		{"single", "imsi-001010000000101", []string{"imsi-001010000000101"}, nil},
		{"trim and dedupe", " imsi-001010000000101 , imsi-001010000000101,imsi-001010000000102 ",
			[]string{"imsi-001010000000101", "imsi-001010000000102"}, nil},
		{"invalid kept apart", "imsi-1,imsi-001010000000101,foo",
			[]string{"imsi-001010000000101"}, []string{"imsi-1", "foo"}},
		{"only separators", " , ,", nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, invalid := ParseSeedSUPIs(tt.raw)
			if !reflect.DeepEqual(valid, tt.wantValid) || !reflect.DeepEqual(invalid, tt.wantInvalid) {
				t.Errorf("ParseSeedSUPIs(%q) = %v, %v; want %v, %v", tt.raw, valid, invalid, tt.wantValid, tt.wantInvalid)
			}
		})
	}
}

func TestSliceProfileForSUPI(t *testing.T) {
	in := SNSSAISubscribed{SST: 1, SD: "000001"}
	profiles := [][]SNSSAISubscribed{
		{in},
		{in, {SST: 1, SD: "000002"}},
		{in, {SST: 2, SD: "000001"}},
		{in, {SST: 3, SD: "000001"}},
	}
	tests := []struct {
		supi string
		want int
	}{
		{"imsi-001010000000101", 0},
		{"imsi-001010000000201", 0},
		{"imsi-001010000000202", 1},
		{"imsi-001010000000203", 2},
		{"imsi-001010000000204", 3},
		{"imsi-001010000000301", 0},
		{"imsi-001010000000003", 2},
		{"imsi-001010000000000", 0},
		{"garbage", 0},
	}
	for _, tc := range tests {
		got := SliceProfileForSUPI(tc.supi, profiles)
		if !reflect.DeepEqual(got, profiles[tc.want]) {
			t.Errorf("%s: got %v want profile %d", tc.supi, got, tc.want)
		}
	}
	if SliceProfileForSUPI("imsi-001010000000001", nil) != nil {
		t.Error("empty profiles must return nil")
	}
}
