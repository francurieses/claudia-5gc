package capability

import (
	"context"
	"testing"

	"gopkg.in/yaml.v3"
)

func regT(t *testing.T, id string, rel Release) {
	t.Helper()
	if err := Register(Feature{ID: id, Title: id, Release: rel, Visibility: "public"}); err != nil {
		t.Fatal(err)
	}
}

func mustProfile(t *testing.T, name string, feats map[string]bool) *Profile {
	t.Helper()
	p, err := NewProfile(ReleaseConfig{Profile: name, Features: feats}, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestGate(t *testing.T) {
	regT(t, "G-R19", Rel19)
	regT(t, "G-R17", Rel17)
	regT(t, "G-OFF", Rel19)
	yes := func(Feature) bool { return true }
	no := func(Feature) bool { return false }
	all := map[string]bool{"G-R19": true, "G-R17": true}
	tests := []struct {
		name  string
		prof  string
		feats map[string]bool
		id    string
		peers []PeerCap
		want  bool
	}{
		{"disabled", ProfileRel19, all, "G-OFF", nil, false},
		{"unregistered", ProfileRel19, map[string]bool{}, "G-NOPE", nil, false},
		{"release above profile", ProfileRel17, all, "G-R19", nil, false},
		{"rel17 feature in rel17 profile", ProfileRel17, all, "G-R17", nil, true},
		{"enabled rel19 no peers", ProfileRel19, all, "G-R19", nil, true},
		{"UE pass", ProfileRel19, all, "G-R19", []PeerCap{PeerUE{yes}}, true},
		{"UE fail", ProfileRel19, all, "G-R19", []PeerCap{PeerUE{no}}, false},
		{"UE nil func", ProfileRel19, all, "G-R19", []PeerCap{PeerUE{}}, false},
		{"gNB rel19 pass", ProfileRel19, all, "G-R19", []PeerCap{PeerRAN{Rel19}}, true},
		{"gNB rel18 fail", ProfileRel19, all, "G-R19", []PeerCap{PeerRAN{Rel18}}, false},
		{"unknown gNB is rel17: rel19 feature", ProfileRel19, all, "G-R19", []PeerCap{PeerRAN{}}, false},
		{"unknown gNB is rel17: rel17 feature", ProfileRel19, all, "G-R17", []PeerCap{PeerRAN{}}, true},
		{"NF pass", ProfileRel19, all, "G-R19", []PeerCap{PeerNF{yes}}, true},
		{"NF fail", ProfileRel19, all, "G-R19", []PeerCap{PeerNF{no}}, false},
		{"multiple one failing", ProfileRel19, all, "G-R19", []PeerCap{PeerUE{yes}, PeerRAN{Rel19}, PeerNF{no}}, false},
		{"multiple all pass", ProfileRel19, all, "G-R19", []PeerCap{PeerUE{yes}, PeerRAN{Rel19}, PeerNF{yes}}, true},
		{"nil peer fails closed", ProfileRel19, all, "G-R19", []PeerCap{nil}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := mustProfile(t, tt.prof, tt.feats)
			if got := p.Gate(tt.id, tt.peers...); got != tt.want {
				t.Fatalf("Gate = %v, want %v", got, tt.want)
			}
			ctx := WithProfile(context.Background(), p)
			if got := Gate(ctx, tt.id, tt.peers...); got != tt.want {
				t.Fatalf("ctx Gate = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGateCtxVersusDefault(t *testing.T) {
	regT(t, "GC-1", Rel19)
	on := mustProfile(t, ProfileRel19, map[string]bool{"GC-1": true})
	off := mustProfile(t, ProfileRel19, nil)
	t.Cleanup(func() { SetDefault(nil) })

	SetDefault(nil)
	if Gate(context.Background(), "GC-1") {
		t.Fatal("no profile must gate off")
	}
	if Gate(nil, "GC-1") { //nolint:staticcheck // nil ctx tolerated
		t.Fatal("nil ctx, no default must gate off")
	}
	SetDefault(on)
	if !Gate(context.Background(), "GC-1") {
		t.Fatal("default profile not used")
	}
	if Gate(WithProfile(context.Background(), off), "GC-1") {
		t.Fatal("ctx profile must override default")
	}
	if !Gate(WithProfile(context.Background(), nil), "GC-1") {
		t.Fatal("nil ctx profile must fall back to default")
	}
}

func TestProfileDefaultRel19(t *testing.T) {
	p, err := NewProfile(ReleaseConfig{}, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if p.Name() != ProfileRel19 || p.Release() != Rel19 {
		t.Fatalf("got %s/%v", p.Name(), p.Release())
	}
	var nilP *Profile
	if nilP.Enabled("x") || nilP.Gate("x") {
		t.Fatal("nil profile must be off")
	}
}

func TestProfileYAML(t *testing.T) {
	regT(t, "PY-1", Rel19)
	regT(t, "PY-2", Rel19)
	var doc struct {
		Release ReleaseConfig `yaml:"release"`
	}
	src := "release:\n  profile: rel19\n  features:\n    PY-1: true\n    PY-2: false\n"
	if err := yaml.Unmarshal([]byte(src), &doc); err != nil {
		t.Fatal(err)
	}
	p, err := NewProfile(doc.Release, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if p.Release() != Rel19 || !p.Enabled("PY-1") || p.Enabled("PY-2") {
		t.Fatalf("profile = %+v", p)
	}
}

func TestProfileEnvOverride(t *testing.T) {
	env := func(k string) string {
		if k == EnvReleaseProfile {
			return "rel19"
		}
		return ""
	}
	p, err := NewProfile(ReleaseConfig{Profile: "rel17"}, env)
	if err != nil || p.Release() != Rel19 {
		t.Fatalf("env override: %v %v", p, err)
	}
	t.Setenv(EnvReleaseProfile, "rel17")
	p, err = NewProfile(ReleaseConfig{Profile: "rel19"}, nil)
	if err != nil || p.Release() != Rel17 {
		t.Fatalf("os env override: %v %v", p, err)
	}
	if _, err := NewProfile(ReleaseConfig{}, func(string) string { return "rel99" }); err == nil {
		t.Fatal("invalid env profile accepted")
	}
}

func TestProfileInvalid(t *testing.T) {
	none := func(string) string { return "" }
	if _, err := NewProfile(ReleaseConfig{Profile: "rel18"}, none); err == nil {
		t.Fatal("invalid profile name accepted")
	}
	if _, err := NewProfile(ReleaseConfig{Features: map[string]bool{"PI-UNKNOWN": true}}, none); err == nil {
		t.Fatal("unknown feature ID accepted")
	}
	if _, err := NewProfile(ReleaseConfig{Features: map[string]bool{"PI-UNKNOWN": false}}, none); err == nil {
		t.Fatal("unknown feature ID (false) accepted")
	}
}
