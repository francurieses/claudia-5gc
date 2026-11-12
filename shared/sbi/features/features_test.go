package features

import (
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/capability"
)

func mustParse(t testing.TB, s string) Set {
	t.Helper()
	v, err := Parse(s)
	if err != nil {
		t.Fatalf("Parse(%q): %v", s, err)
	}
	return v
}

func TestParse(t *testing.T) {
	tests := []struct {
		in   string
		want []int
		str  string
	}{
		{"", nil, "0"},
		{"0", nil, "0"},
		{"000", nil, "0"},
		{"1", []int{1}, "1"},
		{"8", []int{4}, "8"},
		{"F", []int{1, 2, 3, 4}, "f"},
		{"f", []int{1, 2, 3, 4}, "f"},
		{"10", []int{5}, "10"},
		{"0010", []int{5}, "10"},
		{"a1", []int{1, 6, 8}, "a1"},
		{"A1", []int{1, 6, 8}, "a1"},
		{"100000000000000000", []int{69}, "100000000000000000"},
	}
	for _, tc := range tests {
		s, err := Parse(tc.in)
		if err != nil {
			t.Fatalf("Parse(%q): %v", tc.in, err)
		}
		if got := s.Len(); got != len(tc.want) {
			t.Errorf("Parse(%q).Len()=%d want %d", tc.in, got, len(tc.want))
		}
		for _, n := range tc.want {
			if !s.Has(n) {
				t.Errorf("Parse(%q) missing feature %d", tc.in, n)
			}
		}
		if got := s.String(); got != tc.str {
			t.Errorf("Parse(%q).String()=%q want %q", tc.in, got, tc.str)
		}
	}
}

func TestParseInvalid(t *testing.T) {
	for _, in := range []string{"g", "0x1", " 1", "1 ", "é", "12-3", strings.Repeat("1", MaxHexChars+1)} {
		_, err := Parse(in)
		if err == nil || !errors.Is(err, ErrInvalid) {
			t.Errorf("Parse(%q) err=%v, want ErrInvalid", in, err)
		}
	}
	if _, err := Parse(strings.Repeat("f", MaxHexChars)); err != nil {
		t.Errorf("max-length input rejected: %v", err)
	}
}

func TestParseStringRoundTrip(t *testing.T) {
	for _, in := range []string{"", "1", "ff", "DEADBEEF", "0123456789abcdef0123456789abcdef1"} {
		s := mustParse(t, in)
		if r := mustParse(t, s.String()); !r.Equal(s) {
			t.Errorf("round trip %q: %q != %q", in, r, s)
		}
	}
}

func TestHasAndWith(t *testing.T) {
	var s Set
	for _, n := range []int{0, -1, MaxFeatures + 1} {
		if s.With(n).Has(n) || !s.With(n).IsEmpty() {
			t.Errorf("out-of-range %d must be ignored", n)
		}
		if s.Has(n) {
			t.Errorf("Has(%d) true", n)
		}
	}
	s2 := s.With(1).With(65).With(MaxFeatures)
	for _, n := range []int{1, 65, MaxFeatures} {
		if !s2.Has(n) {
			t.Errorf("missing %d", n)
		}
	}
	if s2.Has(2) || s2.Len() != 3 || !s.IsEmpty() {
		t.Errorf("unexpected state %v / %v", s2, s)
	}
	if got := mustParse(t, s2.String()); !got.Equal(s2) {
		t.Errorf("round trip failed for %q", s2)
	}
}

func TestIntersect(t *testing.T) {
	tests := []struct{ a, b, want string }{
		{"", "ff", "0"},
		{"f", "5", "5"},
		{"0f", "5", "5"},
		{"100000000000000001", "1", "1"},
		{"100000000000000001", "100000000000000003", "100000000000000001"},
		{"10", "01", "0"},
	}
	for _, tc := range tests {
		a, b := mustParse(t, tc.a), mustParse(t, tc.b)
		if got := Intersect(a, b).String(); got != tc.want {
			t.Errorf("Intersect(%q,%q)=%q want %q", tc.a, tc.b, got, tc.want)
		}
		if got := b.Intersect(a).String(); got != tc.want {
			t.Errorf("commuted %q,%q=%q want %q", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestCatalogValidation(t *testing.T) {
	ok := Entry{Number: 1, Name: "A", Release: capability.Rel15}
	bad := map[string][]Entry{
		"zero number": {{Number: 0, Name: "A", Release: capability.Rel15}},
		"too big":     {{Number: MaxFeatures + 1, Name: "A", Release: capability.Rel15}},
		"no name":     {{Number: 1, Release: capability.Rel15}},
		"no release":  {{Number: 1, Name: "A"}},
		"dup number":  {ok, {Number: 1, Name: "B", Release: capability.Rel15}},
		"dup id":      {{Number: 1, Name: "A", Release: capability.Rel19, FeatureID: "SF-X"}, {Number: 2, Name: "B", Release: capability.Rel19, FeatureID: "SF-X"}},
	}
	for name, es := range bad {
		if _, err := NewCatalog(es...); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	c, err := NewCatalog(Entry{Number: 3, Name: "C", Release: capability.Rel15}, ok)
	if err != nil {
		t.Fatal(err)
	}
	if es := c.Entries(); len(es) != 2 || es[0].Number != 1 {
		t.Errorf("entries not sorted: %v", es)
	}
	if e, found := c.Lookup(3); !found || e.Name != "C" {
		t.Errorf("Lookup(3)=%v,%v", e, found)
	}
	var nilCat *Catalog
	if nilCat.Entries() != nil || !nilCat.Supported(nil).IsEmpty() {
		t.Error("nil catalog must be empty")
	}
}

var registerOnce sync.Once

func testCatalog() *Catalog {
	registerOnce.Do(func() {
		capability.MustRegister(capability.Feature{ID: "SF-NEW", Title: "x", Release: capability.Rel19, Visibility: "public"})
		capability.MustRegister(capability.Feature{ID: "SF-OFF", Title: "y", Release: capability.Rel17, Visibility: "public"})
	})
	return MustCatalog(
		Entry{Number: 1, Name: "Base", Release: capability.Rel15, Implemented: true},
		Entry{Number: 2, Name: "R17", Release: capability.Rel17, Implemented: true},
		Entry{Number: 3, Name: "R19", Release: capability.Rel19, FeatureID: "SF-NEW", Implemented: true},
		Entry{Number: 4, Name: "Off", Release: capability.Rel17, FeatureID: "SF-OFF", Implemented: true},
	)
}

func profile(t *testing.T, name string, feats map[string]bool) *capability.Profile {
	t.Helper()
	p, err := capability.NewProfile(capability.ReleaseConfig{Profile: name, Features: feats}, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSpecLiteral(t *testing.T) {
	if SpecLiteral(nil) || SpecLiteral(profile(t, "rel17", nil)) || !SpecLiteral(profile(t, "rel19", nil)) {
		t.Error("SpecLiteral must be true only for the rel19 profile")
	}
}

func TestNegotiateRequest(t *testing.T) {
	cat := testCatalog()
	on := map[string]bool{"SF-NEW": true}
	tests := []struct {
		name string
		p    *capability.Profile
		want string
	}{
		{"rel17 omits", profile(t, "rel17", nil), ""},
		{"rel17 with rel19 feature enabled omits", profile(t, "rel17", on), ""},
		{"rel19 feature off", profile(t, "rel19", nil), "3"},
		{"rel19 feature on", profile(t, "rel19", on), "7"},
		{"nil profile omits", nil, ""},
	}
	for _, tc := range tests {
		if got := Request(cat, tc.p); got != tc.want {
			t.Errorf("%s: Request=%q want %q", tc.name, got, tc.want)
		}
	}
	if got := Request(nil, profile(t, "rel19", on)); got != "0" {
		t.Errorf("rel19 nil catalog: got %q want \"0\"", got)
	}
	empty := MustCatalog(Entry{Number: 1, Name: "X", Release: capability.Rel17})
	if got := Request(empty, profile(t, "rel19", nil)); got != "0" {
		t.Errorf("rel19 unimplemented catalog: got %q want \"0\"", got)
	}
}

func TestSupportedSkipsUnimplemented(t *testing.T) {
	c := MustCatalog(
		Entry{Number: 1, Name: "A", Release: capability.Rel17, Implemented: true},
		Entry{Number: 2, Name: "B", Release: capability.Rel17},
		Entry{Number: 3, Name: "C", Release: capability.Rel18, Implemented: true},
	)
	if got := c.Supported(profile(t, "rel19", nil)).String(); got != "5" {
		t.Errorf("rel19 Supported=%q want 5", got)
	}
	if got := c.Supported(profile(t, "rel17", nil)).String(); got != "1" {
		t.Errorf("rel17 Supported=%q want 1", got)
	}
	if got := c.Supported(nil).String(); got != "1" {
		t.Errorf("nil Supported=%q want 1 (rel17 baseline)", got)
	}
}

func TestNegotiateAnswer(t *testing.T) {
	cat := testCatalog()
	p19 := profile(t, "rel19", map[string]bool{"SF-NEW": true})
	p17 := profile(t, "rel17", nil)
	tests := []struct {
		name, peer, want string
		p                *capability.Profile
	}{
		{"rel19 intersection", "5", "5", p19},
		{"rel19 peer superset", "ff", "7", p19},
		{"rel19 peer subset longer string", "0001", "1", p19},
		{"rel19 empty peer", "", "0", p19},
		{"rel19 invalid peer", "zz", "0", p19},
		{"rel19 overlong peer", strings.Repeat("f", MaxHexChars+1), "7", p19},
		{"rel19 zero peer", "0", "0", p19},
		{"rel17 empty peer omits", "", "", p17},
		{"rel17 zero peer", "0", "0", p17},
		{"rel17 f peer", "f", "3", p17},
		{"rel17 invalid peer", "zz", "0", p17},
		{"nil profile empty peer omits", "", "", nil},
		{"nil profile ff (rel17 baseline)", "ff", "3", nil},
	}
	for _, tc := range tests {
		got, set := Answer(cat, tc.p, tc.peer)
		wantSet := tc.want
		if wantSet == "" {
			wantSet = "0"
		}
		if got != tc.want || set.String() != wantSet {
			t.Errorf("%s: Answer=%q/%q want %q", tc.name, got, set, tc.want)
		}
	}
}

func TestAccept(t *testing.T) {
	tests := []struct {
		name, offer, answer, want string
		wantErr                   bool
	}{
		{"intersection", "7", "5", "5", false},
		{"R11 answer bits never offered ignored", "3", "f", "3", false},
		{"R12 absent answer", "7", "", "0", false},
		{"R12 zero answer", "7", "0", "0", false},
		{"R13 non-hex answer", "7", "zz", "0", true},
		{"R14 nothing offered", "", "f", "0", false},
		{"R14 zero offered", "0", "f", "0", false},
		{"overlong valid answer", "5", "1" + strings.Repeat("0", MaxHexChars) + "f", "5", false},
		{"overlong invalid answer", "5", "g" + strings.Repeat("0", MaxHexChars), "0", true},
		{"R14 beats invalid answer", "", "zz", "0", false},
	}
	for _, tc := range tests {
		got, err := Accept(tc.offer, tc.answer)
		if got.String() != tc.want {
			t.Errorf("%s: Accept=%q want %q", tc.name, got, tc.want)
		}
		if (err != nil) != tc.wantErr || (err != nil && !errors.Is(err, ErrInvalid)) {
			t.Errorf("%s: err=%v wantErr=%v", tc.name, err, tc.wantErr)
		}
	}
	if _, err := Accept("zz", "1"); err == nil || !errors.Is(err, ErrInvalid) {
		t.Errorf("invalid offer: err=%v", err)
	}
}

func TestLogAttrs(t *testing.T) {
	local := Set{}.With(1).With(2)
	got := LogAttrs(local, "", false, Set{})
	want := []any{"features_local", "3", "features_peer", "absent", "features_negotiated", "0"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("absent: %v want %v", got, want)
	}
	got = LogAttrs(local, "Ff", true, Set{}.With(1))
	want = []any{"features_local", "3", "features_peer", "Ff", "features_negotiated", "1"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("present: %v want %v", got, want)
	}
	if got := LogAttrs(local, "", true, Set{}); got[3] != "" {
		t.Errorf("present empty peer must be logged as received, got %q", got[3])
	}
	if SpecRef != "TS 29.500 §6.6.2" || SpecRefInvalid != "TS 29.500 §5.2.7.2" || ProcedureName != "FeatureNegotiation" {
		t.Error("log constants changed")
	}
}

// TestNegotiateSVSpec29500 pins the TS 29.500 §6.6.2 / TS 29.571 §5.2.2
// rules confirmed against the spec text (Rel-17 V17.16.0, Rel-19 V19.7.1).
func TestNegotiateSVSpec29500(t *testing.T) {
	cat := testCatalog()
	p19 := profile(t, "rel19", map[string]bool{"SF-NEW": true})
	tests := []struct {
		name, peer, want string
	}{
		// Over-long but schema-valid: high characters ignored, low ones honoured.
		{"overlong high bits", "1" + strings.Repeat("0", MaxHexChars) + "5", "5"},
		{"overlong leading zeros", strings.Repeat("0", 4*MaxHexChars) + "3", "3"},
		// Non-hex anywhere, even outside the honoured window: fail closed.
		{"overlong invalid high char", "g" + strings.Repeat("0", MaxHexChars) + "7", "0"},
		// Unknown bits (feature 4 and above, not in the catalog) are ignored.
		{"unknown bits ignored", "f8", "0"},
		{"uppercase peer", "F", "7"},
	}
	for _, tc := range tests {
		got, set := Answer(cat, p19, tc.peer)
		if got != tc.want || set.String() != tc.want {
			t.Errorf("%s: Answer=%q/%q want %q", tc.name, got, set, tc.want)
		}
	}
	// Under rel19 the answer is always present: an empty intersection is "0".
	if got, _ := Answer(nil, p19, ""); got != "0" {
		t.Errorf("empty negotiation answered %q, want \"0\"", got)
	}
}

func TestParseSVValidate(t *testing.T) {
	for _, ok := range []string{"", "0", "aF09", strings.Repeat("f", MaxHexChars+1)} {
		if err := Validate(ok); err != nil {
			t.Errorf("Validate(%q)=%v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"g", "0x1", " 1", "1 ", "é", "12-3"} {
		if err := Validate(bad); err == nil || !errors.Is(err, ErrInvalid) {
			t.Errorf("Validate(%q)=%v, want ErrInvalid", bad, err)
		}
	}
}

func TestNegotiatePeerNF(t *testing.T) {
	cat := testCatalog()
	p19 := profile(t, "rel19", map[string]bool{"SF-NEW": true})
	_, neg := Answer(cat, p19, "ff")
	peer := PeerNF(cat, neg)
	newF, _ := capability.Lookup("SF-NEW")
	offF, _ := capability.Lookup("SF-OFF")
	if !peer.Allows(newF) {
		t.Error("SF-NEW should be negotiated")
	}
	if peer.Allows(offF) {
		t.Error("SF-OFF not offered, must not be negotiated")
	}
	if !p19.Gate("SF-NEW", peer) {
		t.Error("Gate should pass with negotiated peer")
	}
	_, none := Answer(cat, p19, "1")
	if p19.Gate("SF-NEW", PeerNF(cat, none)) {
		t.Error("Gate must fail when the peer did not offer the bit")
	}
	if PeerNF(nil, neg).Allows(newF) {
		t.Error("nil catalog negotiates nothing")
	}
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{"", "0", "1", "f", "A1", "00ff", "g", strings.Repeat("f", MaxHexChars), strings.Repeat("1", MaxHexChars+1)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		s, err := Parse(in)
		if err != nil {
			return
		}
		out := s.String()
		r, err := Parse(out)
		if err != nil || !r.Equal(s) || r.String() != out {
			t.Fatalf("round trip %q -> %q -> %v (%v)", in, out, r, err)
		}
		if !Intersect(s, s).Equal(s) {
			t.Fatalf("self-intersection differs for %q", in)
		}
	})
}
