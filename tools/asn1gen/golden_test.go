package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/francurieses/claudia-5gc/tools/asn1gen/internal/gogen"
)

// r15Dir holds the Rel-15 NGAP ASN.1 (TS 38.413 V15.13.0), extracted locally by
// scripts/extract-asn1.sh. It is git-ignored (3GPP text is never committed), so the
// golden tests skip when it is absent, e.g. in CI.
const r15Dir = "../../specs/asn1/ngap/r15"

// fieldShape is one struct field as seen by the comparison.
type fieldShape struct{ Name, Type, Tag string }

// shapes is the comparable view of a generated or reference package.
type shapes struct {
	structs map[string][]fieldShape
	consts  map[string]string
}

// goldenRoots are the types the plan step (REL19-4.2) requires to match free5gc v1.1.3,
// together with everything they reference transitively.
var goldenRoots = []string{
	"NGSetupRequest",
	"InitialContextSetupRequest",
	"QosFlowLevelQosParameters",
	"PDUSessionResourceSetupRequestTransfer",
}

// free5gcSnapshot is the frozen reference: the struct and constant shapes of
// github.com/free5gc/ngap v1.1.3 ngapType (Apache-2.0, https://github.com/free5gc/ngap),
// reduced to the types reachable from goldenRoots plus all ProtocolIEID*/ProcedureCode*
// constants. Produced once by parseShapes over the v1.1.3 sources, so the test no longer
// needs the free5gc module. The snapshot is FROZEN: v1.1.3 is a fixed upstream release, so it
// is never regenerated. If it ever must be, check out commit 4e92426 (the last one that still
// required github.com/free5gc/ngap v1.1.3), json-marshal the parseShapes output for the module's
// ngapType sources, and prune it to the goldenRoots closure.
const free5gcSnapshot = "testdata/free5gc_v1.1.3_ngaptype_shapes.json"

func loadSnapshot(t *testing.T) shapes {
	t.Helper()
	b, err := os.ReadFile(free5gcSnapshot)
	if err != nil {
		t.Fatalf("read %s: %v", free5gcSnapshot, err)
	}
	var in struct {
		Structs map[string][]fieldShape `json:"structs"`
		Consts  map[string]string       `json:"consts"`
	}
	if err := json.Unmarshal(b, &in); err != nil {
		t.Fatalf("parse %s: %v", free5gcSnapshot, err)
	}
	if len(in.Structs) == 0 || len(in.Consts) == 0 {
		t.Fatalf("%s: empty snapshot (%d structs, %d consts)", free5gcSnapshot, len(in.Structs), len(in.Consts))
	}
	return shapes{structs: in.Structs, consts: in.Consts}
}

// shapeDelta is an explicit, justified difference between the generator and free5gc
// v1.1.3 for one struct field ("Type.Field"). The test requires the observed
// difference to equal the entry exactly, so a stale or too-broad entry fails.
type shapeDelta struct {
	Ours, Free5GC string // type+tag text, as "<type> `<tag>`"
	Why           string
}

// goldenDeltas lists every accepted field-level difference against free5gc v1.1.3.
var goldenDeltas = map[string]shapeDelta{
	"MobilityRestrictionListExtIEsExtensionValue.LastEUTRANPLMNIdentity": {
		Ours:    "*ngapType.PLMNIdentity `referenceFieldValue:150`",
		Free5GC: "*ngapType.PLMNIdentity ``",
		Why:     "same defect as below: free5gc v1.1.3 drops referenceFieldValue (id 150) on this extension member.",
	},
	"SecurityIndicationExtIEsExtensionValue.MaximumIntegrityProtectedDataRateDL": {
		Ours:    "*ngapType.MaximumIntegrityProtectedDataRate `referenceFieldValue:151`",
		Free5GC: "*ngapType.MaximumIntegrityProtectedDataRate ``",
		Why: "free5gc v1.1.3 omits referenceFieldValue for this extension member (id 151), so aper " +
			"cannot select it; the ASN.1 object `{ID id-MaximumIntegrityProtectedDataRate-DL ...}` " +
			"carries the id, which the generator always emits.",
	},
}

// typeDelta is an accepted difference in the member set of one value struct: free5gc
// v1.1.3 and TS 38.413 V15.13.0 are different revisions (free5gc mixes late Rel-15 and
// early Rel-16 additions). Members common to both are still compared exactly; Present
// constants are compared by name only for these owners (iota values shift).
type typeDelta struct {
	OnlyGenerated []string
	OnlyFree5GC   []string
	Why           string
}

// goldenTypeDeltas is keyed by the value struct name (XValue / XExtensionValue).
var goldenTypeDeltas = map[string]typeDelta{
	"InitialContextSetupRequestIEsValue": {
		OnlyGenerated: []string{"CoreNetworkAssistanceInformationForInactive", "LocationReportingRequestType", "CNAssistedRANTuning"},
		OnlyFree5GC:   []string{"CoreNetworkAssistanceInformation"},
		Why: "V15.13.0 renamed IE id 18 to CoreNetworkAssistanceInformationForInactive and added " +
			"id-LocationReportingRequestType and id-CNAssistedRANTuning (165) to InitialContextSetupRequest; " +
			"free5gc v1.1.3 predates those changes.",
	},
	"PDUSessionResourceSetupRequestTransferIEsValue": {
		OnlyGenerated: []string{"CommonNetworkInstance"},
		Why:           "id-CommonNetworkInstance (166) is a late Rel-15 addition absent from free5gc v1.1.3.",
	},
	"MobilityRestrictionListExtIEsExtensionValue": {
		OnlyGenerated: []string{"CNTypeRestrictionsForServing", "CNTypeRestrictionsForEquivalent"},
		Why:           "late Rel-15 extension IEs of MobilityRestrictionList absent from free5gc v1.1.3.",
	},
	"BroadcastPLMNItemExtIEsExtensionValue": {
		OnlyFree5GC: []string{"NPNSupport", "ExtendedTAISliceSupportList"},
		Why:         "Rel-16 extension IEs of BroadcastPLMNItem present in free5gc v1.1.3 (it tracks part of Rel-16) but not in Rel-15 V15.13.0.",
	},
}

// goldenIDDeltas lists ProtocolIEID*/ProcedureCode* constants of free5gc v1.1.3 that the
// Rel-15 V15.13.0 ASN.1 does not define under that name.
var goldenIDDeltas = map[string]string{
	"ProtocolIEIDCoreNetworkAssistanceInformation": "renamed id-CoreNetworkAssistanceInformationForInactive (18) in V15.13.0",
	"ProtocolIEIDExtendedSliceSupportList":         "Rel-16 NPN / slice-support IE, not in V15.13.0",
	"ProtocolIEIDExtendedTAISliceSupportList":      "Rel-16 NPN / slice-support IE, not in V15.13.0",
	"ProtocolIEIDNID":                              "Rel-16 NPN / slice-support IE, not in V15.13.0",
	"ProtocolIEIDNPNAccessInformation":             "Rel-16 NPN / slice-support IE, not in V15.13.0",
	"ProtocolIEIDNPNMobilityInformation":           "Rel-16 NPN / slice-support IE, not in V15.13.0",
	"ProtocolIEIDNPNPagingAssistanceInformation":   "Rel-16 NPN / slice-support IE, not in V15.13.0",
	"ProtocolIEIDNPNSupport":                       "Rel-16 NPN / slice-support IE, not in V15.13.0",
	"ProtocolIEIDGlobalTNGFID":                     "Rel-16 non-3GPP access (TNGF/TWIF/W-AGF) IE, not in V15.13.0",
	"ProtocolIEIDGlobalTWIFID":                     "Rel-16 non-3GPP access (TNGF/TWIF/W-AGF) IE, not in V15.13.0",
	"ProtocolIEIDGlobalWAGFID":                     "Rel-16 non-3GPP access (TNGF/TWIF/W-AGF) IE, not in V15.13.0",
	"ProtocolIEIDUserLocationInformationTNGF":      "Rel-16 non-3GPP access (TNGF/TWIF/W-AGF) IE, not in V15.13.0",
	"ProtocolIEIDUserLocationInformationTWIF":      "Rel-16 non-3GPP access (TNGF/TWIF/W-AGF) IE, not in V15.13.0",
	"ProtocolIEIDUserLocationInformationWAGF":      "Rel-16 non-3GPP access (TNGF/TWIF/W-AGF) IE, not in V15.13.0",
}

// goldenFree5GCOnly lists types that exist in free5gc v1.1.3 but not in V15.13.0 (Rel-16
// additions, or types renamed in later Rel-15 revisions), with the reason.
var goldenFree5GCOnly = map[string]string{
	"CoreNetworkAssistanceInformation": "renamed CoreNetworkAssistanceInformationForInactive in V15.13.0",
	"ExtendedSliceSupportList":         "Rel-16 type (NPN / extended TAI slice support), not in V15.13.0",
	"NPNSupport":                       "Rel-16 type, not in V15.13.0",
	"GlobalRANNodeIDExtIEs":            "Rel-16 extension IEs of GlobalRANNodeID (TNGF/TWIF/W-AGF), not in V15.13.0",
}

// goldenStructDeltaWhy explains the accepted type-level differences for the exact type
// names in goldenStructDeltas (free5gc v1.1.3 ProtocolIESingleContainer* extension types).
const goldenStructDeltaWhy = //nolint:unused // documentation of the allowlist below
"free5gc emits `struct{}` for the choice-Extensions alternative " +
	"(an open-type declaration it never decodes). The generator emits the real " +
	"ProtocolIE-Field (id, criticality, open-type value) of TS 38.413 clause 9.4.5 so " +
	"future extension alternatives decode. Type names are identical."

// goldenStructDeltas is the exact-name allowlist of accepted type-level differences.
var goldenStructDeltas = map[string]bool{
	"ProtocolIESingleContainerAMFPagingTargetExtIEs":                true,
	"ProtocolIESingleContainerBroadcastCancelledAreaListExtIEs":     true,
	"ProtocolIESingleContainerBroadcastCompletedAreaListExtIEs":     true,
	"ProtocolIESingleContainerCPTransportLayerInformationExtIEs":    true,
	"ProtocolIESingleContainerCauseExtIEs":                          true,
	"ProtocolIESingleContainerCellIDListForRestartExtIEs":           true,
	"ProtocolIESingleContainerDRBStatusDLExtIEs":                    true,
	"ProtocolIESingleContainerDRBStatusULExtIEs":                    true,
	"ProtocolIESingleContainerGNBIDExtIEs":                          true,
	"ProtocolIESingleContainerGlobalRANNodeIDExtIEs":                true,
	"ProtocolIESingleContainerLastVisitedCellInformationExtIEs":     true,
	"ProtocolIESingleContainerN3IWFIDExtIEs":                        true,
	"ProtocolIESingleContainerNGRANCGIExtIEs":                       true,
	"ProtocolIESingleContainerNPNAccessInformationExtIEs":           true,
	"ProtocolIESingleContainerNPNMobilityInformationExtIEs":         true,
	"ProtocolIESingleContainerNPNPagingAssistanceInformationExtIEs": true,
	"ProtocolIESingleContainerNPNSupportExtIEs":                     true,
	"ProtocolIESingleContainerNgENBIDExtIEs":                        true,
	"ProtocolIESingleContainerOverloadResponseExtIEs":               true,
	"ProtocolIESingleContainerPWSFailedCellIDListExtIEs":            true,
	"ProtocolIESingleContainerQosCharacteristicsExtIEs":             true,
	"ProtocolIESingleContainerResetTypeExtIEs":                      true,
	"ProtocolIESingleContainerSONInformationExtIEs":                 true,
	"ProtocolIESingleContainerTNGFIDExtIEs":                         true,
	"ProtocolIESingleContainerTWIFIDExtIEs":                         true,
	"ProtocolIESingleContainerTargetIDExtIEs":                       true,
	"ProtocolIESingleContainerUEIdentityIndexValueExtIEs":           true,
	"ProtocolIESingleContainerUENGAPIDsExtIEs":                      true,
	"ProtocolIESingleContainerUEPagingIdentityExtIEs":               true,
	"ProtocolIESingleContainerUPTransportLayerInformationExtIEs":    true,
	"ProtocolIESingleContainerUserLocationInformationExtIEs":        true,
	"ProtocolIESingleContainerUserLocationInformationWAGFExtIEs":    true,
	"ProtocolIESingleContainerWAGFIDExtIEs":                         true,
	"ProtocolIESingleContainerWarningAreaListExtIEs":                true,
}

func TestGoldenAgainstFree5GC(t *testing.T) {
	if _, err := os.Stat(r15Dir); err != nil {
		t.Skipf("Rel-15 ASN.1 not found at %s (git-ignored, CI has no 3GPP text; run scripts/extract-asn1.sh <38413-fd0.zip> specs/asn1/ngap/r15). CI regression guard is step 4.3: committed generated output plus go generate reproducibility: %v", r15Dir, err)
	}
	files, err := Generate(r15Dir, gogen.Config{Package: "ngapType", Header: "Code generated by tools/asn1gen test. DO NOT EDIT.", AperImport: "github.com/free5gc/aper"})
	if err != nil {
		t.Fatalf("generate r15: %v", err)
	}
	gen := parseShapes(t, "generated", func(yield func(string, []byte)) {
		for n, b := range files {
			yield(n, b)
		}
	})
	ref := loadSnapshot(t)

	visited := map[string]bool{}
	queue := append([]string(nil), goldenRoots...)
	var problems, usedDeltas []string
	for len(queue) > 0 {
		rt := queue[0]
		queue = queue[1:]
		name := rt
		if visited[name] {
			continue
		}
		visited[name] = true

		got, ok := gen.structs[name]
		if !ok {
			if _, allowed := goldenFree5GCOnly[name]; allowed {
				usedDeltas = append(usedDeltas, "only:"+name)
				continue
			}
			problems = append(problems, fmt.Sprintf("type %s: missing in generated output", name))
			continue
		}
		// Queue referenced types regardless of how they compare.
		refList := ref.structs[name]
		for _, f := range refList {
			if n := ngapNamed(f.Type); n != "" && ref.structs[n] != nil {
				queue = append(queue, n)
			}
		}
		if prefixAllowed(name) {
			continue
		}
		refFields := map[string]fieldShape{}
		for _, f := range refList {
			refFields[f.Name] = f
		}
		if td, ok := goldenTypeDeltas[name]; ok {
			usedDeltas = append(usedDeltas, "type:"+name)
			if p := checkTypeDelta(name, td, got, refFields, &usedDeltas); p != "" {
				problems = append(problems, p)
			}
			continue
		}
		if len(got) != len(refList) {
			problems = append(problems, fmt.Sprintf("type %s: %d fields generated, free5gc has %d", name, len(got), len(refList)))
			continue
		}
		for i, f := range refList {
			want := refFields[f.Name]
			if got[i] == want {
				continue
			}
			key := name + "." + f.Name
			d, allowed := goldenDeltas[key]
			ours := fmt.Sprintf("%s `%s`", got[i].Type, got[i].Tag)
			theirs := fmt.Sprintf("%s `%s`", want.Type, want.Tag)
			if got[i].Name == want.Name && allowed && d.Ours == ours && d.Free5GC == theirs {
				usedDeltas = append(usedDeltas, key)
				continue
			}
			problems = append(problems, fmt.Sprintf("%s: generated %s %s, free5gc %s %s", key, got[i].Name, ours, want.Name, theirs))
		}
	}
	// Present / enumeration constants of every visited type.
	for name := range visited {
		if prefixAllowed(name) {
			continue
		}
		g, r := constsWithPrefix(gen.consts, name+"Present"), constsWithPrefix(ref.consts, name+"Present")
		if td, ok := goldenTypeDeltas[name+"Value"]; ok {
			problems = append(problems, checkConstDelta(name+"Present", td, g, r)...)
			continue
		}
		if td, ok := goldenTypeDeltas[name+"ExtensionValue"]; ok {
			problems = append(problems, checkConstDelta(name+"Present", td, g, r)...)
			continue
		}
		if _, only := goldenFree5GCOnly[name]; only {
			continue
		}
		if !reflect.DeepEqual(g, r) {
			problems = append(problems, fmt.Sprintf("constants %sPresent*: generated %v, free5gc %v", name, g, r))
		}
	}
	// Identifier constants: every ProtocolIEID*/ProcedureCode* of free5gc must exist with the same value.
	for k, v := range ref.consts {
		if !strings.HasPrefix(k, "ProtocolIEID") && !strings.HasPrefix(k, "ProcedureCode") {
			continue
		}
		if gv, ok := gen.consts[k]; !ok || gv != v {
			if _, allowed := goldenIDDeltas[k]; allowed {
				usedDeltas = append(usedDeltas, "id:"+k)
				continue
			}
			problems = append(problems, fmt.Sprintf("id constant %s: free5gc %s, generated %q (present: %v)", k, v, gv, ok))
		}
	}
	var all []string
	for k := range goldenIDDeltas {
		all = append(all, "id:"+k)
	}
	for k := range goldenDeltas {
		all = append(all, k)
	}
	for k := range goldenTypeDeltas {
		all = append(all, "type:"+k)
	}
	for k := range goldenFree5GCOnly {
		all = append(all, "only:"+k)
	}
	for _, k := range all {
		if !contains(usedDeltas, k) {
			problems = append(problems, "stale allowlist entry (not exercised): "+k)
		}
	}
	sort.Strings(problems)
	for _, p := range problems {
		t.Error(p)
	}
	for _, r := range goldenRoots {
		if !visited[r] {
			t.Errorf("root %s not visited", r)
		}
	}
	t.Logf("compared %d types (roots %d) against free5gc v1.1.3; %d allowlisted deltas", len(visited), len(goldenRoots), len(usedDeltas))
}

// checkTypeDelta verifies that the member-set difference of a value struct is exactly the
// allowlisted one and that the common members are identical.
func checkTypeDelta(name string, td typeDelta, gen []fieldShape, ref map[string]fieldShape, used *[]string) string {
	genByName := map[string]fieldShape{}
	var onlyGen, onlyRef []string
	for _, f := range gen {
		genByName[f.Name] = f
		if _, ok := ref[f.Name]; !ok {
			onlyGen = append(onlyGen, f.Name)
		}
	}
	for n := range ref {
		if _, ok := genByName[n]; !ok {
			onlyRef = append(onlyRef, n)
		}
	}
	sort.Strings(onlyGen)
	sort.Strings(onlyRef)
	if !sameSet(onlyGen, td.OnlyGenerated) || !sameSet(onlyRef, td.OnlyFree5GC) {
		return fmt.Sprintf("type %s: member delta is only-generated=%v only-free5gc=%v, allowlist says %v / %v", name, onlyGen, onlyRef, td.OnlyGenerated, td.OnlyFree5GC)
	}
	for n, f := range genByName {
		r, ok := ref[n]
		if !ok || r == f {
			continue
		}
		d, allowed := goldenDeltas[name+"."+n]
		if allowed && d.Ours == fmt.Sprintf("%s `%s`", f.Type, f.Tag) && d.Free5GC == fmt.Sprintf("%s `%s`", r.Type, r.Tag) {
			*used = append(*used, name+"."+n)
			continue
		}
		return fmt.Sprintf("type %s.%s: generated %+v, free5gc %+v", name, n, f, r)
	}
	return ""
}

func checkConstDelta(prefix string, td typeDelta, gen, ref map[string]string) []string {
	var onlyGen, onlyRef []string
	for k := range gen {
		if _, ok := ref[k]; !ok {
			onlyGen = append(onlyGen, strings.TrimPrefix(k, prefix))
		}
	}
	for k := range ref {
		if _, ok := gen[k]; !ok {
			onlyRef = append(onlyRef, strings.TrimPrefix(k, prefix))
		}
	}
	if !sameSet(onlyGen, td.OnlyGenerated) || !sameSet(onlyRef, td.OnlyFree5GC) {
		return []string{fmt.Sprintf("constants %s*: delta only-generated=%v only-free5gc=%v, allowlist says %v / %v", prefix, onlyGen, onlyRef, td.OnlyGenerated, td.OnlyFree5GC)}
	}
	return nil
}

func sameSet(a, b []string) bool {
	x, y := append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	return reflect.DeepEqual(x, y) || (len(x) == 0 && len(y) == 0)
}

func prefixAllowed(name string) bool {
	return goldenStructDeltas[name]
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func constsWithPrefix(m map[string]string, prefix string) map[string]string {
	out := map[string]string{}
	for k, v := range m {
		if strings.HasPrefix(k, prefix) {
			out[k] = v
		}
	}
	return out
}

// ngapNamed returns the ngapType type name referenced by a field type string (through
// pointers and slices), or "".
func ngapNamed(typ string) string {
	for strings.HasPrefix(typ, "*") || strings.HasPrefix(typ, "[]") {
		typ = strings.TrimPrefix(strings.TrimPrefix(typ, "*"), "[]")
	}
	if n, ok := strings.CutPrefix(typ, "ngapType."); ok {
		return n
	}
	return ""
}

// normTag sorts the comma-separated aper tag parts: aper reads them as a set, and
// free5gc's own ordering is not consistent ("optional,valueExt,..." appears once).
func normTag(tag string) string {
	if tag == "" {
		return ""
	}
	p := strings.Split(tag, ",")
	sort.Strings(p)
	return strings.Join(p, ",")
}

// parseShapes parses Go sources into the comparable struct/const view. Local type
// identifiers are rendered as "ngapType.X" to match reflect's reflect.Type.String().
func parseShapes(t *testing.T, what string, files func(yield func(string, []byte))) shapes {
	t.Helper()
	s := shapes{structs: map[string][]fieldShape{}, consts: map[string]string{}}
	fset := token.NewFileSet()
	files(func(name string, src []byte) {
		f, err := parser.ParseFile(fset, name, src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s file %s: %v", what, name, err)
		}
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok {
				continue
			}
			switch gd.Tok {
			case token.TYPE:
				for _, sp := range gd.Specs {
					ts := sp.(*ast.TypeSpec)
					st, ok := ts.Type.(*ast.StructType)
					if !ok {
						continue
					}
					var fs []fieldShape
					for _, fl := range st.Fields.List {
						tag := ""
						if fl.Tag != nil {
							raw, err := strconv.Unquote(fl.Tag.Value)
							if err != nil {
								t.Fatalf("%s: bad struct tag %s: %v", name, fl.Tag.Value, err)
							}
							tag = normTag(reflect.StructTag(raw).Get("aper"))
						}
						for _, n := range fl.Names {
							fs = append(fs, fieldShape{n.Name, exprString(fl.Type), tag})
						}
					}
					s.structs[ts.Name.Name] = fs
				}
			case token.CONST:
				for i, sp := range gd.Specs {
					vs := sp.(*ast.ValueSpec)
					val := strconv.Itoa(i) // implicit iota repetition
					if len(vs.Values) > 0 {
						switch v := vs.Values[0].(type) {
						case *ast.Ident:
							val = strconv.Itoa(i) // iota
						case *ast.BasicLit:
							val = v.Value
						}
					}
					for _, n := range vs.Names {
						s.consts[n.Name] = val
					}
				}
			}
		}
	})
	return s
}

func exprString(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		switch x.Name {
		case "int", "int64", "string", "bool":
			return x.Name
		}
		return "ngapType." + x.Name
	case *ast.StarExpr:
		return "*" + exprString(x.X)
	case *ast.ArrayType:
		return "[]" + exprString(x.Elt)
	case *ast.SelectorExpr:
		return exprString(x.X)[len("ngapType."):] + "." + x.Sel.Name
	}
	return fmt.Sprintf("?%T", e)
}
