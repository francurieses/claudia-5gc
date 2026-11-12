package asn1

import (
	"math"
	"strings"
	"testing"
)

func TestLex(t *testing.T) {
	toks, err := Lex("t", "A-b ::= INTEGER (-5..max-1) -- comment -- x\n-- whole line\n ... .. { } &id &Val \"s\" |")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, k := range toks {
		got = append(got, k.Text)
	}
	want := "A-b ::= INTEGER ( -5 .. max-1 ) x ... .. { } id Val s | "
	if strings.Join(got, " ") != want {
		t.Errorf("tokens = %q, want %q", strings.Join(got, " "), want)
	}
	if toks[len(toks)-1].Kind != TokEOF {
		t.Error("missing EOF")
	}
}

func TestLexErrors(t *testing.T) {
	for _, src := range []string{"a # b", "x \"unterminated", "& ", "a .... b"} {
		if _, err := Lex("t", src); err == nil {
			t.Errorf("Lex(%q): expected error", src)
		}
	}
}

const header = "M { 1 } DEFINITIONS AUTOMATIC TAGS ::= BEGIN\n"

func mustParse(t *testing.T, body string) *Module {
	t.Helper()
	m, err := ParseModule("t.asn", header+body+"\nEND")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return m
}

func TestParseTypes(t *testing.T) {
	m := mustParse(t, `
	N INTEGER ::= 8
	A ::= INTEGER (0..N, ...)
	B ::= INTEGER (1..30|40|50, ...)
	C ::= INTEGER (0..18446744073709551615)
	D ::= BIT STRING (SIZE(10))
	E ::= OCTET STRING (SIZE(1..N, ...))
	F ::= OCTET STRING (CONTAINING A)
	G ::= PrintableString (SIZE(1..150, ...))
	H ::= ENUMERATED { x, y, ..., z }
	I ::= SEQUENCE { a A, b B OPTIONAL, c INTEGER (0..3) DEFAULT 1, ... }
	J ::= CHOICE { a A, b NULL, c OBJECT IDENTIFIER, ... }
	K ::= SEQUENCE (SIZE(1..N)) OF A
	L ::= SEQUENCE OF A
	O ::= Alias
	`)
	cases := []struct {
		name  string
		check func(*Type) bool
	}{
		{"A", func(x *Type) bool {
			r := x.Constraint.Value
			return x.Kind == KindInteger && r.Ext && r.Lo.Num == 0 && r.Hi.Name == "N"
		}},
		{"B", func(x *Type) bool { r := x.Constraint.Value; return r.Lo.Num == 1 && r.Hi.Num == 50 && r.Ext }},
		{"C", func(x *Type) bool { return x.Constraint.Value.Hi.Lit == "18446744073709551615" }},
		{"D", func(x *Type) bool {
			s := x.Constraint.Size
			return x.Kind == KindBitString && s.Single && s.Lo.Num == 10
		}},
		{"E", func(x *Type) bool { return x.Kind == KindOctetString && x.Constraint.Size.Ext }},
		{"F", func(x *Type) bool { return x.Constraint.Containing == "A" }},
		{"G", func(x *Type) bool { return x.Kind == KindCharString && x.CharString == "PrintableString" }},
		{"H", func(x *Type) bool {
			return x.Kind == KindEnumerated && x.Extensible && len(x.Enums) == 3 && x.Enums[2].ExtAddition && !x.Enums[1].ExtAddition
		}},
		{"I", func(x *Type) bool {
			c := x.Components
			return x.Kind == KindSequence && x.Extensible && len(c) == 3 && c[1].Optional && c[2].Default != nil && c[2].Default.Num == 1
		}},
		{"J", func(x *Type) bool {
			c := x.Components
			return x.Kind == KindChoice && c[1].Type.Kind == KindNull && c[2].Type.Kind == KindOID && x.Extensible
		}},
		{"K", func(x *Type) bool {
			return x.Kind == KindSequenceOf && x.Constraint.Size.Hi.Name == "N" && x.Elem.Ref == "A"
		}},
		{"L", func(x *Type) bool { return x.Kind == KindSequenceOf && x.Constraint.Size == nil }},
		{"O", func(x *Type) bool { return x.Kind == KindRef && x.Ref == "Alias" }},
	}
	for _, c := range cases {
		ta, ok := m.Types[c.name]
		if !ok {
			t.Errorf("%s: not parsed", c.name)
			continue
		}
		if !c.check(ta.Type) {
			t.Errorf("%s: unexpected AST %+v", c.name, ta.Type)
		}
	}
	if v := m.Values["N"]; v == nil || v.Value.Num != 8 {
		t.Errorf("value N = %+v", v)
	}
}

func TestParseClassesAndObjects(t *testing.T) {
	m := mustParse(t, `
	IES ::= CLASS { &id Pid UNIQUE, &crit Crit DEFAULT ignore, &Value, &presence Presence OPTIONAL }
	WITH SYNTAX { ID &id [CRITICALITY &crit] TYPE &Value PRESENCE &presence }
	Set IES ::= {
		{ ID id-A CRITICALITY reject TYPE Foo PRESENCE mandatory } |
		{ ID id-B TYPE OCTET STRING (SIZE(2)) PRESENCE optional } |
		Other,
		...
	}
	Obj PROC ::= { INITIATING MESSAGE Msg SUCCESSFUL OUTCOME Ack PROCEDURE CODE id-P CRITICALITY ignore }
	Wrap {IES : P} ::= SEQUENCE { id IES.&id ({P}), value IES.&Value ({P}{@id}) }
	Use ::= SEQUENCE { c Wrap { {Set} } }
	`)
	cl := m.Classes["IES"]
	if cl == nil || len(cl.Fields) != 4 || !cl.Fields[0].Unique || !cl.Fields[2].IsType || cl.Fields[1].Default != "ignore" || !cl.Fields[3].Optional {
		t.Fatalf("class = %+v", cl)
	}
	if cl.Syntax["TYPE"] != "Value" || cl.Syntax["CRITICALITY"] != "crit" || cl.Syntax["ID"] != "id" {
		t.Errorf("syntax = %v", cl.Syntax)
	}
	set := m.Objects["Set"]
	if set == nil || !set.IsSet || len(set.Elems) != 4 || set.Elems[2].Ref != "Other" || !set.Elems[3].Ellipsis {
		t.Fatalf("set = %+v", set)
	}
	if f := set.Elems[1].Inline["TYPE"]; f.Type == nil || f.Type.Kind != KindOctetString {
		t.Errorf("inline OCTET STRING type = %+v", f)
	}
	if o := m.Objects["Obj"]; o == nil || o.IsSet || o.Fields["INITIATING MESSAGE"].Type.Ref != "Msg" || o.Fields["PROCEDURE CODE"].Value.Name != "id-P" {
		t.Errorf("object = %+v", o)
	}
	w := m.Types["Wrap"]
	if w == nil || len(w.Params) != 1 || w.Params[0].Governor != "IES" || w.Type.Components[0].Type.Kind != KindClassField {
		t.Fatalf("parameterised type = %+v", w)
	}
	if got := w.Type.Components[1].Type.Constraint.ObjectSets; len(got) != 1 || got[0] != "P" {
		t.Errorf("table constraint sets = %v", got)
	}
	use := m.Types["Use"].Type.Components[0].Type
	if use.Kind != KindRef || len(use.Args) != 1 || use.Args[0].ObjectSet != "Set" {
		t.Errorf("instantiation = %+v", use)
	}
}

func TestParseImportsExports(t *testing.T) {
	m, err := ParseModule("t", `M DEFINITIONS AUTOMATIC TAGS ::= BEGIN
	EXPORTS A{}, B;
	IMPORTS X, Y FROM Mod1 Z, P{} FROM Mod2;
	A ::= INTEGER
	END`)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Imports) != 2 || m.Imports[0].Module != "Mod1" || len(m.Imports[0].Names) != 2 || m.Imports[1].Names[1] != "P" {
		t.Errorf("imports = %+v", m.Imports)
	}
}

func TestParseErrors(t *testing.T) {
	bad := map[string]string{
		"extension group":     "A ::= SEQUENCE { a INTEGER, ..., [[ b INTEGER ]] }",
		"named numbers":       "A ::= INTEGER { x(1) }",
		"duplicate type":      "A ::= INTEGER\nA ::= INTEGER",
		"unterminated seq":    "A ::= SEQUENCE { a INTEGER",
		"bad constraint":      "A ::= INTEGER (0..1 ^ 2)",
		"missing type":        "A ::=",
		"unknown obj keyword": "O C ::= { { BOGUS x } }",
		"two markers":         "A ::= SEQUENCE { ..., ... }",
		"duplicate SIZE":      "A ::= OCTET STRING (SIZE(1) SIZE(2))",
		"duplicate value":     "A ::= INTEGER (1..2 3..4)",
		"stray brace":         "A ::= SEQUENCE OF B (SIZE(1..2) })",
	}
	for name, body := range bad {
		if _, err := ParseModule("t.asn", header+body+"\nEND"); err == nil {
			t.Errorf("%s: expected an error", name)
		} else if !strings.Contains(err.Error(), "t.asn") {
			t.Errorf("%s: error lacks position: %v", name, err)
		}
	}
	if _, err := ParseModule("t.asn", header+"A ::= INTEGER"); err == nil {
		t.Error("missing END: expected error")
	}
}

func TestParseConstraintDetails(t *testing.T) {
	m := mustParse(t, "A ::= INTEGER (0..10, ..., 20..30, 40)\nB ::= SEQUENCE OF C ({Set}{@id})")
	r := m.Types["A"].Type.Constraint.Value
	if !r.Ext || r.Hi.Num != 10 || len(r.ExtAdditions) != 2 || r.ExtAdditions[0].Hi.Num != 30 {
		t.Errorf("A range = %+v", r)
	}
}

func TestModuleHeaderTags(t *testing.T) {
	for name, hdr := range map[string]string{
		"explicit": "M DEFINITIONS EXPLICIT TAGS ::= BEGIN\n",
		"implicit": "M DEFINITIONS IMPLICIT TAGS ::= BEGIN\n",
		"missing":  "M DEFINITIONS ::= BEGIN\n",
		"no ::=":   "M DEFINITIONS AUTOMATIC TAGS BEGIN\n",
	} {
		if _, err := ParseModule("t.asn", hdr+"A ::= INTEGER\nEND"); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if _, err := ParseModule("t.asn", "M DEFINITIONS AUTOMATIC TAGS ::= BEGIN\nA ::= INTEGER\nEND"); err != nil {
		t.Errorf("AUTOMATIC TAGS: %v", err)
	}
}

func TestUint64BoundClamp(t *testing.T) {
	m := mustParse(t, "C ::= INTEGER (0..18446744073709551615)")
	h := m.Types["C"].Type.Constraint.Value.Hi
	if h.Num != math.MaxInt64 || h.Lit != "18446744073709551615" {
		t.Errorf("bound = %+v", h)
	}
}
