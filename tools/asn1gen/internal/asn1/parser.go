package asn1

import (
	"fmt"
	"strconv"
	"strings"
)

type parser struct {
	file string
	toks []Token
	pos  int
}

// ParseModule parses one ASN.1 module from src. file is used in error messages.
func ParseModule(file, src string) (*Module, error) {
	toks, err := Lex(file, src)
	if err != nil {
		return nil, err
	}
	p := &parser{file: file, toks: toks}
	m, err := p.module()
	if err != nil {
		return nil, err
	}
	return m, nil
}

func (p *parser) peek() Token { return p.toks[p.pos] }

func (p *parser) peekN(n int) Token {
	if p.pos+n >= len(p.toks) {
		return p.toks[len(p.toks)-1]
	}
	return p.toks[p.pos+n]
}

func (p *parser) next() Token {
	t := p.toks[p.pos]
	if t.Kind != TokEOF {
		p.pos++
	}
	return t
}

func (p *parser) errf(t Token, format string, args ...any) error {
	return fmt.Errorf("asn1: %s:%d: %s (at %s)", p.file, t.Line, fmt.Sprintf(format, args...), t)
}

func (p *parser) isPunct(s string) bool {
	t := p.peek()
	return t.Kind == TokPunct && t.Text == s
}

func (p *parser) isWord(s string) bool {
	t := p.peek()
	return t.Kind == TokIdent && t.Text == s
}

func (p *parser) expectPunct(s string) error {
	t := p.next()
	if t.Kind != TokPunct || t.Text != s {
		return p.errf(t, "expected %q", s)
	}
	return nil
}

func (p *parser) expectWord(s string) error {
	t := p.next()
	if t.Kind != TokIdent || t.Text != s {
		return p.errf(t, "expected %q", s)
	}
	return nil
}

func (p *parser) ident() (Token, error) {
	t := p.next()
	if t.Kind != TokIdent {
		return t, p.errf(t, "expected identifier")
	}
	return t, nil
}

// skipBalanced consumes a balanced group starting at the current open bracket.
func (p *parser) skipBalanced(open, closing string) error {
	depth := 0
	for {
		t := p.next()
		switch {
		case t.Kind == TokEOF:
			return p.errf(t, "unbalanced %q", open)
		case t.Kind == TokPunct && t.Text == open:
			depth++
		case t.Kind == TokPunct && t.Text == closing:
			depth--
			if depth == 0 {
				return nil
			}
		}
	}
}

func (p *parser) module() (*Module, error) {
	name, err := p.ident()
	if err != nil {
		return nil, err
	}
	m := &Module{
		Name: name.Text, File: p.file,
		Types: map[string]*TypeAssign{}, Values: map[string]*ValueAssign{},
		Classes: map[string]*Class{}, Objects: map[string]*Object{},
	}
	if p.isPunct("{") { // module object identifier
		if err := p.skipBalanced("{", "}"); err != nil {
			return nil, err
		}
	}
	if err := p.expectWord("DEFINITIONS"); err != nil {
		return nil, err
	}
	// The generator assumes AUTOMATIC TAGS (no explicit tag handling): anything else is an error.
	if !p.isWord("AUTOMATIC") || p.peekN(1).Text != "TAGS" {
		return nil, p.errf(p.peek(), "module %s: only AUTOMATIC TAGS is supported", m.Name)
	}
	p.next()
	p.next()
	if err := p.expectPunct("::="); err != nil {
		return nil, err
	}
	if err := p.expectWord("BEGIN"); err != nil {
		return nil, err
	}
	if p.isWord("EXPORTS") {
		for !p.isPunct(";") {
			if t := p.next(); t.Kind == TokEOF {
				return nil, p.errf(t, "EXPORTS: missing ;")
			}
		}
		p.next()
	}
	if p.isWord("IMPORTS") {
		p.next()
		if err := p.imports(m); err != nil {
			return nil, err
		}
	}
	for !p.isWord("END") {
		if p.peek().Kind == TokEOF {
			return nil, p.errf(p.peek(), "module %s: missing END", m.Name)
		}
		if err := p.assignment(m); err != nil {
			return nil, err
		}
	}
	return m, nil
}

func (p *parser) imports(m *Module) error {
	var names []string
	for {
		t := p.next()
		switch {
		case t.Kind == TokEOF:
			return p.errf(t, "IMPORTS: missing ;")
		case t.Kind == TokPunct && t.Text == ";":
			if len(names) != 0 {
				return p.errf(t, "IMPORTS: symbols without FROM")
			}
			return nil
		case t.Kind == TokPunct && t.Text == ",":
		case t.Kind == TokPunct && t.Text == "{": // parameterised symbol "Name{}"
			if err := p.expectPunct("}"); err != nil {
				return err
			}
		case t.Kind == TokIdent && t.Text == "FROM":
			mod, err := p.ident()
			if err != nil {
				return err
			}
			m.Imports = append(m.Imports, Import{Module: mod.Text, Names: names})
			names = nil
			if p.isPunct(";") {
				p.next()
				return nil
			}
		case t.Kind == TokIdent:
			names = append(names, t.Text)
		default:
			return p.errf(t, "IMPORTS: unexpected token")
		}
	}
}

func (p *parser) assignment(m *Module) error {
	name, err := p.ident()
	if err != nil {
		return err
	}
	switch t1 := p.peek(); {
	case t1.Kind == TokPunct && t1.Text == "::=":
		p.next()
		if p.isWord("CLASS") {
			return p.class(m, name)
		}
		ty, err := p.parseType()
		if err != nil {
			return err
		}
		return addType(p, m, &TypeAssign{Name: name.Text, Type: ty, Line: name.Line})
	case t1.Kind == TokPunct && t1.Text == "{": // parameterised type
		params, err := p.params()
		if err != nil {
			return err
		}
		if err := p.expectPunct("::="); err != nil {
			return err
		}
		ty, err := p.parseType()
		if err != nil {
			return err
		}
		return addType(p, m, &TypeAssign{Name: name.Text, Params: params, Type: ty, Line: name.Line})
	case t1.Kind == TokIdent: // value or object (set) assignment: name Governor ::= ...
		gov := p.next()
		if err := p.expectPunct("::="); err != nil {
			return err
		}
		if p.isPunct("{") {
			return p.object(m, name, gov)
		}
		v, err := p.value()
		if err != nil {
			return err
		}
		if _, dup := m.Values[name.Text]; dup {
			return p.errf(name, "duplicate value %s", name.Text)
		}
		m.Values[name.Text] = &ValueAssign{Name: name.Text, Type: gov.Text, Value: v, Line: name.Line}
		m.Order = append(m.Order, Ref{RefValue, name.Text})
		return nil
	default:
		return p.errf(t1, "unsupported assignment form for %s", name.Text)
	}
}

func addType(p *parser, m *Module, ta *TypeAssign) error {
	if _, dup := m.Types[ta.Name]; dup {
		return fmt.Errorf("asn1: %s:%d: duplicate type %s", p.file, ta.Line, ta.Name)
	}
	m.Types[ta.Name] = ta
	m.Order = append(m.Order, Ref{RefType, ta.Name})
	return nil
}

// params parses "{ Governor : Name, ... }" (X.683 clause 8).
func (p *parser) params() ([]Param, error) {
	if err := p.expectPunct("{"); err != nil {
		return nil, err
	}
	var out []Param
	for {
		gov, err := p.ident()
		if err != nil {
			return nil, err
		}
		if err := p.expectPunct(":"); err != nil {
			return nil, err
		}
		nm, err := p.ident()
		if err != nil {
			return nil, err
		}
		out = append(out, Param{Governor: gov.Text, Name: nm.Text})
		if p.isPunct(",") {
			p.next()
			continue
		}
		return out, p.expectPunct("}")
	}
}

func (p *parser) value() (Value, error) {
	t := p.next()
	switch t.Kind {
	case TokNumber:
		n, err := strconv.ParseInt(t.Text, 10, 64)
		if err != nil {
			return Value{}, p.errf(t, "bad number: %v", err)
		}
		return Value{Num: n, IsNum: true}, nil
	case TokIdent:
		return Value{Name: t.Text}, nil
	}
	return Value{}, p.errf(t, "expected value")
}

// class parses "CLASS { &f Type [UNIQUE] [OPTIONAL|DEFAULT v], ... } [WITH SYNTAX {...}]".
func (p *parser) class(m *Module, name Token) error {
	p.next() // CLASS
	c := &Class{Name: name.Text, Syntax: map[string]string{}, Line: name.Line}
	if err := p.expectPunct("{"); err != nil {
		return err
	}
	for {
		ft := p.next()
		if ft.Kind != TokClassField {
			return p.errf(ft, "class %s: expected &field", name.Text)
		}
		f := ClassField{Name: ft.Text, IsType: ft.Text[0] >= 'A' && ft.Text[0] <= 'Z'}
		for !p.isPunct(",") && !p.isPunct("}") {
			t := p.next()
			switch {
			case t.Kind == TokEOF:
				return p.errf(t, "class %s: unterminated", name.Text)
			case t.Kind == TokIdent && t.Text == "UNIQUE":
				f.Unique = true
			case t.Kind == TokIdent && t.Text == "OPTIONAL":
				f.Optional = true
			case t.Kind == TokIdent && t.Text == "DEFAULT":
				d, err := p.value()
				if err != nil {
					return err
				}
				f.Default = d.Name
			case t.Kind == TokIdent && f.Type == "" && !f.IsType:
				f.Type = t.Text
			default:
				return p.errf(t, "class %s: unsupported field syntax", name.Text)
			}
		}
		c.Fields = append(c.Fields, f)
		if p.isPunct(",") {
			p.next()
			continue
		}
		p.next() // }
		break
	}
	if p.isWord("WITH") {
		p.next()
		if err := p.expectWord("SYNTAX"); err != nil {
			return err
		}
		if err := p.expectPunct("{"); err != nil {
			return err
		}
		var kw []string
		for !p.isPunct("}") {
			t := p.next()
			switch {
			case t.Kind == TokEOF:
				return p.errf(t, "class %s: unterminated WITH SYNTAX", name.Text)
			case t.Kind == TokPunct && (t.Text == "[" || t.Text == "]" || t.Text == ","):
			case t.Kind == TokIdent:
				kw = append(kw, t.Text)
			case t.Kind == TokClassField:
				c.Syntax[strings.Join(kw, " ")] = t.Text
				kw = nil
			default:
				return p.errf(t, "class %s: unsupported WITH SYNTAX token", name.Text)
			}
		}
		p.next()
	}
	if _, dup := m.Classes[c.Name]; dup {
		return p.errf(name, "duplicate class %s", c.Name)
	}
	m.Classes[c.Name] = c
	m.Order = append(m.Order, Ref{RefClass, c.Name})
	return nil
}

// object parses the body of "name Class ::= { ... }": either one object written as a
// WITH SYNTAX keyword list, or an object set of elements separated by '|' and ','.
func (p *parser) object(m *Module, name, class Token) error {
	o := &Object{Name: name.Text, Class: class.Text, Line: name.Line}
	p.next() // {
	if _, _, n := p.matchPhrase(); n > 0 {
		fields, err := p.objectFields(class.Text)
		if err != nil {
			return err
		}
		o.Fields = fields
		if err := p.expectPunct("}"); err != nil {
			return err
		}
	} else {
		o.IsSet = true
		for !p.isPunct("}") {
			t := p.peek()
			switch {
			case t.Kind == TokPunct && (t.Text == "|" || t.Text == ","):
				p.next()
			case t.Kind == TokPunct && t.Text == "...":
				p.next()
				o.Elems = append(o.Elems, ObjElem{Ellipsis: true})
			case t.Kind == TokPunct && t.Text == "{":
				p.next()
				fields, err := p.objectFields(class.Text)
				if err != nil {
					return err
				}
				if err := p.expectPunct("}"); err != nil {
					return err
				}
				o.Elems = append(o.Elems, ObjElem{Inline: fields, InlineLn: t.Line})
			case t.Kind == TokIdent:
				p.next()
				o.Elems = append(o.Elems, ObjElem{Ref: t.Text})
			default:
				return p.errf(t, "object set %s: unexpected token", name.Text)
			}
		}
		p.next()
	}
	if _, dup := m.Objects[o.Name]; dup {
		return p.errf(name, "duplicate object %s", o.Name)
	}
	m.Objects[o.Name] = o
	m.Order = append(m.Order, Ref{RefObject, o.Name})
	return nil
}

// keywordPhrases lists the WITH SYNTAX phrases of the X.681 classes used by NGAP
// (TS 38.413 clause 9.4). Longest phrases first. Phrases flagged type introduce a type,
// the others a value. Objects are parsed before their class may be known (it can be
// imported from another module), so the phrases are fixed here and mapped to class
// fields later by the generator through Class.Syntax.
var keywordPhrases = []struct {
	words  []string
	isType bool
}{
	{[]string{"INITIATING", "MESSAGE"}, true},
	{[]string{"SUCCESSFUL", "OUTCOME"}, true},
	{[]string{"UNSUCCESSFUL", "OUTCOME"}, true},
	{[]string{"PROCEDURE", "CODE"}, false},
	{[]string{"FIRST", "CRITICALITY"}, false},
	{[]string{"SECOND", "CRITICALITY"}, false},
	{[]string{"FIRST", "TYPE"}, true},
	{[]string{"SECOND", "TYPE"}, true},
	{[]string{"CRITICALITY"}, false},
	{[]string{"EXTENSION"}, true},
	{[]string{"PRESENCE"}, false},
	{[]string{"TYPE"}, true},
	{[]string{"ID"}, false},
}

// matchPhrase returns the keyword phrase at the current position, if any.
func (p *parser) matchPhrase() (phrase string, isType bool, n int) {
	for _, kp := range keywordPhrases {
		ok := true
		for i, w := range kp.words {
			if t := p.peekN(i); t.Kind != TokIdent || t.Text != w {
				ok = false
				break
			}
		}
		if ok {
			return strings.Join(kp.words, " "), kp.isType, len(kp.words)
		}
	}
	return "", false, 0
}

// objectFields reads "KEYWORD value" pairs until the closing '}' (not consumed).
func (p *parser) objectFields(className string) (map[string]ObjField, error) {
	fields := map[string]ObjField{}
	for !p.isPunct("}") {
		phrase, isType, n := p.matchPhrase()
		if n == 0 {
			return nil, p.errf(p.peek(), "object of class %s: expected keyword", className)
		}
		p.pos += n
		var of ObjField
		if isType {
			ty, err := p.parseType()
			if err != nil {
				return nil, err
			}
			of.Type = ty
		} else {
			v, err := p.value()
			if err != nil {
				return nil, err
			}
			of.Value = &v
		}
		if _, dup := fields[phrase]; dup {
			return nil, p.errf(p.peek(), "object of class %s: duplicate %s", className, phrase)
		}
		fields[phrase] = of
	}
	return fields, nil
}
