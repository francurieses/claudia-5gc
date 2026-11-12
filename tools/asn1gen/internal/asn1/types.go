package asn1

import (
	"fmt"
	"math"
	"strconv"
)

// charStrings lists the restricted character string types accepted by the parser.
var charStrings = map[string]bool{
	"PrintableString": true, "VisibleString": true, "UTF8String": true,
	"IA5String": true, "NumericString": true,
}

func (p *parser) parseType() (*Type, error) {
	t := p.next()
	if t.Kind != TokIdent {
		return nil, p.errf(t, "expected type")
	}
	ty := &Type{Line: t.Line}
	switch t.Text {
	case "SEQUENCE":
		return p.sequence(ty)
	case "CHOICE":
		ty.Kind = KindChoice
		if err := p.components(ty, false); err != nil {
			return nil, err
		}
		return ty, nil
	case "ENUMERATED":
		ty.Kind = KindEnumerated
		if err := p.enumerators(ty); err != nil {
			return nil, err
		}
		return ty, nil
	case "INTEGER":
		ty.Kind = KindInteger
		if p.isPunct("{") {
			return nil, p.errf(p.peek(), "INTEGER with named numbers is not supported")
		}
	case "BIT":
		if err := p.expectWord("STRING"); err != nil {
			return nil, err
		}
		ty.Kind = KindBitString
	case "OCTET":
		if err := p.expectWord("STRING"); err != nil {
			return nil, err
		}
		ty.Kind = KindOctetString
	case "OBJECT":
		if err := p.expectWord("IDENTIFIER"); err != nil {
			return nil, err
		}
		ty.Kind = KindOID
	case "NULL":
		ty.Kind = KindNull
	case "BOOLEAN":
		ty.Kind = KindBoolean
	default:
		if charStrings[t.Text] {
			ty.Kind = KindCharString
			ty.CharString = t.Text
			break
		}
		if p.isPunct(".") && p.peekN(1).Kind == TokClassField {
			p.next()
			ty.Kind = KindClassField
			ty.ClassName = t.Text
			ty.ClassField = p.next().Text
			break
		}
		ty.Kind = KindRef
		ty.Ref = t.Text
		if p.isPunct("{") {
			args, err := p.args()
			if err != nil {
				return nil, err
			}
			ty.Args = args
		}
	}
	if p.isPunct("(") {
		if err := p.constraint(&ty.Constraint); err != nil {
			return nil, err
		}
	}
	return ty, nil
}

// args parses actual parameters "{ {Set} }", "{{Set}}" or "{ 1, max, {Set} }".
func (p *parser) args() ([]Arg, error) {
	if err := p.expectPunct("{"); err != nil {
		return nil, err
	}
	var out []Arg
	for !p.isPunct("}") {
		switch t := p.peek(); {
		case t.Kind == TokPunct && t.Text == ",":
			p.next()
		case t.Kind == TokPunct && t.Text == "{":
			p.next()
			id, err := p.ident()
			if err != nil {
				return nil, err
			}
			if err := p.expectPunct("}"); err != nil {
				return nil, err
			}
			out = append(out, Arg{ObjectSet: id.Text})
		case t.Kind == TokNumber || t.Kind == TokIdent:
			v, err := p.value()
			if err != nil {
				return nil, err
			}
			out = append(out, Arg{Value: &v})
		default:
			return nil, p.errf(t, "unexpected token in actual parameter list")
		}
	}
	p.next()
	return out, nil
}

func (p *parser) sequence(ty *Type) (*Type, error) {
	if p.isPunct("{") {
		ty.Kind = KindSequence
		if err := p.components(ty, true); err != nil {
			return nil, err
		}
		return ty, nil
	}
	ty.Kind = KindSequenceOf
	if p.isPunct("(") || p.isWord("SIZE") {
		paren := p.isPunct("(")
		if paren {
			p.next()
		}
		if err := p.expectWord("SIZE"); err != nil {
			return nil, err
		}
		r, err := p.sizeRange()
		if err != nil {
			return nil, err
		}
		ty.Constraint.Size = r
		if paren {
			if err := p.expectPunct(")"); err != nil {
				return nil, err
			}
		}
	}
	if err := p.expectWord("OF"); err != nil {
		return nil, err
	}
	elem, err := p.parseType()
	if err != nil {
		return nil, err
	}
	ty.Elem = elem
	return ty, nil
}

// components parses "{ name Type [OPTIONAL|DEFAULT v], ..., }" for SEQUENCE (isSeq) or CHOICE.
func (p *parser) components(ty *Type, isSeq bool) error {
	if err := p.expectPunct("{"); err != nil {
		return err
	}
	ext := false
	for !p.isPunct("}") {
		switch t := p.peek(); {
		case t.Kind == TokPunct && t.Text == ",":
			p.next()
		case t.Kind == TokPunct && t.Text == "...":
			p.next()
			if ty.Extensible {
				return p.errf(t, "second extension marker")
			}
			ty.Extensible, ext = true, true
		case t.Kind == TokPunct && t.Text == "[":
			return p.errf(t, "extension addition groups [[ ]] are not supported")
		case t.Kind == TokIdent:
			p.next()
			cty, err := p.parseType()
			if err != nil {
				return err
			}
			c := Component{Name: t.Text, Type: cty, ExtAddition: ext, Line: t.Line}
			if isSeq {
				switch {
				case p.isWord("OPTIONAL"):
					p.next()
					c.Optional = true
				case p.isWord("DEFAULT"):
					p.next()
					v, err := p.value()
					if err != nil {
						return err
					}
					c.Default = &v
				}
			}
			ty.Components = append(ty.Components, c)
		default:
			return p.errf(t, "unexpected token in component list")
		}
	}
	p.next()
	return nil
}

func (p *parser) enumerators(ty *Type) error {
	if err := p.expectPunct("{"); err != nil {
		return err
	}
	ext := false
	for !p.isPunct("}") {
		switch t := p.peek(); {
		case t.Kind == TokPunct && t.Text == ",":
			p.next()
		case t.Kind == TokPunct && t.Text == "...":
			p.next()
			ty.Extensible, ext = true, true
		case t.Kind == TokIdent:
			p.next()
			e := Enumerator{Name: t.Text, Value: -1, ExtAddition: ext}
			if p.isPunct("(") {
				p.next()
				v, err := p.value()
				if err != nil || !v.IsNum {
					return p.errf(t, "enumerator %s: expected number", t.Text)
				}
				e.Value = v.Num
				if err := p.expectPunct(")"); err != nil {
					return err
				}
			}
			ty.Enums = append(ty.Enums, e)
		default:
			return p.errf(t, "unexpected token in enumeration")
		}
	}
	p.next()
	return nil
}

func (p *parser) bound() (Bound, error) {
	t := p.next()
	switch {
	case t.Kind == TokNumber:
		n, err := strconv.ParseInt(t.Text, 10, 64)
		if err != nil {
			// Rel-15 NGAP has INTEGER (0..18446744073709551615): keep the literal text.
			if _, uerr := strconv.ParseUint(t.Text, 10, 64); uerr != nil {
				return Bound{}, p.errf(t, "bad number: %v", err)
			}
			// Num is deliberately clamped to MaxInt64 (arithmetic users such as unions see a
			// saturated value); the generator emits Lit, so the tag carries the real bound
			// (valueUB:18446744073709551615), exactly as free5gc/ngap does.
			n = math.MaxInt64
		}
		return Bound{Kind: BoundNum, Num: n, Lit: t.Text}, nil
	case t.Kind == TokIdent && t.Text == "MIN":
		return Bound{Kind: BoundMin}, nil
	case t.Kind == TokIdent && t.Text == "MAX":
		return Bound{Kind: BoundMax}, nil
	case t.Kind == TokIdent:
		return Bound{Kind: BoundName, Name: t.Text}, nil
	}
	return Bound{}, p.errf(t, "expected range bound")
}

// sizeRange parses "( lo..hi [, ...] )" after SIZE.
func (p *parser) sizeRange() (*Range, error) {
	if err := p.expectPunct("("); err != nil {
		return nil, err
	}
	r, err := p.rangeBody()
	if err != nil {
		return nil, err
	}
	return r, p.expectPunct(")")
}

// rangeBody parses "lo..hi", "v" and an optional ", ..." extension marker.
func (p *parser) rangeBody() (*Range, error) {
	lo, err := p.bound()
	if err != nil {
		return nil, err
	}
	r := &Range{Lo: lo, Hi: lo, Single: true}
	if p.isPunct("..") {
		p.next()
		hi, err := p.bound()
		if err != nil {
			return nil, err
		}
		r.Hi, r.Single = hi, false
	}
	// Union of values/ranges, e.g. (1..30|40|50): PER encodes the smallest range that
	// covers every alternative (X.691 clause 11.5.3 uses the effective constraint's
	// bounds), so the union collapses to min..max.
	for p.isPunct("|") {
		p.next()
		lo2, err := p.bound()
		if err != nil {
			return nil, err
		}
		hi2 := lo2
		if p.isPunct("..") {
			p.next()
			if hi2, err = p.bound(); err != nil {
				return nil, err
			}
		}
		if r.Lo.Kind != BoundNum || r.Hi.Kind != BoundNum || lo2.Kind != BoundNum || hi2.Kind != BoundNum {
			return nil, p.errf(p.peek(), "union of non-numeric bounds is not supported")
		}
		r.Lo.Num, r.Hi.Num = min(r.Lo.Num, lo2.Num), max(r.Hi.Num, hi2.Num)
		r.Lo.Lit, r.Hi.Lit = strconv.FormatInt(r.Lo.Num, 10), strconv.FormatInt(r.Hi.Num, 10)
		r.Single = false
	}
	if p.isPunct(",") && p.peekN(1).Kind == TokPunct && p.peekN(1).Text == "..." {
		p.next()
		p.next()
		r.Ext = true
		// Extension additions "..., 65536..109999" are recorded in ExtAdditions. For PER only
		// the root range bounds the encoding (valueLB/UB plus valueExt), so the generator
		// deliberately uses Lo/Hi and ignores the additions.
		for p.isPunct(",") {
			p.next()
			add, err := p.rangeBody()
			if err != nil {
				return nil, err
			}
			r.ExtAdditions = append(r.ExtAdditions, add)
		}
	}
	return r, nil
}

// constraint parses one parenthesised constraint group.
func (p *parser) constraint(c *Constraint) error {
	open := p.next() // (
	for !p.isPunct(")") {
		switch t := p.peek(); {
		case t.Kind == TokIdent && t.Text == "SIZE":
			p.next()
			r, err := p.sizeRange()
			if err != nil {
				return err
			}
			if c.Size != nil {
				return p.errf(t, "duplicate SIZE constraint (group opened at line %d)", open.Line)
			}
			c.Size = r
		case t.Kind == TokIdent && t.Text == "CONTAINING":
			p.next()
			id, err := p.ident()
			if err != nil {
				return err
			}
			if c.Containing != "" {
				return p.errf(t, "duplicate CONTAINING constraint (group opened at line %d)", open.Line)
			}
			c.Containing = id.Text
		case t.Kind == TokPunct && t.Text == "{": // table constraint {Set}{@id}
			p.next()
			if p.isPunct("@") {
				p.next()
			} else {
				id, err := p.ident()
				if err != nil {
					return err
				}
				c.ObjectSets = append(c.ObjectSets, id.Text)
				if err := p.expectPunct("}"); err != nil {
					return err
				}
				continue
			}
			if _, err := p.ident(); err != nil {
				return err
			}
			if err := p.expectPunct("}"); err != nil {
				return err
			}
			continue
		case t.Kind == TokNumber || t.Kind == TokIdent:
			r, err := p.rangeBody()
			if err != nil {
				return err
			}
			if c.Value != nil {
				return p.errf(t, "duplicate value constraint (group opened at line %d)", open.Line)
			}
			c.Value = r
		default:
			return p.errf(t, "unsupported constraint syntax (group opened at line %d)", open.Line)
		}
	}
	p.next()
	return nil
}

// String renders a bound for diagnostics.
func (b Bound) String() string {
	switch b.Kind {
	case BoundNum:
		return b.Lit
	case BoundName:
		return b.Name
	case BoundMin:
		return "MIN"
	case BoundMax:
		return "MAX"
	}
	return fmt.Sprintf("bound(%d)", int(b.Kind))
}
