// Package asn1 is a lexer and parser for the subset of ASN.1 (ITU-T X.680/X.681/X.683)
// used by the NGAP modules of 3GPP TS 38.413 clause 9.4: module headers, IMPORTS, value
// assignments, type assignments (SEQUENCE, SEQUENCE OF, CHOICE, ENUMERATED, INTEGER,
// BIT STRING, OCTET STRING, character strings, OBJECT IDENTIFIER, NULL, BOOLEAN),
// information-object classes, object sets and parameterised types.
//
// The package only builds an AST; Go code generation lives in ../gogen. Constructs
// outside the subset are rejected with a positioned error, never skipped silently.
package asn1

import (
	"fmt"
	"strings"
	"unicode"
)

// TokKind classifies a lexical token.
type TokKind int

// Token kinds.
const (
	// TokEOF marks the end of input.
	TokEOF TokKind = iota
	// TokIdent is an identifier or reserved word (hyphens allowed inside).
	TokIdent
	// TokNumber is a (possibly negative) decimal integer.
	TokNumber
	// TokPunct is one of ::= { } ( ) [ ] , | . .. ... : ; @ = < >.
	TokPunct
	// TokClassField is an object-class field reference such as &id or &Value.
	TokClassField
	// TokString is a double-quoted string.
	TokString
)

// Token is one lexical token with its source position.
type Token struct {
	Kind TokKind
	Text string
	Line int
}

func (t Token) String() string {
	if t.Kind == TokEOF {
		return "end of input"
	}
	return fmt.Sprintf("%q", t.Text)
}

// Lex splits ASN.1 source into tokens. A comment starts with "--" and ends at the next
// "--" or at the end of the line (X.680 clause 12.6). File is only used in errors.
func Lex(file, src string) ([]Token, error) {
	var toks []Token
	rs := []rune(src)
	line := 1
	for i := 0; i < len(rs); {
		c := rs[i]
		switch {
		case c == '\n':
			line++
			i++
		case unicode.IsSpace(c) || c == 0xFEFF:
			i++
		case c == '-' && i+1 < len(rs) && rs[i+1] == '-':
			i += 2
			for i < len(rs) && rs[i] != '\n' {
				if rs[i] == '-' && i+1 < len(rs) && rs[i+1] == '-' {
					i += 2
					break
				}
				i++
			}
		case c == '/' && i+1 < len(rs) && rs[i+1] == '*':
			i += 2
			for i+1 < len(rs) && (rs[i] != '*' || rs[i+1] != '/') {
				if rs[i] == '\n' {
					line++
				}
				i++
			}
			i += 2
		case isIdentStart(c):
			j := i + 1
			for j < len(rs) && isIdentPart(rs, j) {
				j++
			}
			toks = append(toks, Token{TokIdent, string(rs[i:j]), line})
			i = j
		case c == '&':
			j := i + 1
			for j < len(rs) && isIdentPart(rs, j) {
				j++
			}
			if j == i+1 {
				return nil, fmt.Errorf("asn1: %s:%d: lone '&'", file, line)
			}
			toks = append(toks, Token{TokClassField, string(rs[i+1 : j]), line})
			i = j
		case unicode.IsDigit(c) || (c == '-' && i+1 < len(rs) && unicode.IsDigit(rs[i+1])):
			j := i + 1
			for j < len(rs) && unicode.IsDigit(rs[j]) {
				j++
			}
			toks = append(toks, Token{TokNumber, string(rs[i:j]), line})
			i = j
		case c == '"':
			j := i + 1
			for j < len(rs) && rs[j] != '"' {
				if rs[j] == '\n' {
					line++
				}
				j++
			}
			if j >= len(rs) {
				return nil, fmt.Errorf("asn1: %s:%d: unterminated string", file, line)
			}
			toks = append(toks, Token{TokString, string(rs[i+1 : j]), line})
			i = j + 1
		case c == ':' && strings.HasPrefix(string(rs[i:min(i+3, len(rs))]), "::="):
			toks = append(toks, Token{TokPunct, "::=", line})
			i += 3
		case c == '.':
			j := i
			for j < len(rs) && rs[j] == '.' {
				j++
			}
			n := j - i
			if n > 3 {
				return nil, fmt.Errorf("asn1: %s:%d: too many dots", file, line)
			}
			toks = append(toks, Token{TokPunct, strings.Repeat(".", n), line})
			i = j
		case strings.ContainsRune("{}()[],|:;@=<>", c):
			toks = append(toks, Token{TokPunct, string(c), line})
			i++
		default:
			return nil, fmt.Errorf("asn1: %s:%d: unexpected character %q", file, line, c)
		}
	}
	toks = append(toks, Token{TokEOF, "", line})
	return toks, nil
}

func isIdentStart(c rune) bool { return unicode.IsLetter(c) }

// isIdentPart reports whether rs[j] continues an identifier. A hyphen continues it only
// when followed by an identifier character (a trailing "-" or "--" ends the identifier).
func isIdentPart(rs []rune, j int) bool {
	c := rs[j]
	if unicode.IsLetter(c) || unicode.IsDigit(c) {
		return true
	}
	if c == '-' && j+1 < len(rs) {
		n := rs[j+1]
		return unicode.IsLetter(n) || unicode.IsDigit(n)
	}
	return false
}
