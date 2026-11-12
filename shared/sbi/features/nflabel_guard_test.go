package features

// nflabel_guard_test.go - REL19-2.8 guard on the nf label of
// fivegc_procedure_total{procedure="FeatureNegotiation"}: in production code
// under nf/<x>/, every features.Negotiation literal sets NF and every
// features.CountNegotiation call passes, as a string literal, the upper-cased
// directory name <X> (no "" / UNKNOWN by omission, no copy-paste label from
// another NF). Under shared/ the value must be a non-empty expression (the
// caller's NF, e.g. shared/nrf's DiscoveryQuery.RequesterNFType).

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// wantNFLabel returns the label required for a file under root, or "" for
// files outside nf/<x>/ (shared code: any non-empty expression).
func wantNFLabel(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return ""
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	if len(parts) > 2 && parts[0] == "nf" {
		return strings.ToUpper(parts[1])
	}
	return ""
}

// checkNFExpr reports a problem with the nf label expression e, or "".
func checkNFExpr(e ast.Expr, want string) string {
	lit, isLit := e.(*ast.BasicLit)
	if want == "" {
		if isLit && lit.Kind == token.STRING && lit.Value == `""` {
			return "empty nf label"
		}
		return ""
	}
	if !isLit || lit.Kind != token.STRING {
		return "nf label is not a string literal (want " + strconv.Quote(want) + ")"
	}
	if v, _ := strconv.Unquote(lit.Value); v != want {
		return "nf label " + lit.Value + ", want " + strconv.Quote(want)
	}
	return ""
}

func isFeaturesSel(e ast.Expr, name string) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != name {
		return false
	}
	x, ok := sel.X.(*ast.Ident)
	return ok && x.Name == "features"
}

func TestNegotiationNFLabels(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	fset := token.NewFileSet()
	literals, counts := 0, 0
	for _, dir := range []string{"nf", "shared"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			want := wantNFLabel(root, path)
			ast.Inspect(f, func(n ast.Node) bool {
				switch v := n.(type) {
				case *ast.CompositeLit:
					if !isFeaturesSel(v.Type, "Negotiation") {
						return true
					}
					literals++
					for _, e := range v.Elts {
						kv, ok := e.(*ast.KeyValueExpr)
						if !ok {
							continue
						}
						if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "NF" {
							if msg := checkNFExpr(kv.Value, want); msg != "" {
								t.Errorf("%s: features.Negotiation: %s", fset.Position(v.Pos()), msg)
							}
							return true
						}
					}
					t.Errorf("%s: features.Negotiation literal without NF (counted as %q)", fset.Position(v.Pos()), UnknownNF)
				case *ast.CallExpr:
					if !isFeaturesSel(v.Fun, "CountNegotiation") {
						return true
					}
					counts++
					if len(v.Args) != 2 {
						t.Errorf("%s: CountNegotiation with %d args", fset.Position(v.Pos()), len(v.Args))
						return true
					}
					if msg := checkNFExpr(v.Args[0], want); msg != "" {
						t.Errorf("%s: features.CountNegotiation: %s", fset.Position(v.Pos()), msg)
					}
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	// AMF and SMF count through their own helpers (CountNegotiation calls);
	// every other adopter through features.Negotiation literals.
	if literals == 0 || counts < 2 {
		t.Fatalf("guard scanned %d Negotiation literals and %d CountNegotiation calls: not scanning the tree", literals, counts)
	}
}
