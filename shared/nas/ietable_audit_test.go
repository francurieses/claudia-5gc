package nas_test

// ietable_audit_test.go — TestConformanceAudit: every decoder that parses the
// non-imperative part of a message with an IE table must skip unhandled IEs
// through the table (Reader.skipIE), not through an ad-hoc length guess.
// The audit parses the package source, so a new decoder that bypasses the
// table, or a registered table that no decoder uses, fails the build.
// Ref: TS 24.007 §11.2.4, TS 24.501 §7.6.1

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"strings"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/nas"
)

// auditedDecoders maps each decoder function to the IE table it must consult.
var auditedDecoders = map[string]nas.IEMessage{
	"DecodeRegistrationRequest":            nas.IEMsgRegistrationRequest,
	"DecodeRegistrationAccept":             nas.IEMsgRegistrationAccept,
	"DecodePDUSessionEstablishmentRequest": nas.IEMsgPDUSessionEstablishmentRequest,
	"DecodeServiceRequest":                 nas.IEMsgServiceRequest,
	"DecodeServiceAccept":                  nas.IEMsgServiceAccept,
	"DecodeConfigurationUpdateCommand":     nas.IEMsgConfigurationUpdateCommand,
	"DecodeULNASTransport":                 nas.IEMsgULNASTransport,
	"DecodeAuthenticationRequest":          nas.IEMsgAuthenticationRequest,
	"DecodeAuthenticationResponse":         nas.IEMsgAuthenticationResponse,
	"DecodeSecurityModeCommand":            nas.IEMsgSecurityModeCommand,
	"DecodeSecurityModeComplete":           nas.IEMsgSecurityModeComplete,
}

// noDecoder lists registered tables without a decoder in this package: the AMF
// only encodes DL NAS Transport, the table documents Table 8.2.11.1.1.
var noDecoder = map[nas.IEMessage]string{
	nas.IEMsgDLNASTransport: "DL NAS Transport is encode-only (AMF to UE)",
}

func TestConformanceAudit(t *testing.T) {
	fset := token.NewFileSet()
	// ParseDir is deprecated for build-tag awareness only; shared/nas has no tagged files.
	pkgs, err := parser.ParseDir( //nolint:staticcheck // SA1019: package has no build-tagged files
		fset, ".", func(fi fs.FileInfo) bool {
			return !strings.HasSuffix(fi.Name(), "_test.go")
		}, 0)
	if err != nil {
		t.Fatalf("parse package: %v", err)
	}
	pkg := pkgs["nas"]
	if pkg == nil {
		t.Fatal("package nas not found")
	}

	skips := map[string]map[string]bool{} // decoder -> IEMsg constants passed to skipIE
	declared := map[string]bool{}         // IEMsg constants declared in the package
	for fname, f := range pkg.Files {
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				if d.Tok != token.CONST || !strings.HasSuffix(fname, "ietable.go") {
					continue
				}
				for _, sp := range d.Specs {
					for _, n := range sp.(*ast.ValueSpec).Names {
						if strings.HasPrefix(n.Name, "IEMsg") {
							declared[n.Name] = true
						}
					}
				}
			case *ast.FuncDecl:
				if d.Recv != nil || d.Body == nil {
					continue
				}
				ast.Inspect(d.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok || len(call.Args) == 0 {
						return true
					}
					sel, ok := call.Fun.(*ast.SelectorExpr)
					if !ok || sel.Sel.Name != "skipIE" {
						return true
					}
					if id, ok := call.Args[0].(*ast.Ident); ok {
						if skips[d.Name.Name] == nil {
							skips[d.Name.Name] = map[string]bool{}
						}
						skips[d.Name.Name][id.Name] = true
					}
					return true
				})
			}
		}
	}

	// 1. Every audited decoder skips through its own table.
	for fn, msg := range auditedDecoders {
		want := "IEMsg" + string(msg)
		if !skips[fn][want] {
			t.Errorf("%s does not call skipIE(%s): unknown IEs must go through the IE table", fn, want)
		}
	}
	// 2. Every declared table is either audited or explicitly exempt.
	audited := map[string]bool{}
	for _, msg := range auditedDecoders {
		audited["IEMsg"+string(msg)] = true
	}
	for c := range declared {
		_, exempt := noDecoder[nas.IEMessage(strings.TrimPrefix(c, "IEMsg"))]
		if !audited[c] && !exempt {
			t.Errorf("%s is declared but no audited decoder uses it", c)
		}
	}
	// 3. Every registered table is non-empty.
	for _, msg := range auditedDecoders {
		if len(nas.IETable(msg)) == 0 {
			t.Errorf("%s: empty IE table", msg)
		}
	}
	for msg, why := range noDecoder {
		if len(nas.IETable(msg)) == 0 {
			t.Errorf("%s: empty IE table (%s)", msg, why)
		}
	}
}
