// log_nf_test.go - guards that every SMF log line carries the "nf" key exactly
// once. cmd/smf/main.go puts nf="SMF" on the root logger; neither Server nor any
// call site may add it again (slog does not de-duplicate keys, so a JSON line
// would carry two "nf" members).
package server

import (
	"encoding/base64"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/francurieses/claudia-5gc/nf/smf/internal/config"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

// TestSMFLogLineCarriesNFOnce builds the logger chain the way main.go + New do
// and captures a real handler log line.
func TestSMFLogLineCarriesNFOnce(t *testing.T) {
	logs := &syncBuffer{}
	root := slog.New(slog.NewJSONHandler(logs, nil)).With("nf", "SMF", "nf_instance_id", "test-instance") // main.go:41
	s, err := New(&config.Config{UEIPPool: "10.60.0.0/24"}, root, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// An Establishment Request on /modify is not a modification and logs a warning
	// from the handler ("no N2SM info and no upCnxState").
	n1 := []byte{nas.PDGroupSessionManagement, 0x01, 0x01, byte(nas.MsgTypePDUSessionEstablishmentRequest)}
	body, _ := json.Marshal(map[string]any{"n1SmMsg": base64.StdEncoding.EncodeToString(n1), "pduSessionId": 1})
	r := httptest.NewRequest(http.MethodPost, "/nsmf-pdusession/v1/sm-contexts/ctx-nf/modify", strings.NewReader(string(body)))
	r.Header.Set("Content-Type", "application/json")
	r.SetPathValue("smContextRef", "ctx-nf")
	s.handleUpdateSMContext(httptest.NewRecorder(), r)

	lines := strings.Split(strings.TrimSpace(logs.String()), "\n")
	if len(lines) == 0 || lines[0] == "" {
		t.Fatal("no log line captured")
	}
	for _, line := range lines {
		if n := strings.Count(line, `"nf":`); n != 1 {
			t.Errorf("log line has %d \"nf\" keys, want exactly 1: %s", n, line)
		}
		if !strings.Contains(line, `"nf":"SMF"`) {
			t.Errorf("log line lacks nf=SMF: %s", line)
		}
	}
}

// TestNoExplicitNFLogAttr fails when production code anywhere under nf/smf
// re-adds the "nf" attribute (the duplicate-key regression). It parses every
// non-test .go file and rejects a call that takes the string literal "nf" as an
// argument (slog.Logger.With/Info/..., slog.String("nf", ...), slog.Any, ...);
// comments, map keys and struct tags cannot match. cmd/smf/main.go is the single
// place allowed to set it on the root logger.
func TestNoExplicitNFLogAttr(t *testing.T) {
	root := filepath.Join("..", "..") // nf/smf
	allowed := filepath.Join(root, "cmd", "smf", "main.go")
	checked := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || path == allowed {
			return nil
		}
		checked++
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			for _, a := range call.Args {
				if lit, ok := a.(*ast.BasicLit); ok && lit.Kind == token.STRING && lit.Value == `"nf"` {
					t.Errorf("%s: adds the nf log attribute explicitly; the root logger in cmd/smf/main.go already carries it", fset.Position(lit.Pos()))
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked < 10 {
		t.Fatalf("walked only %d files under %s; the guard is not looking at nf/smf", checked, root)
	}
	if _, err := os.Stat(allowed); err != nil {
		t.Fatalf("allowed file %s missing: %v", allowed, err)
	}
}
