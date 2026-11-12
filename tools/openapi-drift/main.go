// Command openapi-drift checks hand-written Go SBI types against the 3GPP
// OpenAPI YAML (checker, not a code generator).
//
// Usage:
//
//	openapi-drift -spec specs/3gpp-openapi/Rel-19 [flags] ./nf/... ./shared/...
//	openapi-drift -unannotated [-scope REGEXP] ./nf/... ./shared/...
//
// A struct type is linked to a schema with a doc comment line
//
//	// oapi: TS29502_Nsmf_PDUSession.yaml#/components/schemas/SmContextCreateData
//
// (type doc, single-spec GenDecl doc, or trailing comment). Internal-only JSON
// structs opt out with "// oapi: none <reason>".
//
// Flags:
//
//	-spec DIR        spec directory (from `make sync-openapi REL=<Rel-NN>`)
//	-profile P       apiversion column: rel17|rel19 (default: from the spec
//	                 dir name; Rel-18 and above use rel19, else rel17)
//	-fail-on LIST    comma list of categories, or "all" (all excludes
//	                 "extension", which fails a run only when named):
//	                 exit 1 if any such finding exists (default: report mode, always exit 0)
//	-unannotated     list JSON-tagged structs without an oapi: line
//	-scope REGEXP    directories considered by -unannotated
//	                 (default /internal/(sbi|server)(/|$))
//	-format F        text (default), json or md
//	-diff OLD NEW    compare two release directories (component schemas:
//	                 added/removed/re-typed properties, optional vs mandatory,
//	                 enum extensions, major version bumps); takes the next two
//	                 arguments, e.g.
//	                 -diff specs/3gpp-openapi/Rel-17 specs/3gpp-openapi/Rel-19 -used ./nf/... ./shared/...
//	-used            with -diff: restrict to YAML files and schemas annotated
//	                 with "// oapi:" in the scanned packages (plus their $ref
//	                 closure) and the files listed in shared/sbi/apiversion;
//	                 remaining arguments are package patterns
//	-detail D        md only (error otherwise): all (default) or direct (full detail only for
//	                 annotated schemas, transitive ones summarised by count)
//
// Finding categories: bad-annotation, unresolved-ref, missing-mandatory,
// unknown-attr, type-mismatch, version-drift, missing-yaml.
//
// Exit codes: 0 run succeeded (and no -fail-on category hit), 1 -fail-on
// category hit, 2 usage or configuration error (bad flag, unknown category,
// missing spec directory).
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/francurieses/claudia-5gc/shared/sbi/apiversion"
	"github.com/francurieses/claudia-5gc/tools/openapi-drift/internal/diff"
	"github.com/francurieses/claudia-5gc/tools/openapi-drift/internal/drift"
	"github.com/francurieses/claudia-5gc/tools/openapi-drift/internal/oapi"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

var relDir = regexp.MustCompile(`^Rel-(\d+)$`)

func run(args []string, stdout, stderr io.Writer) int {
	var diffOld, diffNew string
	if rest, o, n, ok := extractDiff(args); ok {
		args, diffOld, diffNew = rest, o, n
	} else if ok2 := hasFlag(args, "diff"); ok2 {
		fmt.Fprintln(stderr, "openapi-drift: -diff needs two arguments: OLD_DIR NEW_DIR")
		return 2
	}
	fs := flag.NewFlagSet("openapi-drift", flag.ContinueOnError)
	fs.SetOutput(stderr)
	spec := fs.String("spec", "", "spec directory, e.g. specs/3gpp-openapi/Rel-19")
	profile := fs.String("profile", "", "apiversion profile rel17|rel19 (default: from spec dir name)")
	failOn := fs.String("fail-on", "", "comma list of categories or 'all'")
	unann := fs.Bool("unannotated", false, "list JSON structs lacking an oapi: annotation")
	scopeS := fs.String("scope", drift.DefaultScope, "directory regexp for -unannotated")
	format := fs.String("format", "text", "text|json|md")
	used := fs.Bool("used", false, "with -diff: restrict to APIs/schemas used by the scanned Go packages")
	detail := fs.String("detail", "all", "md only: all|direct")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if diffOld != "" {
		if *spec != "" {
			fmt.Fprintln(stderr, "openapi-drift: -diff cannot be combined with -spec")
			return 2
		}
		return runDiff(diffOld, diffNew, *used, *format, *detail, fs.Args(), stdout, stderr)
	}
	if *spec == "" && !*unann {
		fmt.Fprintln(stderr, "openapi-drift: -spec is required (or use -unannotated)")
		return 2
	}
	if *format != "text" && *format != "json" && *format != "md" {
		fmt.Fprintf(stderr, "openapi-drift: unknown -format %q (want text, json or md)\n", *format)
		return 2
	}
	scope, err := regexp.Compile(*scopeS)
	if err != nil {
		fmt.Fprintf(stderr, "openapi-drift: bad -scope: %v\n", err)
		return 2
	}
	failCats := map[string]bool{}
	if *failOn != "" {
		valid := map[string]bool{}
		for _, c := range drift.Categories {
			valid[c] = true
		}
		for _, c := range strings.Split(*failOn, ",") {
			c = strings.TrimSpace(c)
			switch {
			case c == "all":
				for k := range valid {
					if k == drift.CatExtension {
						continue // not part of "all"; fails only when named explicitly
					}
					failCats[k] = true
				}
			case valid[c]:
				failCats[c] = true
			default:
				fmt.Fprintf(stderr, "openapi-drift: unknown category %q in -fail-on\n", c)
				return 2
			}
		}
	}
	prof := *profile
	if prof != "" && prof != apiversion.ProfileRel17 && prof != apiversion.ProfileRel19 {
		fmt.Fprintf(stderr, "openapi-drift: unknown -profile %q (want rel17 or rel19)\n", prof)
		return 2
	}
	if prof == "" && *spec != "" {
		prof = apiversion.ProfileRel19
		if m := relDir.FindStringSubmatch(filepath.Base(filepath.Clean(*spec))); m != nil {
			if n, _ := strconv.Atoi(m[1]); n < 18 {
				prof = apiversion.ProfileRel17
			}
		}
	}
	patterns := fs.Args()
	if len(patterns) == 0 {
		patterns = []string{"./..."}
	}

	var loader *oapi.Loader
	if *spec != "" {
		if !oapi.HasYAML(*spec) {
			hint := "make sync-openapi REL=<Rel-NN>"
			if b := filepath.Base(filepath.Clean(*spec)); relDir.MatchString(b) {
				hint = "make sync-openapi REL=" + b
			}
			fmt.Fprintf(stderr, "openapi-drift: spec dir %q is missing or has no *.yaml files; fetch it with: %s\n", *spec, hint)
			return 2
		}
		loader = oapi.NewLoader(*spec)
	}
	dirs, err := drift.ExpandPatterns(patterns)
	if err != nil {
		fmt.Fprintln(stderr, "openapi-drift:", err)
		return 2
	}
	pkgs, err := drift.ScanDirs(dirs)
	if err != nil {
		fmt.Fprintln(stderr, "openapi-drift:", err)
		return 2
	}

	var h drift.Header
	var findings []drift.Finding
	if loader != nil {
		h = drift.Header{Spec: *spec, Profile: prof}
		drift.ReadProvenance(*spec, &h)
		findings = append(findings, drift.CheckStructs(loader, pkgs)...)
		findings = append(findings, drift.CheckVersions(loader, apiversion.All(), prof)...)
	}
	rep := drift.NewReport(h, findings)
	if *unann {
		rep.ListUnannotated = true
		rep.Unannotated = drift.FindUnannotated(pkgs, scope)
	}
	switch *format {
	case "json":
		if err := rep.WriteJSON(stdout); err != nil {
			fmt.Fprintln(stderr, "openapi-drift:", err)
			return 2
		}
	case "md":
		rep.WriteMarkdown(stdout)
	default:
		rep.WriteText(stdout)
	}
	if len(failCats) > 0 && rep.Count(failCats) > 0 {
		return 1
	}
	return 0
}

// extractDiff removes "-diff OLD NEW" from args (the flag package cannot take
// two values).
func extractDiff(args []string) (rest []string, oldDir, newDir string, ok bool) {
	for i, a := range args {
		if (a == "-diff" || a == "--diff") && i+2 < len(args) && !strings.HasPrefix(args[i+1], "-") && !strings.HasPrefix(args[i+2], "-") {
			rest = append(rest, args[:i]...)
			rest = append(rest, args[i+3:]...)
			return rest, args[i+1], args[i+2], true
		}
	}
	return args, "", "", false
}

func hasFlag(args []string, name string) bool {
	for _, a := range args {
		if a == "-"+name || a == "--"+name {
			return true
		}
	}
	return false
}

func runDiff(oldDir, newDir string, used bool, format, detail string, patterns []string, stdout, stderr io.Writer) int {
	if format != "text" && format != "json" && format != "md" {
		fmt.Fprintf(stderr, "openapi-drift: unknown -format %q (want text, json or md)\n", format)
		return 2
	}
	if detail != "all" && detail != "direct" {
		fmt.Fprintf(stderr, "openapi-drift: unknown -detail %q (want all or direct)\n", detail)
		return 2
	}
	if detail == "direct" && format != "md" {
		fmt.Fprintln(stderr, "openapi-drift: -detail direct applies to -format md only")
		return 2
	}
	var u *diff.Used
	if used {
		if len(patterns) == 0 {
			patterns = []string{"./..."}
		}
		dirs, err := drift.ExpandPatterns(patterns)
		if err != nil {
			fmt.Fprintln(stderr, "openapi-drift:", err)
			return 2
		}
		pkgs, err := drift.ScanDirs(dirs)
		if err != nil {
			fmt.Fprintln(stderr, "openapi-drift:", err)
			return 2
		}
		for _, d := range []string{oldDir, newDir} {
			if !oapi.HasYAML(d) {
				fmt.Fprintf(stderr, "openapi-drift: spec dir %q is missing or has no *.yaml files\n", d)
				return 2
			}
		}
		seeds := drift.AnnotatedRefs(pkgs)
		schemas, unresolved := diff.Closure(seeds, oapi.NewLoader(oldDir), oapi.NewLoader(newDir))
		for _, m := range unresolved {
			fmt.Fprintln(stderr, "openapi-drift: warning: unresolved:", m)
		}
		u = &diff.Used{Schemas: schemas, Unresolved: unresolved,
			Direct: map[string]map[string]bool{}, Files: map[string]bool{}}
		for _, s := range seeds {
			f, ptr, err := oapi.SplitRef(s)
			if err != nil || len(ptr) != 3 {
				continue
			}
			f = filepath.Clean(f)
			if u.Direct[f] == nil {
				u.Direct[f] = map[string]bool{}
			}
			u.Direct[f][ptr[2]] = true
		}
		for _, e := range apiversion.All() {
			u.Files[e.YAML+".yaml"] = true
		}
	}
	rep, err := diff.Compare(oldDir, newDir, u)
	if err != nil {
		fmt.Fprintln(stderr, "openapi-drift:", err)
		return 2
	}
	switch format {
	case "json":
		if err := rep.WriteJSON(stdout); err != nil {
			fmt.Fprintln(stderr, "openapi-drift:", err)
			return 2
		}
	case "md":
		rep.WriteMarkdown(stdout, detail == "direct")
	default:
		rep.WriteText(stdout)
	}
	return 0
}
