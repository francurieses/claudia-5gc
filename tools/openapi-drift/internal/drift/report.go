package drift

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Header describes the run in the report.
type Header struct {
	Spec    string `json:"spec,omitempty"`
	Profile string `json:"profile,omitempty"`
	Branch  string `json:"branch,omitempty"`
	Commit  string `json:"commit,omitempty"`
}

// Report is the complete result of a run.
type Report struct {
	Header      Header         `json:"header"`
	Findings    []Finding      `json:"findings"`
	Counts      map[string]int `json:"counts"`
	Unannotated []Unannotated  `json:"unannotated,omitempty"`
	// ListUnannotated is true when the unannotated listing was requested.
	ListUnannotated bool `json:"-"`
}

// ReadProvenance reads branch= and commit= from <dir>/UPSTREAM-COMMIT into h.
func ReadProvenance(dir string, h *Header) {
	f, err := os.Open(filepath.Join(dir, "UPSTREAM-COMMIT"))
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		switch k {
		case "branch":
			h.Branch = v
		case "commit":
			h.Commit = v
		}
	}
}

// NewReport sorts findings and computes per-category counts.
func NewReport(h Header, f []Finding) *Report {
	SortFindings(f)
	r := &Report{Header: h, Findings: f, Counts: map[string]int{}}
	for _, c := range Categories {
		r.Counts[c] = 0
	}
	for _, x := range f {
		r.Counts[x.Category]++
	}
	if r.Findings == nil {
		r.Findings = []Finding{}
	}
	return r
}

// Count returns the number of findings whose category is in cats.
func (r *Report) Count(cats map[string]bool) int {
	n := 0
	for _, f := range r.Findings {
		if cats[f.Category] {
			n++
		}
	}
	return n
}

// WriteText writes the deterministic text report.
func (r *Report) WriteText(w io.Writer) {
	h := r.Header
	if h.Spec != "" {
		fmt.Fprintf(w, "openapi-drift report\n  spec:    %s\n  profile: %s\n", h.Spec, h.Profile)
		if h.Branch != "" || h.Commit != "" {
			fmt.Fprintf(w, "  upstream: branch=%s commit=%s\n", h.Branch, h.Commit)
		}
		fmt.Fprintln(w)
		for _, c := range Categories {
			var group []Finding
			for _, f := range r.Findings {
				if f.Category == c {
					group = append(group, f)
				}
			}
			if len(group) == 0 {
				continue
			}
			fmt.Fprintf(w, "[%s] %d\n", c, len(group))
			for _, f := range group {
				loc := f.File
				if f.Line > 0 {
					loc = fmt.Sprintf("%s:%d", f.File, f.Line)
				}
				name := f.Type
				if f.Field != "" {
					name += "." + f.Field
				}
				fmt.Fprintf(w, "  %s %s: %s\n", loc, name, f.Message)
			}
			fmt.Fprintln(w)
		}
		fmt.Fprint(w, "summary:")
		for _, c := range Categories {
			fmt.Fprintf(w, " %s=%d", c, r.Counts[c])
		}
		fmt.Fprintln(w)
	}
	if r.ListUnannotated {
		fmt.Fprintln(w, "unannotated JSON structs:")
		for _, u := range r.Unannotated {
			fmt.Fprintf(w, "  %s:%d %s\n", u.File, u.Line, u.Type)
		}
		fmt.Fprintf(w, "unannotated total: %d\n", len(r.Unannotated))
	}
}

// WriteJSON writes the report as indented JSON.
func (r *Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("drift: encode report: %w", err)
	}
	return nil
}

// WriteMarkdown writes the report as Markdown: a summary table and one
// section per non-empty category.
func (r *Report) WriteMarkdown(w io.Writer) {
	h := r.Header
	if h.Spec != "" {
		fmt.Fprintf(w, "# openapi-drift report\n\n- spec: `%s`\n- profile: `%s`\n", h.Spec, h.Profile)
		if h.Branch != "" || h.Commit != "" {
			fmt.Fprintf(w, "- upstream: branch=%s commit=%s\n", h.Branch, h.Commit)
		}
		fmt.Fprint(w, "\n| category | count |\n|---|---|\n")
		for _, c := range Categories {
			fmt.Fprintf(w, "| %s | %d |\n", c, r.Counts[c])
		}
		for _, c := range Categories {
			var group []Finding
			for _, f := range r.Findings {
				if f.Category == c {
					group = append(group, f)
				}
			}
			if len(group) == 0 {
				continue
			}
			fmt.Fprintf(w, "\n## %s (%d)\n\n", c, len(group))
			for _, f := range group {
				loc := f.File
				if f.Line > 0 {
					loc = fmt.Sprintf("%s:%d", f.File, f.Line)
				}
				name := f.Type
				if f.Field != "" {
					name += "." + f.Field
				}
				fmt.Fprintf(w, "- `%s` `%s`: %s\n", loc, name, f.Message)
			}
		}
	}
	if r.ListUnannotated {
		fmt.Fprint(w, "\n## unannotated JSON structs\n\n")
		for _, u := range r.Unannotated {
			fmt.Fprintf(w, "- `%s:%d` `%s`\n", u.File, u.Line, u.Type)
		}
		fmt.Fprintf(w, "\nunannotated total: %d\n", len(r.Unannotated))
	}
}
