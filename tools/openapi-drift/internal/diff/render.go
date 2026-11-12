package diff

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

func prov(m map[string]string) string {
	return fmt.Sprintf("branch=%s commit=%s fetched=%s", m["branch"], m["commit"], m["fetched"])
}

func (r *Report) total(k string) int {
	n := 0
	for _, f := range r.Files {
		n += f.Counts[k]
	}
	return n
}

// WriteJSON writes the report as indented JSON.
func (r *Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(map[string]any{
		"old": r.OldDir, "new": r.NewDir, "old_provenance": r.OldProv, "new_provenance": r.NewProv,
		"used_filter": r.Used, "unresolved": nonNil(r.Unresolved), "files_added": r.FilesAdded, "files_removed": r.FilesRemoved, "files": r.Files,
	})
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (r *Report) skippedCount() int {
	n := 0
	for _, f := range r.Files {
		n += len(f.Skipped)
	}
	return n
}

// WriteText writes a plain-text report.
func (r *Report) WriteText(w io.Writer) {
	fmt.Fprintf(w, "old: %s (%s)\nnew: %s (%s)\nused-filter: %v\n", r.OldDir, prov(r.OldProv), r.NewDir, prov(r.NewProv), r.Used)
	fmt.Fprintf(w, "files added: %d, removed: %d, compared: %d\n", len(r.FilesAdded), len(r.FilesRemoved), len(r.Files))
	for _, f := range r.Files {
		if len(f.Changes) == 0 && f.OldVersion == f.NewVersion {
			continue
		}
		fmt.Fprintf(w, "\n%s  %s -> %s\n", f.File, f.OldVersion, f.NewVersion)
		for _, c := range f.Changes {
			fmt.Fprintf(w, "  %-16s %s\n", c.Kind, c.target())
		}
	}
	fmt.Fprintf(w, "\nskipped schemas: %d\n", r.skippedCount())
	for _, f := range r.Files {
		for _, s := range f.Skipped {
			fmt.Fprintf(w, "  %s %s: %s\n", f.File, s.Schema, s.Error)
		}
	}
	fmt.Fprintf(w, "unresolved refs: %d\n", len(r.Unresolved))
	for _, u := range r.Unresolved {
		fmt.Fprintf(w, "  %s\n", u)
	}
}

func (c Change) target() string {
	t := c.Schema
	if c.Prop != "" {
		t += "." + c.Prop
	}
	if c.Detail != "" {
		t += "  " + c.Detail
	}
	return strings.TrimSpace(t)
}

// WriteMarkdown writes the report as markdown. When directOnly is true the
// per-change detail is limited to annotated schemas and transitive ones are
// summarised by count.
func (r *Report) WriteMarkdown(w io.Writer, directOnly bool) {
	fmt.Fprintf(w, "- Old: `%s` — %s\n- New: `%s` — %s\n- Filter: %s\n\n", r.OldDir, prov(r.OldProv), r.NewDir, prov(r.NewProv),
		map[bool]string{true: "used APIs only (`-used`)", false: "none (all APIs)"}[r.Used])
	fmt.Fprintf(w, "Files only in new: %d; only in old: %d; compared: %d.\n\n", len(r.FilesAdded), len(r.FilesRemoved), len(r.Files))

	fmt.Fprintln(w, "## Summary per API")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "| YAML | Old | New | Major | Add opt | Add mand | Became req | Removed | Enum ext | Type chg | Schemas +/- |")
	fmt.Fprintln(w, "|---|---|---|---|---|---|---|---|---|---|---|")
	for _, f := range r.Files {
		maj := "no"
		if f.Major {
			maj = "**YES**"
		}
		c := f.Counts
		fmt.Fprintf(w, "| %s | %s | %s | %s | %d | %d | %d | %d | %d | %d | %d/%d |\n", f.File, f.OldVersion, f.NewVersion, maj,
			c[KAddedOptional], c[KAddedMandatory], c[KBecameRequired], c[KRemoved], c[KEnumAdded], c[KTypeChanged],
			c[KSchemaAdded], c[KSchemaRemoved])
	}
	fmt.Fprintf(w, "| **Total** | | | | %d | %d | %d | %d | %d | %d | %d/%d |\n\n", r.total(KAddedOptional), r.total(KAddedMandatory),
		r.total(KBecameRequired), r.total(KRemoved), r.total(KEnumAdded), r.total(KTypeChanged), r.total(KSchemaAdded), r.total(KSchemaRemoved))

	fmt.Fprintln(w, "## Major version bumps")
	fmt.Fprintln(w)
	n := 0
	for _, f := range r.Files {
		if f.Major {
			n++
			fmt.Fprintf(w, "- %s: %s\n", f.File, f.Changes[0].Detail)
		}
	}
	if n == 0 {
		fmt.Fprintln(w, "None. No compared API changed its `info.version` major or its `/vN` URI major.")
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "## Per-API detail")
	for _, f := range r.Files {
		var cs []Change
		for _, c := range f.Changes {
			if c.Kind != KMajorBump {
				cs = append(cs, c)
			}
		}
		if len(cs) == 0 {
			continue
		}
		fmt.Fprintf(w, "\n### %s (%s -> %s)\n\n", f.File, f.OldVersion, f.NewVersion)
		hidden := map[string]int{}
		for _, k := range Kinds {
			var lines []string
			for _, c := range cs {
				if c.Kind != k {
					continue
				}
				if directOnly && !c.Direct {
					hidden[k]++
					continue
				}
				lines = append(lines, "`"+c.target()+"`")
			}
			if len(lines) > 0 {
				fmt.Fprintf(w, "- **%s** (%d): %s\n", k, len(lines), strings.Join(lines, "; "))
			}
		}
		if len(hidden) > 0 {
			var parts []string
			for _, k := range Kinds {
				if hidden[k] > 0 {
					parts = append(parts, fmt.Sprintf("%s %d", k, hidden[k]))
				}
			}
			fmt.Fprintf(w, "- transitive (not annotated) schemas, counts only: %s\n", strings.Join(parts, ", "))
		}
	}
	if len(r.FilesAdded)+len(r.FilesRemoved) > 0 {
		fmt.Fprintf(w, "\n## Files added / removed (used set)\n\n- added: %s\n- removed: %s\n", strings.Join(r.FilesAdded, ", "), strings.Join(r.FilesRemoved, ", "))
	}

	fmt.Fprintf(w, "\n## Skipped schemas\n\n")
	if n := r.skippedCount(); n == 0 {
		fmt.Fprintln(w, "None (0). Every schema present in both releases was compared.")
	} else {
		fmt.Fprintf(w, "%d schema(s) present in both releases could not be resolved or flattened and were not compared:\n\n", n)
		for _, f := range r.Files {
			for _, s := range f.Skipped {
				fmt.Fprintf(w, "- `%s` `%s`: %s\n", f.File, s.Schema, s.Error)
			}
		}
	}
	fmt.Fprintf(w, "\n## Unresolved references\n\n")
	if len(r.Unresolved) == 0 {
		fmt.Fprintln(w, "None (0).")
	} else {
		fmt.Fprintf(w, "%d seed(s) or `$ref` target(s) could not be resolved in any release:\n\n", len(r.Unresolved))
		for _, u := range r.Unresolved {
			fmt.Fprintf(w, "- `%s`\n", u)
		}
	}
}
