// Package assets embeds the compiled React SPA.
// The static/ subdirectory is populated by `npm run build` (Vite).
// If the directory is empty (dev mode), the Go server still starts and
// proxying the Vite dev server is handled via the vite.config.ts proxy.
package assets

import (
	"embed"
	"io/fs"
)

//go:embed all:static
var embeddedFS embed.FS

// FS returns a fs.FS rooted at the embedded static directory.
func FS() fs.FS {
	sub, err := fs.Sub(embeddedFS, "static")
	if err != nil {
		panic("assets: sub static: " + err.Error())
	}
	return sub
}
