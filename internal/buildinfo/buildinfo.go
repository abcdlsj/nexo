// Package buildinfo carries version data injected at build time with
// -ldflags "-X github.com/abcdlsj/nexo/internal/buildinfo.Version=...".
// A fleet coordinator compares these values to surface version skew.
package buildinfo

import (
	"fmt"
	"runtime"
)

var (
	// Version is the release or tag name; "dev" for local builds.
	Version = "dev"
	// Commit is the short commit hash the binary was built from.
	Commit = "none"
	// Date is the build date in RFC 3339 form.
	Date = "unknown"
)

// String renders a compact one-line description.
func String() string {
	return fmt.Sprintf("nexo %s (commit %s, built %s, %s)", Version, Commit, Date, runtime.Version())
}
