// Package version provides version information for SchemaPin Go implementation.
package version

// Version is set at build time via ldflags
var Version = "1.1.3"

// GetVersion returns the current version string
func GetVersion() string {
	return Version
}
