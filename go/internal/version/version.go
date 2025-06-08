// Package version provides version information for SchemaPin Go implementation.
package version

// Version is set at build time via ldflags
var Version = "dev"

// GetVersion returns the current version string
func GetVersion() string {
	return Version
}