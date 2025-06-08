// Package main provides the schemapin-keygen CLI tool for generating ECDSA key pairs.
package main

import (
	"fmt"
	"os"

	"github.com/jascha/schemapin-go/internal/version"
)

func main() {
	fmt.Printf("SchemaPin Key Generator v%s\n", version.GetVersion())
	fmt.Println("TODO: Implement key generation CLI with Cobra framework")

	// TODO: Implement CLI with flags:
	// --type: Key type (ecdsa, rsa) [default: ecdsa]
	// --key-size: RSA key size (2048, 3072, 4096) [default: 2048]
	// --output-dir: Output directory [default: current directory]
	// --prefix: Filename prefix [default: schemapin]
	// --developer: Developer name for .well-known template
	// --contact: Contact information
	// --schema-version: Schema version [default: 1.1]
	// --well-known: Generate .well-known template
	// --verbose, -v: Verbose output
	// --quiet, -q: Quiet output
	// --json: JSON output format

	os.Exit(0)
}
