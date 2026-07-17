//go:generate go run -tags codegen .

package main

import (
	"os"

	jsg "github.com/alanshaw/dag-json-gen"
	"github.com/fil-forge/swarf/pkg/api"
)

const buildTag = "//go:build !codegen\n\n"

func main() {
	const output = "../json_gen.go"
	if err := jsg.WriteMapEncodersToFile(output, "api", api.Revocation{}, api.FirehoseRevocation{}); err != nil {
		panic(err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(output, append([]byte(buildTag), data...), 0644); err != nil {
		panic(err)
	}
}
