// Package build provides version metadata for the running binary.
package build

import (
	"encoding/json"
	"fmt"
	"os"
)

var (
	version string
	Version string
	Commit  = "unknown"
	Date    = "unknown"
	BuiltBy = "unknown"
)

const (
	defaultVersion = "v0.0.0"
	versionFile    = "version.json"
)

func init() {
	if version == "" {
		var err error
		version, err = readVersionFromFile()
		if err != nil {
			version = defaultVersion
		}
	}
	Version = fmt.Sprintf("%s-%s", version, revision)
}

func readVersionFromFile() (string, error) {
	file, err := os.Open(versionFile)
	if err != nil {
		return "", err
	}
	defer file.Close()

	var value struct {
		Version string `json:"version"`
	}
	if err := json.NewDecoder(file).Decode(&value); err != nil {
		return "", err
	}
	return value.Version, nil
}
