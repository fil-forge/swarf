package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"
)

func TestLoadAppliesDefaultsAndFlags(t *testing.T) {
	flags := pflag.NewFlagSet("serve", pflag.ContinueOnError)
	flags.String("storage", StorageTypePostgres, "")
	flags.String("postgres-dsn", "", "")
	flags.Int("port", 8080, "")
	require.NoError(t, flags.Set("storage", StorageTypeMemory))
	require.NoError(t, flags.Set("port", "9090"))

	cfg, err := Load("", flags)
	require.NoError(t, err)
	require.Equal(t, StorageTypeMemory, cfg.Storage.Type)
	require.Equal(t, 9090, cfg.Server.Port)
	require.Equal(t, "127.0.0.1", cfg.Server.Host)
	require.Equal(t, DefaultPLCDirectory, cfg.PLC.Directory)
}

func TestLoadBindsPLCDirectoryFlag(t *testing.T) {
	flags := pflag.NewFlagSet("serve", pflag.ContinueOnError)
	flags.String("plc-directory", DefaultPLCDirectory, "")
	require.NoError(t, flags.Set("plc-directory", "https://plc.example.com"))

	cfg, err := Load("", flags)
	require.NoError(t, err)
	require.Equal(t, "https://plc.example.com", cfg.PLC.Directory)
}

func TestLoadReadsPrincipalPublishersFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	contents := "principal:\n  publishers:\n    - did:web:auth.example.com\n    - did:key:z6Mk\n"
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))

	cfg, err := Load(path, nil)
	require.NoError(t, err)
	require.Equal(t, []string{"did:web:auth.example.com", "did:key:z6Mk"}, cfg.Principal.Publishers)
}

func TestLoadBindsPrincipalPublishersFlag(t *testing.T) {
	flags := pflag.NewFlagSet("serve", pflag.ContinueOnError)
	flags.StringSlice("principal-publishers", nil, "")
	require.NoError(t, flags.Set("principal-publishers", "did:web:auth.example.com,did:web:auth.other.com"))

	cfg, err := Load("", flags)
	require.NoError(t, err)
	require.Equal(t, []string{"did:web:auth.example.com", "did:web:auth.other.com"}, cfg.Principal.Publishers)
}

func TestLoadReadsPrincipalPublishersFromEnvironment(t *testing.T) {
	t.Setenv("SWARF_PRINCIPAL_PUBLISHERS", "did:web:auth.example.com,did:web:auth.other.com")

	cfg, err := Load("", nil)
	require.NoError(t, err)
	require.Equal(t, []string{"did:web:auth.example.com", "did:web:auth.other.com"}, cfg.Principal.Publishers)
}
