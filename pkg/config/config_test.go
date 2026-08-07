package config

import (
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
	require.Equal(t, DefaultPLCDirectory, cfg.Server.PLCDirectory)
}

func TestLoadBindsPLCDirectoryFlag(t *testing.T) {
	flags := pflag.NewFlagSet("serve", pflag.ContinueOnError)
	flags.String("plc-directory", DefaultPLCDirectory, "")
	require.NoError(t, flags.Set("plc-directory", "https://plc.example.com"))

	cfg, err := Load("", flags)
	require.NoError(t, err)
	require.Equal(t, "https://plc.example.com", cfg.Server.PLCDirectory)
}
