package main

import (
	"fmt"
	"os"

	"github.com/fil-forge/swarf/pkg/config"
	appfx "github.com/fil-forge/swarf/pkg/fx"
	"github.com/spf13/cobra"
	"go.uber.org/fx"
)

func main() {
	var configFile string
	root := &cobra.Command{
		Use:   "swarf",
		Short: "Swarf UCAN revocation service",
	}
	serve := &cobra.Command{
		Use:   "serve",
		Short: "Start the Swarf service",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(configFile, cmd.Flags())
			if err != nil {
				return err
			}
			fx.New(appfx.AppModule(cfg)).Run()
			return nil
		},
	}
	serve.Flags().String("identity-key-file", "", "path to the PEM-encoded Ed25519 identity key")
	serve.Flags().String("identity-service-id", "", "optional service DID, such as did:web:swarf.example.com")
	serve.Flags().String("host", "127.0.0.1", "host to bind")
	serve.Flags().Int("port", 8080, "port to bind")
	serve.Flags().Bool("insecure-did-resolution", false, "resolve did:web DIDs over HTTP")
	serve.Flags().String("log-level", "info", "Zap log level")
	serve.Flags().String("storage", "postgres", "storage backend (memory or postgres)")
	serve.Flags().String("postgres-dsn", "", "Postgres connection string")
	serve.Flags().Bool("skip-migrations", false, "skip Postgres migrations on startup")
	root.PersistentFlags().StringVarP(&configFile, "config", "c", "", "configuration file path")
	root.AddCommand(serve)
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
