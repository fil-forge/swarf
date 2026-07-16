// Package config loads Swarf service configuration.
package config

import (
	"fmt"
	"strings"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	StorageTypeMemory   = "memory"
	StorageTypePostgres = "postgres"
)

type Config struct {
	Identity IdentityConfig `mapstructure:"identity"`
	Server   ServerConfig   `mapstructure:"server"`
	Log      LogConfig      `mapstructure:"log"`
	Storage  StorageConfig  `mapstructure:"storage"`
}

type IdentityConfig struct {
	KeyFile   string `mapstructure:"key_file"`
	ServiceID string `mapstructure:"service_id"`
}

type ServerConfig struct {
	Host                  string `mapstructure:"host"`
	Port                  int    `mapstructure:"port"`
	InsecureDIDResolution bool   `mapstructure:"insecure_did_resolution"`
}

type LogConfig struct {
	Level string `mapstructure:"level"`
}

type StorageConfig struct {
	Type     string         `mapstructure:"type"`
	Postgres PostgresConfig `mapstructure:"postgres"`
}

type PostgresConfig struct {
	DSN            string `mapstructure:"dsn"`
	MaxConns       int32  `mapstructure:"max_conns"`
	MinConns       int32  `mapstructure:"min_conns"`
	SkipMigrations bool   `mapstructure:"skip_migrations"`
}

var flagBindings = map[string]string{
	"identity.key_file":                "identity-key-file",
	"identity.service_id":              "identity-service-id",
	"server.host":                      "host",
	"server.port":                      "port",
	"server.insecure_did_resolution":   "insecure-did-resolution",
	"log.level":                        "log-level",
	"storage.type":                     "storage",
	"storage.postgres.dsn":             "postgres-dsn",
	"storage.postgres.skip_migrations": "skip-migrations",
}

func Load(configFile string, flags *pflag.FlagSet) (*Config, error) {
	v := viper.New()
	v.SetDefault("server.host", "127.0.0.1")
	v.SetDefault("server.port", 8080)
	v.SetDefault("log.level", "info")
	v.SetDefault("storage.type", StorageTypePostgres)
	v.SetDefault("storage.postgres.max_conns", 10)
	v.SetDefault("storage.postgres.min_conns", 0)
	v.SetEnvPrefix("SWARF")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	for key, flag := range flagBindings {
		if err := v.BindEnv(key); err != nil {
			return nil, fmt.Errorf("binding environment for %s: %w", key, err)
		}
		if flags != nil && flags.Lookup(flag) != nil {
			if err := v.BindPFlag(key, flags.Lookup(flag)); err != nil {
				return nil, fmt.Errorf("binding flag %s: %w", flag, err)
			}
		}
	}
	if configFile != "" {
		v.SetConfigFile(configFile)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("reading config file: %w", err)
		}
	} else {
		v.SetConfigName("config")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		v.AddConfigPath("/etc/swarf")
		if err := v.ReadInConfig(); err != nil {
			if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
				return nil, fmt.Errorf("reading config file: %w", err)
			}
		}
	}
	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshaling config: %w", err)
	}
	return &cfg, nil
}
