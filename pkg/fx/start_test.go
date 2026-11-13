package fx

import (
	"testing"

	"github.com/fil-forge/swarf/pkg/config"
	"github.com/stretchr/testify/require"
	"go.uber.org/fx"
)

// The app gives its OnStart hooks minutes, not fx's default 15 seconds, so a
// slow schema migration finishes instead of being canceled.
func TestAppStartTimeoutLeavesTimeForMigrations(t *testing.T) {
	cfg := &config.Config{}
	cfg.Storage.Type = config.StorageTypeMemory
	app := fx.New(AppModule(cfg), fx.NopLogger)
	require.Equal(t, startTimeout, app.StartTimeout())
}
