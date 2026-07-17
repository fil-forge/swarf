package integration

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/fil-forge/libforge/identity"
	"github.com/fil-forge/swarf/internal/testutil"
	swarfclient "github.com/fil-forge/swarf/pkg/client"
	"github.com/fil-forge/swarf/pkg/config"
	appfx "github.com/fil-forge/swarf/pkg/fx"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.uber.org/fx"
	"go.uber.org/fx/fxtest"
)

func TestRevocationHappyPath(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	if testutil.IsRunningInCI(t) && runtime.GOOS == "linux" {
		if !testutil.IsDockerAvailable(t) {
			t.Fatalf("docker is expected in CI linux testing environments, but wasn't found")
		}
	}
	if !testutil.IsDockerAvailable(t) {
		t.SkipNow()
	}
	ctx := t.Context()
	container, err := tcpostgres.Run(ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase("swarf"),
		tcpostgres.WithUsername("swarf"),
		tcpostgres.WithPassword("swarf"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	require.NoError(t, err)
	testcontainers.CleanupContainer(t, container)
	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	serviceSigner, err := ed25519.Generate()
	require.NoError(t, err)
	serviceIssuer := multikey.KeyIssuer(serviceSigner)
	keyFile := filepath.Join(t.TempDir(), "service.pem")
	pem, err := identity.EncodeSignerToPEM(serviceSigner)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(keyFile, pem, 0o600))
	port := freePort(t)
	app := fxtest.New(t, appfx.AppModule(&config.Config{
		Identity: config.IdentityConfig{KeyFile: keyFile},
		Server:   config.ServerConfig{Host: "127.0.0.1", Port: port},
		Log:      config.LogConfig{Level: "error"},
		Storage: config.StorageConfig{
			Type: config.StorageTypePostgres,
			Postgres: config.PostgresConfig{
				DSN: dsn,
			},
		},
	}), fx.NopLogger)
	app.RequireStart()
	t.Cleanup(app.RequireStop)

	serviceURL, err := url.Parse("http://127.0.0.1:" + portString(port))
	require.NoError(t, err)
	alice, err := ed25519.GenerateIssuer()
	require.NoError(t, err)
	bob, err := ed25519.GenerateIssuer()
	require.NoError(t, err)
	carol, err := ed25519.GenerateIssuer()
	require.NoError(t, err)
	client, err := swarfclient.New(serviceIssuer.DID(), *serviceURL, bob)
	require.NoError(t, err)

	first := revocationPath(t, alice, bob, carol)
	require.NoError(t, client.Publish(ctx, first[len(first)-1].Link(), first))
	record, err := client.Get(ctx, first[len(first)-1].Link())
	require.NoError(t, err)
	require.NotNil(t, record.Cause)
	require.Equal(t, first[len(first)-1].Link(), record.Revoke)
	require.Equal(t, first[len(first)-1].Link(), record.Path[len(record.Path)-1].Link())

	second := revocationPath(t, alice, bob, carol)
	expected := second[len(second)-1].Link()
	streamCtx, cancelStream := context.WithCancel(ctx)
	defer cancelStream()
	records := make(chan error, 1)
	go func() {
		for record, err := range client.Stream(streamCtx, record.CreatedAt) {
			if err != nil {
				records <- err
				return
			}
			if record.Revoke != expected {
				records <- errors.New("stream returned an unexpected revocation")
				return
			}
			records <- nil
			return
		}
	}()
	require.NoError(t, client.Publish(ctx, expected, second))
	select {
	case err := <-records:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		require.Fail(t, "timed out waiting for streamed revocation")
	}
}

func revocationPath(t *testing.T, alice, bob, carol ucan.Issuer) []ucan.Delegation {
	t.Helper()
	command, err := command.Parse("/test/invoke")
	require.NoError(t, err)
	authority, err := delegation.Delegate(alice, bob.DID(), alice.DID(), command)
	require.NoError(t, err)
	target, err := delegation.Delegate(bob, carol.DID(), alice.DID(), command)
	require.NoError(t, err)
	return []ucan.Delegation{authority, target}
}

func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func portString(port int) string {
	return fmt.Sprintf("%d", port)
}
