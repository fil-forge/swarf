package testutil

import (
	"os"
	"testing"

	docker_client "github.com/docker/docker/client"
)

// IsRunningInCI returns true if the process is running in a CI environment.
func IsRunningInCI(t testing.TB) bool {
	t.Helper()
	return os.Getenv("CI") != ""
}

// IsDockerAvailable returns true if the docker daemon is available, useful for
// skipping tests when docker isn't running.
func IsDockerAvailable(t testing.TB) bool {
	t.Helper()
	c, err := docker_client.NewClientWithOpts(docker_client.FromEnv, docker_client.WithAPIVersionNegotiation())
	if err != nil {
		t.Logf("Docker client not available for test %s: %v", t.Name(), err)
		return false
	}
	_, err = c.Info(t.Context())
	if err != nil {
		t.Logf("Docker not available for test %s: %v", t.Name(), err)
		return false
	}
	return true
}
