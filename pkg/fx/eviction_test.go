package fx

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/fil-forge/swarf/pkg/store"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// evictingStore reports each EvictExpired call's cutoff, failing the first
// call.
type evictingStore struct {
	store.RevocationStore
	cutoffs chan time.Time
	calls   int
}

func (s *evictingStore) EvictExpired(_ context.Context, before time.Time) (int64, error) {
	s.calls++
	s.cutoffs <- before
	if s.calls == 1 {
		return 0, errors.New("database unavailable")
	}
	return 3, nil
}

func TestRunEvictionEvictsAtStartAndEachInterval(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	revocations := &evictingStore{cutoffs: make(chan time.Time)}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runEviction(ctx, revocations, zap.New(core), time.Millisecond)
	}()

	start := time.Now()
	first := <-revocations.cutoffs
	require.WithinDuration(t, start.Add(-evictionGrace), first, time.Minute, "the cutoff is the grace period ago")
	// A failed eviction does not stop the next one.
	<-revocations.cutoffs
	<-revocations.cutoffs
	cancel()
	<-done

	require.Equal(t, 1, logs.FilterMessage("evicting expired revocations failed").Len())
	evicted := logs.FilterMessage("evicted expired revocations").All()
	require.NotEmpty(t, evicted)
	require.EqualValues(t, 3, evicted[0].ContextMap()["count"])
}
