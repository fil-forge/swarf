package memory_test

import (
	"context"
	"iter"
	"testing"
	"time"

	"github.com/fil-forge/swarf/pkg/store"
	"github.com/fil-forge/swarf/pkg/store/memory"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/stretchr/testify/require"
)

func TestMemoryRevocationStoreGet(t *testing.T) {
	store := memory.New()
	revocation, path := revocationPath(t)

	add(t, store, revocation, path)

	record, err := store.Get(context.Background(), path[len(path)-1].Link())
	require.NoError(t, err)
	require.Equal(t, path[len(path)-1].Link(), record.Revoke)
	require.Equal(t, revocation.Link(), record.Cause.Link())
	require.Len(t, record.Path, len(path))
	require.Equal(t, path[0].Link(), record.Path[0].Link())
	require.False(t, record.RecordedAt.IsZero())

	record.Path[0] = nil
	again, err := store.Get(context.Background(), path[len(path)-1].Link())
	require.NoError(t, err)
	require.NotNil(t, again.Path[0])
}

func TestMemoryRevocationStoreGetNotFound(t *testing.T) {
	s := memory.New()
	_, path := revocationPath(t)

	_, err := s.Get(context.Background(), path[0].Link())
	require.ErrorIs(t, err, store.ErrNotFound)
}

func TestMemoryRevocationStoreStream(t *testing.T) {
	s := memory.New()
	firstRevocation, firstPath := revocationPath(t)
	add(t, s, firstRevocation, firstPath)
	first, err := s.Get(context.Background(), firstPath[len(firstPath)-1].Link())
	require.NoError(t, err)

	secondRevocation, secondPath := revocationPath(t)
	add(t, s, secondRevocation, secondPath)

	ctx, cancel := context.WithCancel(context.Background())
	records, done := collectStream(s.Stream(ctx, time.Time{}))
	require.Equal(t, firstRevocation.Link(), (<-records).Cause().Link())
	require.Equal(t, secondRevocation.Link(), (<-records).Cause().Link())

	thirdRevocation, thirdPath := revocationPath(t)
	add(t, s, thirdRevocation, thirdPath)
	require.Equal(t, thirdRevocation.Link(), (<-records).Cause().Link())
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)

	// The from filter is inclusive: the record recorded at exactly from is
	// re-delivered.
	filteredCtx, filteredCancel := context.WithCancel(context.Background())
	filtered, filteredDone := collectStream(s.Stream(filteredCtx, first.RecordedAt))
	require.Equal(t, firstRevocation.Link(), (<-filtered).Cause().Link())
	require.Equal(t, secondRevocation.Link(), (<-filtered).Cause().Link())
	require.Equal(t, thirdRevocation.Link(), (<-filtered).Cause().Link())
	filteredCancel()
	require.ErrorIs(t, <-filteredDone, context.Canceled)
}

func TestMemoryRevocationStoreStreamEvents(t *testing.T) {
	s := memory.New()
	revocation, path := revocationPath(t)
	add(t, s, revocation, path)

	ctx, cancel := context.WithCancel(context.Background())
	events, done := collectStream(s.Stream(ctx, time.Time{}))
	event := <-events
	require.Equal(t, store.EventKindRevocation, event.Kind)
	require.Nil(t, event.PrincipalRevocation)
	require.NotNil(t, event.Revocation)
	require.Equal(t, path[len(path)-1].Link(), event.Revocation.Revoke)
	require.Equal(t, revocation.Link(), event.Revocation.Cause.Link())
	require.Len(t, event.Revocation.Path, len(path))
	require.False(t, event.Revocation.RecordedAt.IsZero())

	// Streamed records are copies: mutating one does not affect the store.
	event.Revocation.Path[0] = nil
	again, err := s.Get(context.Background(), path[len(path)-1].Link())
	require.NoError(t, err)
	require.NotNil(t, again.Path[0])
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
}

func TestMemoryRevocationStoreStreamBroadcasts(t *testing.T) {
	s := memory.New()
	firstRevocation, firstPath := revocationPath(t)
	add(t, s, firstRevocation, firstPath)

	firstCtx, firstCancel := context.WithCancel(context.Background())
	firstRecords, firstDone := collectStream(s.Stream(firstCtx, time.Time{}))
	secondCtx, secondCancel := context.WithCancel(context.Background())
	secondRecords, secondDone := collectStream(s.Stream(secondCtx, time.Time{}))
	<-firstRecords
	<-secondRecords

	revocation, path := revocationPath(t)
	add(t, s, revocation, path)
	require.Equal(t, revocation.Link(), (<-firstRecords).Cause().Link())
	require.Equal(t, revocation.Link(), (<-secondRecords).Cause().Link())

	firstCancel()
	secondCancel()
	require.ErrorIs(t, <-firstDone, context.Canceled)
	require.ErrorIs(t, <-secondDone, context.Canceled)
}

func TestMemoryRevocationStoreStreamCanceled(t *testing.T) {
	s := memory.New()
	revocation, path := revocationPath(t)
	add(t, s, revocation, path)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	for _, err := range s.Stream(ctx, time.Time{}) {
		require.ErrorIs(t, err, context.Canceled)
		return
	}
	require.Fail(t, "Stream did not return context.Canceled")
}

func TestMemoryRevocationStoreAddIgnoresRetriedRevocation(t *testing.T) {
	s := memory.New()
	revocation, path := revocationPath(t)
	add(t, s, revocation, path)
	add(t, s, revocation, path)

	ctx, cancel := context.WithCancel(context.Background())
	events, done := collectStream(s.Stream(ctx, time.Time{}))
	require.Equal(t, revocation.Link(), (<-events).Cause().Link())
	select {
	case event := <-events:
		require.Fail(t, "retried revocation streamed twice", event.Cause().Link())
	case <-time.After(100 * time.Millisecond):
	}
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
}

func TestMemoryRevocationStoreAddSecondRevocationOfDelegation(t *testing.T) {
	s := memory.New()
	firstRevocation, path := revocationPath(t)
	// A second revocation of the same delegation, by a different invocation.
	secondRevocation, _ := revocationPath(t)
	add(t, s, firstRevocation, path)
	add(t, s, secondRevocation, path)

	record, err := s.Get(context.Background(), path[len(path)-1].Link())
	require.NoError(t, err)
	require.Equal(t, secondRevocation.Link(), record.Cause.Link())

	ctx, cancel := context.WithCancel(context.Background())
	events, done := collectStream(s.Stream(ctx, time.Time{}))
	require.Equal(t, firstRevocation.Link(), (<-events).Cause().Link())
	require.Equal(t, secondRevocation.Link(), (<-events).Cause().Link())
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
}

func TestMemoryRevocationStoreAddRejectsInvalidPath(t *testing.T) {
	err := memory.New().Add(context.Background(), nil, nil)
	require.Error(t, err)
}

func add(t *testing.T, s store.RevocationStore, revocation ucan.Invocation, path []ucan.Delegation) {
	t.Helper()
	require.NoError(t, s.Add(context.Background(), revocation, path))
}

func collectStream(stream iter.Seq2[store.Event, error]) (<-chan store.Event, <-chan error) {
	records := make(chan store.Event)
	done := make(chan error, 1)
	go func() {
		for record, err := range stream {
			if err != nil {
				done <- err
				return
			}
			records <- record
		}
		done <- nil
	}()
	return records, done
}

func revocationPath(t *testing.T) (ucan.Invocation, []ucan.Delegation) {
	t.Helper()

	issuer, err := ed25519.GenerateIssuer()
	require.NoError(t, err)
	cmd, err := command.Parse("/test/revoke")
	require.NoError(t, err)
	delegation, err := delegation.Delegate(issuer, issuer.DID(), did.Undef, cmd)
	require.NoError(t, err)
	revocation, err := invocation.Invoke(issuer, did.Undef, cmd, nil)
	require.NoError(t, err)
	return revocation, []ucan.Delegation{delegation}
}

func TestMemoryPrincipalStoreStreamInterleaved(t *testing.T) {
	s := memory.New()
	firstRevocation, firstPath := revocationPath(t)
	add(t, s, firstRevocation, firstPath)
	invalidation, tenant, principal := principalInvalidation(t)
	addPrincipalRevocation(t, s, invalidation, tenant, principal)
	secondRevocation, secondPath := revocationPath(t)
	add(t, s, secondRevocation, secondPath)

	ctx, cancel := context.WithCancel(context.Background())
	events, done := collectStream(s.Stream(ctx, time.Time{}))

	// Both kinds share one stream, ordered by the time they were recorded.
	event := <-events
	require.Equal(t, store.EventKindRevocation, event.Kind)
	require.Equal(t, firstRevocation.Link(), event.Cause().Link())

	event = <-events
	require.Equal(t, store.EventKindPrincipalRevocation, event.Kind)
	require.Nil(t, event.Revocation)
	require.NotNil(t, event.PrincipalRevocation)
	require.Equal(t, tenant, event.PrincipalRevocation.Tenant)
	require.Equal(t, principal, event.PrincipalRevocation.Principal)
	require.Equal(t, invalidation.Link(), event.PrincipalRevocation.Cause.Link())
	require.False(t, event.PrincipalRevocation.RecordedAt.IsZero())
	require.Equal(t, invalidation.Link(), event.Cause().Link())
	require.True(t, event.RecordedAt().Equal(event.PrincipalRevocation.RecordedAt))

	event = <-events
	require.Equal(t, store.EventKindRevocation, event.Kind)
	require.Equal(t, secondRevocation.Link(), event.Cause().Link())

	// A principal invalidation added while streaming wakes the stream.
	liveInvalidation, liveTenant, livePrincipal := principalInvalidation(t)
	addPrincipalRevocation(t, s, liveInvalidation, liveTenant, livePrincipal)
	event = <-events
	require.Equal(t, store.EventKindPrincipalRevocation, event.Kind)
	require.Equal(t, liveInvalidation.Link(), event.Cause().Link())
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)

	// Principal records do not affect revocation lookup.
	record, err := s.Get(context.Background(), firstPath[len(firstPath)-1].Link())
	require.NoError(t, err)
	require.Equal(t, firstRevocation.Link(), record.Cause.Link())
}

func TestMemoryPrincipalStoreStreamFrom(t *testing.T) {
	s := memory.New()
	revocation, path := revocationPath(t)
	add(t, s, revocation, path)
	time.Sleep(time.Millisecond)
	invalidation, tenant, principal := principalInvalidation(t)
	addPrincipalRevocation(t, s, invalidation, tenant, principal)

	// Only the principal record was recorded on or after from.
	ctx, cancel := context.WithCancel(context.Background())
	var from time.Time
	for event, err := range s.Stream(ctx, time.Time{}) {
		require.NoError(t, err)
		if event.Kind == store.EventKindPrincipalRevocation {
			from = event.RecordedAt()
			break
		}
	}
	cancel()
	require.False(t, from.IsZero())

	filteredCtx, filteredCancel := context.WithCancel(context.Background())
	filtered, filteredDone := collectStream(s.Stream(filteredCtx, from))
	event := <-filtered
	require.Equal(t, store.EventKindPrincipalRevocation, event.Kind)
	require.Equal(t, invalidation.Link(), event.Cause().Link())
	select {
	case event := <-filtered:
		require.Failf(t, "stream delivered a record recorded before from", "cause: %s", event.Cause().Link())
	case <-time.After(100 * time.Millisecond):
	}
	filteredCancel()
	require.ErrorIs(t, <-filteredDone, context.Canceled)
}

func TestMemoryPrincipalStoreAddIgnoresRetriedInvalidation(t *testing.T) {
	s := memory.New()
	invalidation, tenant, principal := principalInvalidation(t)
	addPrincipalRevocation(t, s, invalidation, tenant, principal)
	addPrincipalRevocation(t, s, invalidation, tenant, principal)

	ctx, cancel := context.WithCancel(context.Background())
	events, done := collectStream(s.Stream(ctx, time.Time{}))
	require.Equal(t, invalidation.Link(), (<-events).Cause().Link())
	select {
	case event := <-events:
		require.Fail(t, "retried invalidation streamed twice", event.Cause().Link())
	case <-time.After(100 * time.Millisecond):
	}
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
}

func TestMemoryPrincipalStoreAddRejectsInvalid(t *testing.T) {
	s := memory.New()
	invalidation, tenant, principal := principalInvalidation(t)

	require.Error(t, s.AddPrincipalRevocation(context.Background(), invalidation, did.Undef, principal))
	require.Error(t, s.AddPrincipalRevocation(context.Background(), invalidation, tenant, ""))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, s.AddPrincipalRevocation(ctx, invalidation, tenant, principal), context.Canceled)
}

func addPrincipalRevocation(t *testing.T, s store.RevocationStore, invalidation ucan.Invocation, tenant did.DID, principal string) {
	t.Helper()
	require.NoError(t, s.AddPrincipalRevocation(context.Background(), invalidation, tenant, principal))
}

func principalInvalidation(t *testing.T) (ucan.Invocation, did.DID, string) {
	t.Helper()

	issuer, err := ed25519.GenerateIssuer()
	require.NoError(t, err)
	cmd, err := command.Parse("/test/invalidate")
	require.NoError(t, err)
	invalidation, err := invocation.Invoke(issuer, did.Undef, cmd, nil)
	require.NoError(t, err)
	tenant, err := did.Parse("did:plc:" + issuer.DID().Identifier())
	require.NoError(t, err)
	return invalidation, tenant, "principal-" + invalidation.Link().String()[:8]
}
