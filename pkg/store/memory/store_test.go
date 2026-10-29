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
	records, done := collectStream(s.Stream(ctx, store.Cursor{}, time.Time{}))
	require.Equal(t, firstRevocation.Link(), (<-records).Cause.Link())
	require.Equal(t, secondRevocation.Link(), (<-records).Cause.Link())

	thirdRevocation, thirdPath := revocationPath(t)
	add(t, s, thirdRevocation, thirdPath)
	require.Equal(t, thirdRevocation.Link(), (<-records).Cause.Link())
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)

	// The from filter is inclusive: the record recorded at exactly from is
	// re-delivered.
	filteredCtx, filteredCancel := context.WithCancel(context.Background())
	filtered, filteredDone := collectStream(s.Stream(filteredCtx, store.Cursor{}, first.RecordedAt))
	require.Equal(t, firstRevocation.Link(), (<-filtered).Cause.Link())
	require.Equal(t, secondRevocation.Link(), (<-filtered).Cause.Link())
	require.Equal(t, thirdRevocation.Link(), (<-filtered).Cause.Link())
	filteredCancel()
	require.ErrorIs(t, <-filteredDone, context.Canceled)
}

func TestMemoryRevocationStoreStreamAfterCursor(t *testing.T) {
	s := memory.New()
	firstRevocation, firstPath := revocationPath(t)
	add(t, s, firstRevocation, firstPath)
	secondRevocation, secondPath := revocationPath(t)
	add(t, s, secondRevocation, secondPath)

	ctx, cancel := context.WithCancel(context.Background())
	records, done := collectStream(s.Stream(ctx, store.Cursor{}, time.Time{}))
	first := <-records
	require.Equal(t, firstRevocation.Link(), first.Cause.Link())
	second := <-records
	require.Equal(t, secondRevocation.Link(), second.Cause.Link())
	require.Positive(t, second.Cursor.Compare(first.Cursor))
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)

	// A stream after the first record's cursor starts at the second.
	resumedCtx, resumedCancel := context.WithCancel(context.Background())
	resumed, resumedDone := collectStream(s.Stream(resumedCtx, first.Cursor, time.Time{}))
	require.Equal(t, secondRevocation.Link(), (<-resumed).Cause.Link())
	thirdRevocation, thirdPath := revocationPath(t)
	add(t, s, thirdRevocation, thirdPath)
	require.Equal(t, thirdRevocation.Link(), (<-resumed).Cause.Link())
	resumedCancel()
	require.ErrorIs(t, <-resumedDone, context.Canceled)

	// A cursor past every record yields nothing until a record passes it.
	aheadCtx, aheadCancel := context.WithCancel(context.Background())
	ahead, aheadDone := collectStream(s.Stream(aheadCtx, store.Cursor{Seq: 4}, time.Time{}))
	fourthRevocation, fourthPath := revocationPath(t)
	add(t, s, fourthRevocation, fourthPath)
	fifthRevocation, fifthPath := revocationPath(t)
	add(t, s, fifthRevocation, fifthPath)
	require.Equal(t, fifthRevocation.Link(), (<-ahead).Cause.Link())
	aheadCancel()
	require.ErrorIs(t, <-aheadDone, context.Canceled)
}

func TestMemoryRevocationStoreStreamAfterHead(t *testing.T) {
	s := memory.New()
	firstRevocation, firstPath := revocationPath(t)
	add(t, s, firstRevocation, firstPath)

	head, err := s.Head(context.Background())
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	records, done := collectStream(s.Stream(ctx, head, time.Time{}))

	secondRevocation, secondPath := revocationPath(t)
	add(t, s, secondRevocation, secondPath)
	require.Equal(t, secondRevocation.Link(), (<-records).Cause.Link())
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
}

func TestMemoryRevocationStoreStreamBroadcasts(t *testing.T) {
	s := memory.New()
	firstRevocation, firstPath := revocationPath(t)
	add(t, s, firstRevocation, firstPath)

	firstCtx, firstCancel := context.WithCancel(context.Background())
	firstRecords, firstDone := collectStream(s.Stream(firstCtx, store.Cursor{}, time.Time{}))
	secondCtx, secondCancel := context.WithCancel(context.Background())
	secondRecords, secondDone := collectStream(s.Stream(secondCtx, store.Cursor{}, time.Time{}))
	<-firstRecords
	<-secondRecords

	revocation, path := revocationPath(t)
	add(t, s, revocation, path)
	require.Equal(t, revocation.Link(), (<-firstRecords).Cause.Link())
	require.Equal(t, revocation.Link(), (<-secondRecords).Cause.Link())

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

	for _, err := range s.Stream(ctx, store.Cursor{}, time.Time{}) {
		require.ErrorIs(t, err, context.Canceled)
		return
	}
	require.Fail(t, "Stream did not return context.Canceled")
}

func TestMemoryRevocationStoreAddRejectsInvalidPath(t *testing.T) {
	err := memory.New().Add(context.Background(), nil, nil)
	require.Error(t, err)
}

func add(t *testing.T, s store.RevocationStore, revocation ucan.Invocation, path []ucan.Delegation) {
	t.Helper()
	require.NoError(t, s.Add(context.Background(), revocation, path))
}

func collectStream(stream iter.Seq2[store.StreamRecord, error]) (<-chan store.StreamRecord, <-chan error) {
	records := make(chan store.StreamRecord)
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
