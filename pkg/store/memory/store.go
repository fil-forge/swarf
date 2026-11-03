package memory

import (
	"context"
	"fmt"
	"iter"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/fil-forge/swarf/pkg/store"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/ipfs/go-cid"
)

// Store stores revocation records in process memory.
type Store struct {
	mu             sync.RWMutex
	records        map[cid.Cid]memoryRecord
	subscribers    map[uint64]chan struct{}
	nextSeq        uint64
	nextSubscriber uint64
}

type memoryRecord struct {
	record store.RevocationRecord
	seq    uint64
}

// New creates an empty revocation store.
func New() *Store {
	return &Store{
		records:     make(map[cid.Cid]memoryRecord),
		subscribers: make(map[uint64]chan struct{}),
	}
}

var _ store.RevocationStore = (*Store)(nil)

// Add stores a revocation record for the final delegation in path.
func (s *Store) Add(ctx context.Context, revocation ucan.Invocation, path []ucan.Delegation) error {
	return s.AddBatch(ctx, []store.Revocation{{Cause: revocation, Path: path}})
}

// AddBatch stores a revocation record for the final delegation in each path,
// all recorded at the same time.
func (s *Store) AddBatch(ctx context.Context, revocations []store.Revocation) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(revocations) == 0 {
		return nil
	}
	for i, revocation := range revocations {
		if len(revocation.Path) == 0 {
			return fmt.Errorf("revocation at batch index %d: revocation path must contain the revoked delegation", i)
		}
	}

	recordedAt := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.records == nil {
		s.records = make(map[cid.Cid]memoryRecord)
	}
	for _, revocation := range revocations {
		revoked := revocation.Path[len(revocation.Path)-1].Link()
		// A repeat of the stored revocation keeps its first record, as the
		// Postgres store does, so a retry is not streamed again.
		if existing, ok := s.records[revoked]; ok && existing.record.Cause.Link() == revocation.Cause.Link() {
			continue
		}
		s.nextSeq++
		s.records[revoked] = memoryRecord{
			record: store.RevocationRecord{
				Revoke:     revoked,
				Cause:      revocation.Cause,
				Path:       slices.Clone(revocation.Path),
				RecordedAt: recordedAt,
			},
			seq: s.nextSeq,
		}
	}
	for _, notification := range s.subscribers {
		select {
		case notification <- struct{}{}:
		default:
		}
	}
	return nil
}

// Get retrieves the revocation record for delegation.
func (s *Store) Get(ctx context.Context, delegation cid.Cid) (store.RevocationRecord, error) {
	if err := ctx.Err(); err != nil {
		return store.RevocationRecord{}, err
	}

	s.mu.RLock()
	entry, ok := s.records[delegation]
	s.mu.RUnlock()
	if !ok {
		return store.RevocationRecord{}, store.ErrNotFound
	}

	return copyRecord(entry.record), nil
}

// Stream returns matching revocation records and remains open until ctx is canceled.
func (s *Store) Stream(ctx context.Context, from time.Time) iter.Seq2[store.RevocationRecord, error] {
	return func(yield func(store.RevocationRecord, error) bool) {
		if err := ctx.Err(); err != nil {
			yield(store.RevocationRecord{}, err)
			return
		}

		s.mu.Lock()
		entries, sequence := s.recordsFromLocked(0, from)
		s.nextSubscriber++
		subscriber := s.nextSubscriber
		notification := make(chan struct{}, 1)
		if s.subscribers == nil {
			s.subscribers = make(map[uint64]chan struct{})
		}
		s.subscribers[subscriber] = notification
		s.mu.Unlock()
		defer func() {
			s.mu.Lock()
			delete(s.subscribers, subscriber)
			s.mu.Unlock()
		}()

		for {
			for _, entry := range entries {
				if err := ctx.Err(); err != nil {
					yield(store.RevocationRecord{}, err)
					return
				}
				if !yield(copyRecord(entry.record), nil) {
					return
				}
			}

			select {
			case <-ctx.Done():
				yield(store.RevocationRecord{}, ctx.Err())
				return
			case <-notification:
				s.mu.RLock()
				entries, sequence = s.recordsFromLocked(sequence, from)
				s.mu.RUnlock()
			}
		}
	}
}

func (s *Store) recordsFromLocked(sequence uint64, from time.Time) ([]memoryRecord, uint64) {
	entries := make([]memoryRecord, 0, len(s.records))
	for _, entry := range s.records {
		if entry.seq > sequence && (from.IsZero() || !entry.record.RecordedAt.Before(from)) {
			entries = append(entries, entry)
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].record.RecordedAt.Equal(entries[j].record.RecordedAt) {
			return entries[i].seq < entries[j].seq
		}
		return entries[i].record.RecordedAt.Before(entries[j].record.RecordedAt)
	})
	return entries, s.nextSeq
}

func copyRecord(record store.RevocationRecord) store.RevocationRecord {
	record.Path = slices.Clone(record.Path)
	return record
}
