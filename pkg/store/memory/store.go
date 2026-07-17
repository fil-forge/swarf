package memory

import (
	"context"
	"errors"
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
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(path) == 0 {
		return errors.New("revocation path must contain the revoked delegation")
	}

	record := store.RevocationRecord{
		Revoke:    path[len(path)-1].Link(),
		Cause:     revocation,
		Path:      append([]ucan.Delegation(nil), path...),
		CreatedAt: time.Now(),
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.records == nil {
		s.records = make(map[cid.Cid]memoryRecord)
	}
	s.nextSeq++
	s.records[path[len(path)-1].Link()] = memoryRecord{
		record: record,
		seq:    s.nextSeq,
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
func (s *Store) Stream(ctx context.Context, since time.Time) iter.Seq2[store.RevocationRecord, error] {
	return func(yield func(store.RevocationRecord, error) bool) {
		if err := ctx.Err(); err != nil {
			yield(store.RevocationRecord{}, err)
			return
		}

		s.mu.Lock()
		entries, sequence := s.recordsSinceLocked(0, since)
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
				entries, sequence = s.recordsSinceLocked(sequence, since)
				s.mu.RUnlock()
			}
		}
	}
}

func (s *Store) recordsSinceLocked(sequence uint64, since time.Time) ([]memoryRecord, uint64) {
	entries := make([]memoryRecord, 0, len(s.records))
	for _, entry := range s.records {
		if entry.seq > sequence && (since.IsZero() || entry.record.CreatedAt.After(since)) {
			entries = append(entries, entry)
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].record.CreatedAt.Equal(entries[j].record.CreatedAt) {
			return entries[i].seq < entries[j].seq
		}
		return entries[i].record.CreatedAt.Before(entries[j].record.CreatedAt)
	})
	return entries, s.nextSeq
}

func copyRecord(record store.RevocationRecord) store.RevocationRecord {
	record.Path = slices.Clone(record.Path)
	return record
}
