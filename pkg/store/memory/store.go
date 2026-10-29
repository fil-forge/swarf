package memory

import (
	"context"
	"errors"
	"iter"
	"slices"
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
		Revoke:     path[len(path)-1].Link(),
		Cause:      revocation,
		Path:       append([]ucan.Delegation(nil), path...),
		RecordedAt: time.Now(),
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

// Head returns the cursor of the last record added.
func (s *Store) Head(ctx context.Context) (store.Cursor, error) {
	if err := ctx.Err(); err != nil {
		return store.Cursor{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return store.Cursor{Seq: s.nextSeq}, nil
}

// Stream yields matching revocation records and remains open until ctx is
// canceled. A record's cursor is the sequence number Add gave it, and Add
// gives each record its number under the same lock that makes it visible, so
// no record can appear ahead of one already streamed.
func (s *Store) Stream(ctx context.Context, after store.Cursor, from time.Time) iter.Seq2[store.StreamRecord, error] {
	return func(yield func(store.StreamRecord, error) bool) {
		if err := ctx.Err(); err != nil {
			yield(store.StreamRecord{}, err)
			return
		}

		s.mu.Lock()
		entries, scanned := s.recordsAfterLocked(after, from)
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
					yield(store.StreamRecord{}, err)
					return
				}
				record := store.StreamRecord{
					RevocationRecord: copyRecord(entry.record),
					Cursor:           entry.cursor(),
				}
				if !yield(record, nil) {
					return
				}
			}

			select {
			case <-ctx.Done():
				yield(store.StreamRecord{}, ctx.Err())
				return
			case <-notification:
				s.mu.RLock()
				entries, scanned = s.recordsAfterLocked(scanned, from)
				s.mu.RUnlock()
			}
		}
	}
}

// recordsAfterLocked returns the records after the after cursor and recorded
// on or after from, in cursor order, and the cursor the next scan starts
// after: the later of after and the last record added.
func (s *Store) recordsAfterLocked(after store.Cursor, from time.Time) ([]memoryRecord, store.Cursor) {
	entries := make([]memoryRecord, 0, len(s.records))
	for _, entry := range s.records {
		if entry.cursor().Compare(after) > 0 && !entry.record.RecordedAt.Before(from) {
			entries = append(entries, entry)
		}
	}
	slices.SortFunc(entries, func(a, b memoryRecord) int {
		return a.cursor().Compare(b.cursor())
	})
	scanned := store.Cursor{Seq: s.nextSeq}
	if scanned.Compare(after) < 0 {
		scanned = after
	}
	return entries, scanned
}

func (r memoryRecord) cursor() store.Cursor {
	return store.Cursor{Seq: r.seq}
}

func copyRecord(record store.RevocationRecord) store.RevocationRecord {
	record.Path = slices.Clone(record.Path)
	return record
}
