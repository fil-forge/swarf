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
	mu sync.RWMutex
	// records indexes the latest revocation record by revoked delegation for Get.
	records map[cid.Cid]store.RevocationRecord
	// log is the append-only sequence of every stored record, in the order it
	// was stored, for Stream. Entry i has seq i+1.
	log []logEntry
	// causes holds the cause link of every logged record, so a retried
	// invocation is logged once.
	causes         map[cid.Cid]struct{}
	subscribers    map[uint64]chan struct{}
	nextSeq        uint64
	nextSubscriber uint64
}

type logEntry struct {
	event store.Event
	seq   uint64
}

// New creates an empty revocation store.
func New() *Store {
	return &Store{
		records:     make(map[cid.Cid]store.RevocationRecord),
		causes:      make(map[cid.Cid]struct{}),
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
		Revoke: path[len(path)-1].Link(),
		Cause:  revocation,
		Path:   append([]ucan.Delegation(nil), path...),
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Stamped under the lock so the log's append order is its time order:
	// a streamer that has already yielded a later record never sees an
	// earlier one arrive behind it.
	record.RecordedAt = time.Now()

	if s.records == nil {
		s.records = make(map[cid.Cid]store.RevocationRecord)
	}
	s.records[record.Revoke] = record
	s.appendLocked(store.RevocationEvent(record))
	return nil
}

// appendLocked appends event to the log and wakes every streamer. An event
// whose cause is already logged is dropped, so a retried invocation is
// streamed once, as the postgres backend's ON CONFLICT (id) DO NOTHING gives.
// The caller must hold the write lock.
func (s *Store) appendLocked(event store.Event) {
	cause := event.Cause().Link()
	if _, ok := s.causes[cause]; ok {
		return
	}
	if s.causes == nil {
		s.causes = make(map[cid.Cid]struct{})
	}
	s.causes[cause] = struct{}{}
	s.nextSeq++
	s.log = append(s.log, logEntry{event: event, seq: s.nextSeq})
	for _, notification := range s.subscribers {
		select {
		case notification <- struct{}{}:
		default:
		}
	}
}

// Get retrieves the revocation record for delegation.
func (s *Store) Get(ctx context.Context, delegation cid.Cid) (store.RevocationRecord, error) {
	if err := ctx.Err(); err != nil {
		return store.RevocationRecord{}, err
	}

	s.mu.RLock()
	record, ok := s.records[delegation]
	s.mu.RUnlock()
	if !ok {
		return store.RevocationRecord{}, store.ErrNotFound
	}

	return copyRecord(record), nil
}

// Stream returns matching records as events and remains open until ctx is canceled.
func (s *Store) Stream(ctx context.Context, from time.Time) iter.Seq2[store.Event, error] {
	return func(yield func(store.Event, error) bool) {
		if err := ctx.Err(); err != nil {
			yield(store.Event{}, err)
			return
		}

		s.mu.Lock()
		entries, sequence := s.eventsFromLocked(0, from)
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
					yield(store.Event{}, err)
					return
				}
				if !yield(copyEvent(entry.event), nil) {
					return
				}
			}

			select {
			case <-ctx.Done():
				yield(store.Event{}, ctx.Err())
				return
			case <-notification:
				s.mu.RLock()
				entries, sequence = s.eventsFromLocked(sequence, from)
				s.mu.RUnlock()
			}
		}
	}
}

// eventsFromLocked returns the log entries appended after sequence and
// recorded on or after from, ordered by recorded time then sequence, along
// with the sequence to resume from. The caller must hold the lock.
func (s *Store) eventsFromLocked(sequence uint64, from time.Time) ([]logEntry, uint64) {
	entries := make([]logEntry, 0, len(s.log)-int(sequence))
	for _, entry := range s.log[sequence:] {
		if from.IsZero() || !entry.event.RecordedAt().Before(from) {
			entries = append(entries, entry)
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].event.RecordedAt().Equal(entries[j].event.RecordedAt()) {
			return entries[i].seq < entries[j].seq
		}
		return entries[i].event.RecordedAt().Before(entries[j].event.RecordedAt())
	})
	return entries, s.nextSeq
}

func copyRecord(record store.RevocationRecord) store.RevocationRecord {
	record.Path = slices.Clone(record.Path)
	return record
}

func copyEvent(event store.Event) store.Event {
	if event.Revocation != nil {
		return store.RevocationEvent(copyRecord(*event.Revocation))
	}
	if event.PrincipalRevocation != nil {
		return store.PrincipalRevocationEvent(*event.PrincipalRevocation)
	}
	return event
}
