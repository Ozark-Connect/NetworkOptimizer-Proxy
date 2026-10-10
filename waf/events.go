package main

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// Event actions.
const (
	ActionBlocked  = "blocked"
	ActionDetected = "detected"
)

// RuleHit is one CRS rule that contributed to an event.
type RuleHit struct {
	ID       int      `json:"id"`
	Message  string   `json:"msg"`
	Severity string   `json:"severity"`
	Tags     []string `json:"tags"`
}

// Event is a request that crossed the CRS anomaly threshold.
type Event struct {
	Seq          uint64    `json:"seq"`
	Time         time.Time `json:"ts"`
	SourceIP     string    `json:"src_ip"`
	Host         string    `json:"host"`
	Method       string    `json:"method"`
	URI          string    `json:"uri"`
	Action       string    `json:"action"`
	AnomalyScore int       `json:"anomaly_score"`
	Rules        []RuleHit `json:"rules"`
}

// Stats are counters since this process started.
type Stats struct {
	Inspected uint64 `json:"inspected"`
	Blocked   uint64 `json:"blocked"`
	Detected  uint64 `json:"detected"`
}

// EventPage is the events API response.
type EventPage struct {
	// Instance changes on every restart; a reader holding a cursor from another instance starts over.
	Instance string    `json:"instance"`
	Started  time.Time `json:"started"`
	Mode     string    `json:"mode"`
	Paranoia int       `json:"paranoia"`
	Stats    Stats     `json:"stats"`
	Next     uint64    `json:"next"`
	Events   []Event   `json:"events"`
}

// Store keeps the most recent events in a fixed-size ring with monotonically increasing sequence numbers.
type Store struct {
	mu       sync.Mutex
	ring     []Event
	size     int
	nextSeq  uint64
	stats    Stats
	instance string
	started  time.Time
	now      func() time.Time
}

// NewStore creates a store holding up to capacity events.
func NewStore(capacity int) *Store {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return &Store{
		ring:     make([]Event, capacity),
		nextSeq:  1,
		instance: hex.EncodeToString(b),
		started:  time.Now().UTC(),
		now:      func() time.Time { return time.Now().UTC() },
	}
}

// Record counts an inspected request and stores its event, if any.
func (s *Store) Record(v Verdict) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.Inspected++
	if v.Event == nil {
		return
	}
	if v.Event.Action == ActionBlocked {
		s.stats.Blocked++
	} else {
		s.stats.Detected++
	}
	e := *v.Event
	e.Seq = s.nextSeq
	e.Time = s.now()
	s.ring[int(e.Seq%uint64(len(s.ring)))] = e
	s.nextSeq++
	if s.size < len(s.ring) {
		s.size++
	}
}

// Since returns up to limit events with Seq >= from, oldest first.
func (s *Store) Since(from uint64, limit int, mode string, paranoia int) EventPage {
	s.mu.Lock()
	defer s.mu.Unlock()

	oldest := s.nextSeq - uint64(s.size)
	if from < oldest {
		from = oldest
	}
	if from > s.nextSeq {
		from = s.nextSeq
	}
	events := make([]Event, 0, min(limit, int(s.nextSeq-from)))
	seq := from
	for ; seq < s.nextSeq && len(events) < limit; seq++ {
		events = append(events, s.ring[int(seq%uint64(len(s.ring)))])
	}
	return EventPage{
		Instance: s.instance,
		Started:  s.started,
		Mode:     mode,
		Paranoia: paranoia,
		Stats:    s.stats,
		Next:     seq,
		Events:   events,
	}
}
