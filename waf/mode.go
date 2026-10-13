package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ModeState is the mode Network Optimizer last set and when it took effect.
type ModeState struct {
	Mode  string    `json:"mode"`
	Since time.Time `json:"since"`
	// Persisted is false when there is no state directory: a change then lasts until a restart.
	Persisted bool `json:"persisted"`
}

// ModeStore keeps the mode in the state directory, so a mode set from Network Optimizer survives
// a restart and overrides WAF_MODE, which only sets the mode a new install starts in.
type ModeStore struct {
	mu    sync.Mutex
	dir   string
	state ModeState
}

// NewModeStore loads the saved mode, or starts from initial and saves it with the current time
// so the time spent in that mode is known from the first start.
func NewModeStore(dir, initial string, now time.Time) (*ModeStore, error) {
	s := &ModeStore{dir: dir, state: ModeState{Mode: initial, Since: now.UTC(), Persisted: dir != ""}}
	if dir == "" {
		return s, nil
	}
	data, err := os.ReadFile(s.path())
	if os.IsNotExist(err) {
		return s, s.save()
	}
	if err != nil {
		return nil, err
	}
	var saved ModeState
	if err := json.Unmarshal(data, &saved); err != nil {
		return nil, fmt.Errorf("%s: %w", s.path(), err)
	}
	if saved.Mode == ModeDetect || saved.Mode == ModeBlock {
		s.state.Mode, s.state.Since = saved.Mode, saved.Since
	}
	return s, nil
}

func (s *ModeStore) path() string { return filepath.Join(s.dir, "mode.json") }

func (s *ModeStore) save() error {
	if s.dir == "" {
		return nil
	}
	data, err := json.Marshal(s.state)
	if err != nil {
		return err
	}
	tmp := s.path() + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path())
}

// Get returns the current mode.
func (s *ModeStore) Get() ModeState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// Set records a new mode; the time only resets when the mode actually changes.
func (s *ModeStore) Set(mode string, now time.Time) (ModeState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if mode != s.state.Mode {
		s.state.Mode, s.state.Since = mode, now.UTC()
	}
	return s.state, s.save()
}
