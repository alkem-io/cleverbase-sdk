// Package session holds the server-side envelope for one signing journey (data-model: SigningSession),
// addressed by a correlation id, with the OAuth state mapped to it and an in-memory TTL store.
package session

import (
	"errors"
	"sync"
	"time"
)

// Status is the frontend-facing status (mirrors the helper's SignStatus).
type Status string

// Session statuses surfaced to the frontend.
const (
	StatusPending     Status = "pending"
	StatusAuthorizing Status = "authorizing"
	StatusCompleted   Status = "completed"
	StatusDeclined    Status = "declined"
	StatusFailed      Status = "failed"
)

// ErrNotFound is returned for an unknown/expired correlation id or state.
var ErrNotFound = errors.New("session not found")

// Session is the per-journey state. Handle/ResultPDF are sensitive and never leave the backend
// except the signed PDF on an explicit result fetch.
type Session struct {
	CorrelationID string
	OAuthState    string // current pending CSRF state; re-indexed across both redirects
	Handle        []byte // SDK session handle (opaque CBOR); dropped on terminal
	Status        Status
	Reason        string // failure reason code, set when Status == failed
	Conformance   string
	ResultPDF     []byte
	Evidence      []byte // raw JSON evidence record
	CreatedAt     time.Time
	ExpiresAt     time.Time
}

// Terminal reports whether the session has reached an end state.
func (s *Session) Terminal() bool {
	return s.Status == StatusCompleted || s.Status == StatusDeclined || s.Status == StatusFailed
}

// Memory is the default single-instance store (a shared/persistent store is a documented swap-in).
type Memory struct {
	mu      sync.Mutex
	byID    map[string]*Session
	byState map[string]string // oauth state -> correlation id
	clock   func() time.Time
}

// NewMemory builds an empty in-memory store.
func NewMemory() *Memory {
	return &Memory{byID: map[string]*Session{}, byState: map[string]string{}, clock: time.Now}
}

// New creates and indexes a session with the given initial OAuth state and TTL.
func (m *Memory) New(corr, state, conformance string, ttl time.Duration) *Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.clock()
	s := &Session{
		CorrelationID: corr,
		OAuthState:    state,
		Status:        StatusAuthorizing,
		Conformance:   conformance,
		CreatedAt:     now,
		ExpiresAt:     now.Add(ttl),
	}
	m.byID[corr] = s
	if state != "" {
		m.byState[state] = corr
	}
	return s
}

// Get returns the session by correlation id, expiring it first if its TTL elapsed.
func (m *Memory) Get(corr string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.byID[corr]
	if s == nil {
		return nil, ErrNotFound
	}
	m.expireLocked(s)
	return s, nil
}

// GetByState returns the session whose current pending OAuth state matches.
func (m *Memory) GetByState(state string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	corr := m.byState[state]
	if corr == "" {
		return nil, ErrNotFound
	}
	s := m.byID[corr]
	if s == nil {
		return nil, ErrNotFound
	}
	m.expireLocked(s)
	return s, nil
}

// Update runs mutate (which closes over the session) under the store lock, serializing field writes
// with concurrent reads.
func (m *Memory) Update(_ *Session, mutate func()) {
	m.mu.Lock()
	defer m.mu.Unlock()
	mutate()
}

// SetState re-indexes the session's pending OAuth state (used when the second redirect is issued).
func (m *Memory) SetState(s *Session, state string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s.OAuthState != "" {
		delete(m.byState, s.OAuthState)
	}
	s.OAuthState = state
	if state != "" {
		m.byState[state] = s.CorrelationID
	}
}

// Finalize marks a terminal session: drops the handle and the state index.
func (m *Memory) Finalize(s *Session) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s.OAuthState != "" {
		delete(m.byState, s.OAuthState)
		s.OAuthState = ""
	}
	s.Handle = nil
}

func (m *Memory) expireLocked(s *Session) {
	if !s.Terminal() && m.clock().After(s.ExpiresAt) {
		s.Status = StatusFailed
		s.Reason = "session_expired"
		s.Handle = nil
		if s.OAuthState != "" {
			delete(m.byState, s.OAuthState)
			s.OAuthState = ""
		}
	}
}
