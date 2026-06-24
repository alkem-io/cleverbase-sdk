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

// ErrTerminal is returned when a resume is attempted on an already-terminal session.
var ErrTerminal = errors.New("session already terminal")

// ErrResuming is returned when a resume is attempted while another resume for the same session is
// already in flight (a concurrent duplicate callback for the same state).
var ErrResuming = errors.New("session already resuming")

// evictGrace is how long a session is retained in byID after its TTL elapses, so a late /status or
// /result fetch still resolves; past this it is evicted to bound memory (expireLocked only marks a
// session failed — it keeps ResultPDF/Evidence — so eviction is what actually frees the memory).
const evictGrace = 5 * time.Minute

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
	// resuming guards against a concurrent duplicate callback: it is set when a resume is started
	// (the pending state is consumed) and cleared when the next pending redirect state is indexed.
	// While set, the SDK handle is "checked out" to one in-flight resume and no other callback may
	// advance the same session, so non-idempotent upstream/signing effects run at most once.
	resuming bool
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
	m.evictExpiredLocked() // bound memory: sweep long-expired sessions whenever a new one is created
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
	// expireLocked de-indexes the pending state on TTL expiry. If the state is no longer pending, the
	// callback arrived after the session expired → treat it as an unknown/expired state (a clean 400
	// in handleComplete), not a session we hand on to resume and then 500 on as terminal.
	if m.byState[state] != corr {
		return nil, ErrNotFound
	}
	return s, nil
}

// View is a race-free value snapshot of a session's client-facing fields, copied under the lock.
// ResultPDF/Evidence share the underlying arrays, which are immutable once set on completion.
type View struct {
	Status    Status
	Reason    string
	ResultPDF []byte
	Evidence  []byte
}

// ViewByID returns a snapshot by correlation id (expiring first), so handlers never read fields off
// the live pointer while the flow engine writes them under the lock.
func (m *Memory) ViewByID(corr string) (View, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.byID[corr]
	if s == nil {
		return View{}, ErrNotFound
	}
	m.expireLocked(s)
	return View{Status: s.Status, Reason: s.Reason, ResultPDF: s.ResultPDF, Evidence: s.Evidence}, nil
}

// ConsumeForResume atomically claims a session for a single resume step and returns a copy of its
// SDK handle. Under the store lock it: (1) rejects an already-terminal session (ErrTerminal); (2)
// rejects a session that another caller is already resuming (ErrResuming); (3) marks the session
// resuming and de-indexes its pending OAuth state, so a concurrent duplicate callback for the same
// state can neither find the session by state nor pass the resuming check. This is the single
// authoritative point that serializes redirect callbacks: it guarantees the non-idempotent
// upstream/signing effects in a resume run at most once per redirect.
//
// The pending state is expired-checked first (an expired session is terminal and rejected). The
// handle is copied so callers never alias mutable session state.
func (m *Memory) ConsumeForResume(s *Session) (handle []byte, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.expireLocked(s)
	if s.Terminal() {
		return nil, ErrTerminal
	}
	if s.resuming {
		return nil, ErrResuming
	}
	s.resuming = true
	if s.OAuthState != "" {
		delete(m.byState, s.OAuthState)
		s.OAuthState = ""
	}
	return append([]byte(nil), s.Handle...), nil
}

// Update runs mutate (which closes over the session) under the store lock, serializing field writes
// with concurrent reads.
func (m *Memory) Update(_ *Session, mutate func()) {
	m.mu.Lock()
	defer m.mu.Unlock()
	mutate()
}

// SetState re-indexes the session's pending OAuth state (used when the second redirect is issued).
// Indexing a fresh pending state ends the in-flight resume: the session is again awaiting a callback,
// so it is cleared of the resuming claim and a subsequent callback for the new state may resume it.
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
	s.resuming = false
}

// Finalize marks a terminal session: drops the handle and the state index, and ends any resume claim.
func (m *Memory) Finalize(s *Session) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s.OAuthState != "" {
		delete(m.byState, s.OAuthState)
		s.OAuthState = ""
	}
	s.Handle = nil
	s.resuming = false
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

// evictExpiredLocked drops sessions whose TTL elapsed more than evictGrace ago from both indexes,
// freeing their ResultPDF/Evidence. Called when a new session is created (the only growth driver), so
// byID stays bounded by the working set plus sessions that expired within the last evictGrace window.
func (m *Memory) evictExpiredLocked() {
	now := m.clock()
	for id, s := range m.byID {
		// Never evict a session that is checked out for an in-flight resume (resuming==true, its state
		// already de-indexed). That resume runs outside the store lock and will re-index a fresh pending
		// state via SetState when it emits the next redirect; evicting it here would strand that callback
		// (GetByState → ErrNotFound, the in-flight signing session lost mid-flow) and leak the re-added
		// byState entry. `resuming` is transient — cleared by SetState/Finalize when the resume advances
		// or terminates — so skipping it cannot leak memory.
		if !s.resuming && now.After(s.ExpiresAt.Add(evictGrace)) {
			if s.OAuthState != "" {
				delete(m.byState, s.OAuthState)
			}
			delete(m.byID, id)
		}
	}
}
