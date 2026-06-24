package session

import (
	"errors"
	"testing"
	"time"
)

func TestNewGetAndStateIndex(t *testing.T) {
	m := NewMemory()
	s := m.New("corr-1", "state-A", "B-B", time.Minute)
	if s.Status != StatusAuthorizing || s.CorrelationID != "corr-1" {
		t.Fatalf("unexpected new session: %+v", s)
	}
	got, err := m.Get("corr-1")
	if err != nil || got != s {
		t.Fatalf("Get failed: %v", err)
	}
	byState, err := m.GetByState("state-A")
	if err != nil || byState != s {
		t.Fatalf("GetByState failed: %v", err)
	}
	if _, err := m.Get("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if _, err := m.GetByState("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestSetStateReindexesBothRedirects(t *testing.T) {
	m := NewMemory()
	s := m.New("corr-1", "state-A", "B-B", time.Minute)
	// Second (credential-scope) redirect issues a fresh state.
	m.SetState(s, "state-B")
	if _, err := m.GetByState("state-A"); !errors.Is(err, ErrNotFound) {
		t.Fatal("old state should be de-indexed after the second redirect")
	}
	got, err := m.GetByState("state-B")
	if err != nil || got != s || s.OAuthState != "state-B" {
		t.Fatalf("new state not indexed: %v", err)
	}
}

func TestFinalizeScrubs(t *testing.T) {
	m := NewMemory()
	s := m.New("corr-1", "state-A", "B-B", time.Minute)
	m.Update(s, func() { s.Handle = []byte("secret-handle"); s.Status = StatusCompleted })
	m.Finalize(s)
	if s.Handle != nil {
		t.Fatal("handle should be scrubbed on finalize")
	}
	if _, err := m.GetByState("state-A"); !errors.Is(err, ErrNotFound) {
		t.Fatal("state should be de-indexed on finalize")
	}
	if got, _ := m.Get("corr-1"); got.Status != StatusCompleted {
		t.Fatal("session should remain retrievable by id with its terminal status")
	}
}

func TestConcurrentViewAndUpdateRaceFree(t *testing.T) {
	// Run under `go test -race`: a reader taking snapshots while the flow engine mutates the same
	// session must not race (handlers read via ViewByID/ResumeView, never the live pointer off-lock).
	m := NewMemory()
	s := m.New("c", "st", "B-B", time.Minute)
	done := make(chan struct{})
	go func() {
		for i := 0; i < 2000; i++ {
			m.Update(s, func() { s.Status = StatusCompleted; s.ResultPDF = []byte("pdf") })
			m.ResumeView(s)
		}
		close(done)
	}()
	for i := 0; i < 2000; i++ {
		_, _ = m.ViewByID("c")
	}
	<-done
	if v, err := m.ViewByID("c"); err != nil || v.Status != StatusCompleted || string(v.ResultPDF) != "pdf" {
		t.Fatalf("final view: %v status=%s pdf=%q", err, v.Status, v.ResultPDF)
	}
}

func TestExpiryYieldsTerminalNotHang(t *testing.T) {
	m := NewMemory()
	base := time.Now()
	m.clock = func() time.Time { return base }
	s := m.New("corr-1", "state-A", "B-B", time.Minute)
	s.Handle = []byte("h")
	// Advance past the TTL.
	m.clock = func() time.Time { return base.Add(2 * time.Minute) }
	got, err := m.Get("corr-1")
	if err != nil {
		t.Fatalf("expired session should still be retrievable: %v", err)
	}
	if got.Status != StatusFailed || got.Reason != "session_expired" {
		t.Fatalf("expired session should be failed/session_expired, got %s/%s", got.Status, got.Reason)
	}
	if got.Handle != nil {
		t.Fatal("expired session should be scrubbed")
	}
	if _, err := m.GetByState("state-A"); !errors.Is(err, ErrNotFound) {
		t.Fatal("expired session's state should be de-indexed")
	}
}
