package session

import (
	"errors"
	"sync"
	"sync/atomic"
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
	// session must not race (handlers read via ViewByID, never the live pointer off-lock).
	m := NewMemory()
	s := m.New("c", "st", "B-B", time.Minute)
	done := make(chan struct{})
	go func() {
		for range 2000 {
			m.Update(s, func() { s.Status = StatusCompleted; s.ResultPDF = []byte("pdf") })
		}
		close(done)
	}()
	for range 2000 {
		_, _ = m.ViewByID("c")
	}
	<-done
	if v, err := m.ViewByID("c"); err != nil || v.Status != StatusCompleted || string(v.ResultPDF) != "pdf" {
		t.Fatalf("final view: %v status=%s pdf=%q", err, v.Status, v.ResultPDF)
	}
}

func TestConsumeForResumeIsAtomicAndSingleWinner(t *testing.T) {
	// Run under `go test -race`: many concurrent callbacks for the SAME pending state must yield
	// exactly one successful consume; every loser sees a clean error (ErrResuming/ErrTerminal) and
	// never a stale handle, so the non-idempotent resume runs at most once.
	const goroutines = 64
	m := NewMemory()
	s := m.New("c", "st", "B-B", time.Minute)
	m.Update(s, func() { s.Handle = []byte("HANDLE") })

	start := make(chan struct{})
	var wg sync.WaitGroup
	var winners atomic.Int64
	results := make(chan error, goroutines)
	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			h, err := m.ConsumeForResume(s)
			if err == nil {
				winners.Add(1)
				if string(h) != "HANDLE" {
					results <- errors.New("winner got the wrong handle")
					return
				}
			}
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	for err := range results {
		if err != nil && !errors.Is(err, ErrResuming) && !errors.Is(err, ErrTerminal) {
			t.Fatalf("loser got an unexpected error: %v", err)
		}
	}
	if n := winners.Load(); n != 1 {
		t.Fatalf("expected exactly one resume winner, got %d", n)
	}
	// The winning consume de-indexed the pending state, so a fresh callback by that state misses.
	if _, err := m.GetByState("st"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("consumed state must be de-indexed, got %v", err)
	}
}

func TestConsumeForResumeRejectsTerminal(t *testing.T) {
	m := NewMemory()
	s := m.New("c", "st", "B-B", time.Minute)
	m.Update(s, func() { s.Status = StatusCompleted })
	m.Finalize(s)
	if _, err := m.ConsumeForResume(s); !errors.Is(err, ErrTerminal) {
		t.Fatalf("terminal session should reject resume with ErrTerminal, got %v", err)
	}
}

func TestConsumeForResumeClearedByNextRedirect(t *testing.T) {
	// After a consume, indexing a fresh redirect state clears the resuming claim so the next callback
	// (for the new state) may resume again — the legitimate two-redirect flow.
	m := NewMemory()
	s := m.New("c", "s1", "B-B", time.Minute)
	if _, err := m.ConsumeForResume(s); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if _, err := m.ConsumeForResume(s); !errors.Is(err, ErrResuming) {
		t.Fatalf("a second consume before re-index must be rejected, got %v", err)
	}
	m.SetState(s, "s2") // fresh redirect emitted
	if _, err := m.ConsumeForResume(s); err != nil {
		t.Fatalf("consume after the next redirect should succeed: %v", err)
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
