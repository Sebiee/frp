package client

import (
	"errors"
	"testing"
	"time"
)

func TestReconnectBackoff(t *testing.T) {
	now := time.Now()
	b := newReconnectBackoff(20 * time.Second)
	b.now = func() time.Time { return now }
	b.lastErr = errors.New("connect: connection refused")

	// Fast for a minute after the first failure.
	d := b.Backoff(0, true)
	for now.Sub(b.firstFail) < fastRetryWindow {
		if d < fastRetryDelay || d > fastRetryDelay*3/2 {
			t.Fatalf("at %s: %s, want 250-375ms", now.Sub(b.firstFail), d)
		}
		now = now.Add(d)
		d = b.Backoff(d, true)
	}
	// Then doubling, from a second, up to the maximum.
	for _, want := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second} {
		if d < want || d > want*11/10 {
			t.Fatalf("after the window: %s, want about %s", d, want)
		}
		d = b.Backoff(d, true)
	}
	for range 10 {
		d = b.Backoff(d, true)
	}
	if d != 20*time.Second {
		t.Fatalf("capped at %s", d)
	}

	// A success starts over: the next loss is fast again.
	b.Backoff(d, false)
	if d = b.Backoff(0, true); d > fastRetryDelay*3/2 {
		t.Fatalf("after a success: %s", d)
	}

	// A refusal from the server backs off at once.
	b = newReconnectBackoff(20 * time.Second)
	b.lastErr = &LoginRefusedError{Msg: "token doesn't match"}
	if d = b.Backoff(0, true); d < time.Second {
		t.Fatalf("refused: %s", d)
	}
}
