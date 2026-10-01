package client

import (
	"context"
	"errors"
	"net"
	"os"
	"sync/atomic"
	"syscall"
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

// A first attempt whose SYN was lost does not hold the dial: the next,
// a stagger later, finds the server.
func TestAwaitPortStaggers(t *testing.T) {
	var n atomic.Int32
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		if n.Add(1) == 1 {
			<-ctx.Done() // lost: TCP would send it again only after a second
			return nil, ctx.Err()
		}
		a, b := net.Pipe()
		b.Close()
		return a, nil
	}
	start := time.Now()
	if err := awaitPort(context.Background(), dial, "edge:443", 2*time.Second); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > staggerInterval+200*time.Millisecond {
		t.Fatalf("took %s: the lost attempt held the dial", took)
	}

	refused := func(context.Context, string, string) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	}
	start = time.Now()
	if err := awaitPort(context.Background(), refused, "edge:443", 2*time.Second); !errors.Is(err, syscall.ECONNREFUSED) || time.Since(start) > 100*time.Millisecond {
		t.Fatalf("refused: %v after %s", err, time.Since(start))
	}

	lost := func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	start = time.Now()
	if err := awaitPort(context.Background(), lost, "edge:443", 600*time.Millisecond); err == nil || time.Since(start) > time.Second {
		t.Fatalf("nothing answers: %v after %s", err, time.Since(start))
	}
}

func TestAwaitPortLoopback(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var d net.Dialer
	if err := awaitPort(context.Background(), d.DialContext, ln.Addr().String(), time.Second); err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	if err := awaitPort(context.Background(), d.DialContext, addr, time.Second); !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("closed port: %v", err)
	}
}
