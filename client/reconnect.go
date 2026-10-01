// Copyright 2026 The frp Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package client

import (
	"context"
	"errors"
	"net"
	"strconv"
	"syscall"
	"time"

	libnet "github.com/fatedier/golib/net"

	"github.com/fatedier/frp/pkg/util/log"
	"github.com/fatedier/frp/pkg/util/wait"
)

// LoginRefusedError is a login the server answered with a refusal.
type LoginRefusedError struct{ Msg string }

func (e *LoginRefusedError) Error() string { return e.Msg }

const (
	// A server that went away is dialed again every fastRetryDelay, plus
	// up to half again of jitter, for fastRetryWindow: it is most likely
	// restarting and back in seconds, and a refused connection means its
	// machine is up and it is about to listen.
	fastRetryDelay  = 250 * time.Millisecond
	fastRetryWindow = time.Minute
)

// reconnectBackoff is how often the client dials a server it lost: fast
// for fastRetryWindow after the first failure, then doubling from a second
// up to maxInterval. A login the server refused backs off at once: asking
// again sooner does not change its answer.
type reconnectBackoff struct {
	maxInterval time.Duration
	now         func() time.Time
	lastErr     error         // the last attempt's, set by the caller
	firstFail   time.Time     // zero until an attempt fails
	base        time.Duration // the backoff before jitter, once past the fast window
}

func newReconnectBackoff(maxInterval time.Duration) *reconnectBackoff {
	return &reconnectBackoff{maxInterval: maxInterval, now: time.Now}
}

func (b *reconnectBackoff) Backoff(prev time.Duration, failed bool) time.Duration {
	if !failed {
		b.firstFail, b.base = time.Time{}, 0
		return time.Second
	}
	now := b.now()
	if b.firstFail.IsZero() {
		b.firstFail = now
	}
	var refused *LoginRefusedError
	if now.Sub(b.firstFail) < fastRetryWindow && !errors.As(b.lastErr, &refused) {
		return wait.Jitter(fastRetryDelay, 0.5)
	}
	b.base = min(max(b.base*2, time.Second), b.maxInterval)
	return min(wait.Jitter(b.base, 0.1), b.maxInterval)
}

// deadServerHook sets the dead-server timeout on the TCP connection to the
// server: keepalive probes every second while it is idle, and, on Linux,
// TCP_USER_TIMEOUT, so data the server leaves unacknowledged for timeout
// closes it. A connection that is not TCP (a proxy's) is left alone.
func deadServerHook(timeout time.Duration) libnet.AfterHookFunc {
	return func(ctx context.Context, c net.Conn, addr string) (context.Context, net.Conn, error) {
		tc, ok := c.(*net.TCPConn)
		if !ok {
			return ctx, c, nil
		}
		err := tc.SetKeepAliveConfig(net.KeepAliveConfig{
			Enable: true, Idle: time.Second, Interval: time.Second, Count: max(int(timeout/time.Second), 1),
		})
		if err == nil {
			err = setUserTimeout(tc, timeout)
		}
		if err != nil {
			// The connection still works; it is only found dead later.
			log.Warnf("dead server timeout on %s: %v", addr, err)
		}
		return ctx, c, nil
	}
}

// staggerInterval is how often awaitServer starts another connection
// attempt while none has connected: a SYN sent while the server's machine
// was still down is lost, and TCP would send it again only after a
// second.
const staggerInterval = 250 * time.Millisecond

// awaitServer returns once the server's TCP port accepts a connection, or
// refuses one, before the client dials it for real. Over tcp, websocket,
// and wss without a proxy, with frpc's own connector; the dial timeout
// bounds it.
func (svr *Service) awaitServer() error {
	if !svr.ownConnector {
		return nil // the embedder's connector, which may not dial TCP
	}
	t := svr.common.Transport
	switch t.Protocol {
	case "tcp", "websocket", "wss":
	default:
		return nil
	}
	if t.ProxyURL != "" {
		return nil
	}
	addr := net.JoinHostPort(svr.common.ServerAddr, strconv.Itoa(svr.common.ServerPort))
	var d net.Dialer
	return awaitPort(svr.ctx, d.DialContext, addr, time.Duration(t.DialServerTimeout)*time.Second)
}

// awaitPort connects to addr, starting a new attempt every
// staggerInterval while none has connected, until one does (it is closed
// at once), one is refused (the machine is up and the port not yet
// listening: the caller retries soon anyway), or timeout passes.
func awaitPort(ctx context.Context, dial func(ctx context.Context, network, addr string) (net.Conn, error),
	addr string, timeout time.Duration,
) error {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	type result struct {
		c   net.Conn
		err error
	}
	// Room for every attempt, so none blocks once nobody is listening.
	results := make(chan result, int(timeout/staggerInterval)+2)
	pending := 0
	attempt := func() {
		pending++
		go func() {
			c, err := dial(ctx, "tcp", addr)
			results <- result{c, err}
		}()
	}
	// The attempts still out are closed when they finish.
	defer func() {
		go func(n int) {
			for range n {
				if r := <-results; r.c != nil {
					r.c.Close()
				}
			}
		}(pending)
	}()
	tick := time.NewTicker(staggerInterval)
	defer tick.Stop()
	attempt()
	var last error
	for {
		select {
		case r := <-results:
			pending--
			if r.err == nil {
				r.c.Close()
				return nil
			}
			last = r.err
			if errors.Is(r.err, syscall.ECONNREFUSED) {
				return r.err
			}
			if pending == 0 && ctx.Err() != nil {
				return last
			}
		case <-tick.C:
			if ctx.Err() == nil {
				attempt()
			}
		case <-ctx.Done():
			if last == nil {
				last = ctx.Err()
			}
			return last
		}
	}
}
