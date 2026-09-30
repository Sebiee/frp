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
