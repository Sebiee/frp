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

package vhost

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
	"sync"
	"sync/atomic"
	"time"
)

// workConnTransport sends a request over a work connection and reads the
// response on the caller's goroutine. http.Transport hands every request
// to a writer goroutine and every response back from a reader goroutine:
// two wakeups a request, which on a small VM cost more than the proxying.
// Idle work connections are kept per route, as http.Transport kept them.
type workConnTransport struct {
	dial                  func(ctx context.Context) (net.Conn, error)
	responseHeaderTimeout time.Duration
	idleTimeout           time.Duration
	maxIdlePerKey         int

	mu   sync.Mutex
	idle map[string][]*workConn // oldest first; reuse takes the newest
}

type workConn struct {
	net.Conn
	br        *bufio.Reader
	bw        *bufio.Writer
	read      int64 // bytes read from the connection, under br
	idleSince time.Time
}

// workConnWriteBuffer holds a whole ordinary request, so it leaves in one
// write: a yamux frame, a WebSocket frame, a TLS record and a syscall.
const workConnWriteBuffer = 32 << 10

func newWorkConn(c net.Conn) *workConn {
	wc := &workConn{Conn: c, bw: bufio.NewWriterSize(c, workConnWriteBuffer)}
	wc.br = bufio.NewReader(readCounter{wc})
	return wc
}

// readCounter counts what br reads, so a failure can tell whether any of
// the response had arrived.
type readCounter struct{ wc *workConn }

func (r readCounter) Read(p []byte) (int, error) {
	n, err := r.wc.Conn.Read(p)
	r.wc.read += int64(n)
	return n, err
}

// alive reports whether an idle work connection can carry a request: the
// other end has sent nothing, EOF included. The peek hits an expired
// deadline, so it waits for nothing.
func (wc *workConn) alive() bool {
	if wc.br.Buffered() > 0 {
		return false
	}
	if wc.SetReadDeadline(time.Now()) != nil {
		return true // cannot tell; the retry covers it
	}
	_, err := wc.br.Peek(1)
	_ = wc.SetReadDeadline(time.Time{})
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// errResponseHeaderTimeout is a net.Error that times out, so the proxy
// answers 504 as it did for http.Transport's.
type errResponseHeaderTimeout struct{}

func (errResponseHeaderTimeout) Error() string   { return "timeout awaiting response headers" }
func (errResponseHeaderTimeout) Timeout() bool   { return true }
func (errResponseHeaderTimeout) Temporary() bool { return true }

func (t *workConnTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	key := req.URL.Host
	for attempt := 0; ; attempt++ {
		wc := t.get(key)
		reused := wc != nil
		if wc == nil {
			c, err := t.dial(req.Context())
			if err != nil {
				return nil, err
			}
			wc = newWorkConn(c)
		}
		resp, stale, err := t.roundTrip(wc, key, req)
		if err == nil {
			return resp, nil
		}
		// A pooled connection the other end had closed: once more on a
		// fresh one, when nothing of the request can have been used.
		if reused && stale && attempt == 0 && (req.Body == nil || req.Body == http.NoBody) {
			continue
		}
		return nil, err
	}
}

// roundTrip sends req on wc and reads its response. stale is true when
// the connection failed before any of the response arrived.
func (t *workConnTransport) roundTrip(wc *workConn, key string, req *http.Request) (resp *http.Response, stale bool, err error) {
	// A visitor who leaves closes the connection, wherever it is.
	stopCancel := context.AfterFunc(req.Context(), func() { _ = wc.Close() })
	fail := func(err error, stale bool) (*http.Response, bool, error) {
		stopCancel()
		_ = wc.Close()
		if req.Context().Err() != nil {
			return nil, false, req.Context().Err()
		}
		return nil, stale, err
	}

	if proxyMode(req) {
		err = req.WriteProxy(wc.bw)
	} else {
		err = req.Write(wc.bw)
	}
	if err == nil {
		err = wc.bw.Flush()
	}
	if err != nil {
		return fail(err, true)
	}

	before := wc.read
	var timedOut atomic.Bool
	timer := time.AfterFunc(t.responseHeaderTimeout, func() {
		timedOut.Store(true)
		_ = wc.Close()
	})
	for {
		resp, err = http.ReadResponse(wc.br, req)
		if err != nil || resp.StatusCode < 100 || resp.StatusCode >= 200 || resp.StatusCode == http.StatusSwitchingProtocols {
			break
		}
		// 1xx: passed on through the trace, as http.Transport does, for
		// httputil.ReverseProxy to forward.
		if trace := httptrace.ContextClientTrace(req.Context()); trace != nil && trace.Got1xxResponse != nil {
			if err = trace.Got1xxResponse(resp.StatusCode, textproto.MIMEHeader(resp.Header)); err != nil {
				break
			}
		}
	}
	if !timer.Stop() || timedOut.Load() {
		return fail(errResponseHeaderTimeout{}, false)
	}
	if err != nil {
		// Nothing of a response came: the connection was dead already.
		return fail(err, wc.read == before)
	}

	if resp.StatusCode == http.StatusSwitchingProtocols {
		// The proxy copies both ways on the connection itself.
		stopCancel()
		resp.Body = &upgradedBody{Reader: wc.br, workConn: wc}
		return resp, false, nil
	}
	resp.Body = &returnBody{
		ReadCloser: resp.Body,
		done: func(clean bool) {
			reuse := stopCancel() && clean && !resp.Close && !req.Close
			if reuse {
				t.put(key, wc)
			} else {
				_ = wc.Close()
			}
		},
	}
	return resp, false, nil
}

// proxyMode is frp's proxy mode: the request line named a host, so the
// origin gets the absolute URL.
func proxyMode(req *http.Request) bool {
	info, _ := req.Context().Value(RouteInfoKey).(*RequestRouteInfo)
	return info != nil && info.URLHost != ""
}

func (t *workConnTransport) get(key string) *workConn {
	t.mu.Lock()
	for {
		conns := t.idle[key]
		if len(conns) == 0 {
			t.mu.Unlock()
			return nil
		}
		wc := conns[len(conns)-1]
		conns[len(conns)-1] = nil
		t.idle[key] = conns[:len(conns)-1]
		t.mu.Unlock()
		if time.Since(wc.idleSince) < t.idleTimeout && wc.alive() {
			return wc
		}
		_ = wc.Close()
		t.mu.Lock()
	}
}

func (t *workConnTransport) put(key string, wc *workConn) {
	now := time.Now()
	wc.idleSince = now
	var old []*workConn
	t.mu.Lock()
	if t.idle == nil {
		t.idle = make(map[string][]*workConn)
	}
	conns := t.idle[key]
	// The oldest are first: drop those idle too long.
	for len(conns) > 0 && now.Sub(conns[0].idleSince) >= t.idleTimeout {
		old = append(old, conns[0])
		conns = conns[1:]
	}
	if len(conns) < t.maxIdlePerKey {
		conns = append(conns, wc)
		wc = nil
	}
	t.idle[key] = conns
	t.mu.Unlock()
	for _, c := range old {
		_ = c.Close()
	}
	if wc != nil {
		_ = wc.Close()
	}
}

// returnBody hands its work connection back once the response body has
// been read to the end, and closes it otherwise.
type returnBody struct {
	io.ReadCloser
	once sync.Once
	done func(clean bool)
}

func (b *returnBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err == io.EOF {
		b.once.Do(func() { b.done(true) })
	}
	return n, err
}

func (b *returnBody) Close() error {
	// Not read to the end: close the connection first, so Close does not
	// drain the rest of a large body.
	b.once.Do(func() { b.done(false) })
	return b.ReadCloser.Close()
}

// upgradedBody is a 101 response's body: the connection, both ways.
type upgradedBody struct {
	io.Reader
	*workConn
}

func (b *upgradedBody) Read(p []byte) (int, error)  { return b.Reader.Read(p) }
func (b *upgradedBody) Write(p []byte) (int, error) { return b.workConn.Conn.Write(p) }
func (b *upgradedBody) Close() error                { return b.workConn.Conn.Close() }
