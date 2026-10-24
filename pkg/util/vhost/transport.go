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
	"fmt"
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
// Idle work connections are kept per route and endpoint (the request's
// URL host, RouteConfig.poolHost), as http.Transport kept them, until
// close drops them with the endpoint's proxy.
type workConnTransport struct {
	dial                  func(ctx context.Context) (net.Conn, error)
	responseHeaderTimeout time.Duration
	idleTimeout           time.Duration
	maxIdlePerKey         int
	// onError, when set, gets a response body that broke off: the proxy
	// has sent the headers by then, so it reports nothing itself.
	onError func(*http.Request, error)

	mu     sync.Mutex
	pools  map[string]*workConnPool
	active atomic.Int64 // work connections carrying a request
}

// workConnPool is one route and endpoint's idle work connections. Each
// request holds its pool from choosing it until its connection comes
// back, so a connection that comes back after close is closed too.
type workConnPool struct {
	key     string
	idle    []*workConn // oldest first; reuse takes the newest
	holders int
	closed  bool
}

type workConn struct {
	net.Conn
	br        *bufio.Reader
	bw        *bufio.Writer
	read      int64 // bytes read from the connection, under br
	headEnd   int64 // where read stops while a response head is read; 0 for none
	idleSince time.Time
	busy      atomic.Bool // counted in active
}

// acquire counts wc as carrying a request, release as done with it.
func (t *workConnTransport) acquire(wc *workConn) {
	if wc.busy.CompareAndSwap(false, true) {
		t.active.Add(1)
	}
}

func (t *workConnTransport) release(wc *workConn) {
	if wc.busy.CompareAndSwap(true, false) {
		t.active.Add(-1)
	}
}

// counts reports the work connections kept idle and those carrying a request.
func (t *workConnTransport) counts() (idle, active int) {
	t.mu.Lock()
	for _, p := range t.pools {
		idle += len(p.idle)
	}
	t.mu.Unlock()
	return idle, int(t.active.Load())
}

// workConnWriteBuffer holds a whole ordinary request, so it leaves in one
// write: a yamux frame, a WebSocket frame, a TLS record and a syscall.
const workConnWriteBuffer = 32 << 10

func newWorkConn(c net.Conn) *workConn {
	wc := &workConn{Conn: c, bw: bufio.NewWriterSize(c, workConnWriteBuffer)}
	wc.br = bufio.NewReader(readCounter{wc})
	return wc
}

// A response's status line and headers, and the 1xx responses before it,
// are bounded: a hostile origin could otherwise send a header that never
// ends, all of it held until the header timeout.
const (
	maxResponseHeaderBytes = 64 << 10 // each response head
	max1xxResponses        = 5
)

var (
	errResponseHeadTooLarge = fmt.Errorf("response headers exceed %d bytes", maxResponseHeaderBytes)
	errTooMany1xxResponses  = fmt.Errorf("more than %d 1xx responses", max1xxResponses)
)

// readCounter counts what br reads, so a failure can tell whether any of
// the response had arrived, and stops at headEnd.
type readCounter struct{ wc *workConn }

func (r readCounter) Read(p []byte) (int, error) {
	wc := r.wc
	if wc.headEnd > 0 {
		left := wc.headEnd - wc.read
		if left <= 0 {
			return 0, errResponseHeadTooLarge
		}
		p = p[:min(int64(len(p)), left)]
	}
	n, err := wc.Conn.Read(p)
	wc.read += int64(n)
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

// timeoutError is a net.Error that times out, so the proxy answers 504
// as it did for http.Transport's.
type timeoutError string

func (e timeoutError) Error() string { return string(e) }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

const (
	errResponseHeaderTimeout timeoutError = "timeout awaiting response headers"
	errRequestWriteTimeout   timeoutError = "timeout writing the request"
)

// requestWriter writes a request to its work connection, each write
// within timeout: an origin that stops reading fails the request rather
// than hold it and its visitor. Each write, not the whole request: a
// large body may take long.
type requestWriter struct {
	conn     net.Conn
	timeout  time.Duration
	timedOut bool
}

func (w *requestWriter) Write(p []byte) (int, error) {
	_ = w.conn.SetWriteDeadline(time.Now().Add(w.timeout))
	n, err := w.conn.Write(p)
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		w.timedOut = true
	}
	return n, err
}

func (t *workConnTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	key := req.URL.Host
	switched := false
	for attempt := 0; ; attempt++ {
		p := t.hold(key)
		wc := t.get(p)
		reused := wc != nil
		if wc == nil {
			c, err := t.dial(req.Context())
			if err != nil {
				t.put(p, nil)
				if req.Context().Err() != nil {
					return nil, req.Context().Err()
				}
				stage := StageDial
				if errors.Is(err, ErrNoRouteFound) {
					stage = StageRoute
				} else if next, ok := nextEndpoint(req, switched); ok {
					// Nothing of the request has been sent: once more on
					// another endpoint, any request. Its connections are
					// pooled under its own key.
					switched = true
					key = next
					continue
				}
				return nil, &ProxyError{Stage: stage, Err: err}
			}
			wc = newWorkConn(c)
		}
		t.acquire(wc)
		resp, stale, err := t.roundTrip(wc, p, req)
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

// nextEndpoint moves req to the endpoint after its own, unless it moved
// already, and returns that endpoint's pool key.
func nextEndpoint(req *http.Request, moved bool) (string, bool) {
	rc, _ := req.Context().Value(RouteConfigKey).(*RouteConfig)
	info, _ := req.Context().Value(RouteInfoKey).(*RequestRouteInfo)
	if moved || rc == nil || info == nil || rc.NextEndpointFn == nil {
		return "", false
	}
	next, ok := rc.NextEndpointFn(info.Endpoint)
	if !ok || next == info.Endpoint {
		return "", false
	}
	info.Endpoint = next
	return rc.poolHost(next), true
}

// roundTrip sends req on wc, from p, and reads its response, then puts
// wc back in p. stale is true when the connection failed before any of
// the response arrived.
func (t *workConnTransport) roundTrip(wc *workConn, p *workConnPool, req *http.Request) (resp *http.Response, stale bool, err error) {
	// A visitor who leaves closes the connection, wherever it is.
	stopCancel := context.AfterFunc(req.Context(), func() { _ = wc.Close() })
	fail := func(stage string, err error, stale bool) (*http.Response, bool, error) {
		stopCancel()
		t.release(wc)
		_ = wc.Close()
		t.put(p, nil)
		if req.Context().Err() != nil {
			return nil, false, req.Context().Err()
		}
		return nil, stale, &ProxyError{Stage: stage, Err: err}
	}

	headerTimeout := responseHeaderTimeout(req.Context(), t.responseHeaderTimeout)
	w := &requestWriter{conn: wc.Conn, timeout: headerTimeout}
	wc.bw.Reset(w)
	if proxyMode(req) {
		err = req.WriteProxy(wc.bw)
	} else {
		err = req.Write(wc.bw)
	}
	if err == nil {
		err = wc.bw.Flush()
	}
	if err != nil {
		if w.timedOut {
			// net/http reports it as the body's read error.
			err = errRequestWriteTimeout
		}
		return fail(StageSend, err, true)
	}
	// An upgraded connection's writes start with no deadline.
	_ = wc.SetWriteDeadline(time.Time{})

	before := wc.read
	var timedOut atomic.Bool
	timer := time.AfterFunc(headerTimeout, func() {
		timedOut.Store(true)
		_ = wc.Close()
	})
	for n1xx := 0; ; n1xx++ {
		wc.headEnd = wc.read + maxResponseHeaderBytes
		resp, err = http.ReadResponse(wc.br, req)
		if err != nil || resp.StatusCode < 100 || resp.StatusCode >= 200 || resp.StatusCode == http.StatusSwitchingProtocols {
			break
		}
		if n1xx == max1xxResponses {
			err = errTooMany1xxResponses
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
	wc.headEnd = 0
	if !timer.Stop() || timedOut.Load() {
		return fail(StageHeaders, errResponseHeaderTimeout, false)
	}
	if err != nil {
		// Nothing of a response came: the connection was dead already.
		return fail(StageHeaders, err, wc.read == before)
	}

	if resp.StatusCode == http.StatusSwitchingProtocols {
		// The proxy copies both ways on the connection itself.
		stopCancel()
		t.put(p, nil)
		resp.Body = &upgradedBody{Reader: wc.br, workConn: wc, t: t}
		return resp, false, nil
	}
	resp.Body = &returnBody{
		ReadCloser: resp.Body,
		fail: func(err error) {
			// A visitor who left closed the connection: not the origin's.
			if t.onError != nil && req.Context().Err() == nil {
				t.onError(req, &ProxyError{Stage: StageBody, Err: err})
			}
		},
		done: func(clean bool) {
			reuse := stopCancel() && clean && !resp.Close && !req.Close
			t.release(wc)
			if reuse {
				t.put(p, wc)
			} else {
				_ = wc.Close()
				t.put(p, nil)
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

// hold returns key's pool, held until put.
func (t *workConnTransport) hold(key string) *workConnPool {
	t.mu.Lock()
	defer t.mu.Unlock()
	p := t.pools[key]
	if p == nil {
		if t.pools == nil {
			t.pools = make(map[string]*workConnPool)
		}
		p = &workConnPool{key: key}
		t.pools[key] = p
	}
	p.holders++
	return p
}

// get takes the newest of p's idle work connections that can carry a
// request, if any.
func (t *workConnTransport) get(p *workConnPool) *workConn {
	t.mu.Lock()
	for {
		if len(p.idle) == 0 {
			t.mu.Unlock()
			return nil
		}
		wc := p.idle[len(p.idle)-1]
		p.idle[len(p.idle)-1] = nil
		p.idle = p.idle[:len(p.idle)-1]
		t.mu.Unlock()
		if time.Since(wc.idleSince) < t.idleTimeout && wc.alive() {
			return wc
		}
		_ = wc.Close()
		t.mu.Lock()
	}
}

// put lets go of p, keeping wc, unless nil, idle in it: or closing wc
// when p is closed or full.
func (t *workConnTransport) put(p *workConnPool, wc *workConn) {
	now := time.Now()
	var drop []*workConn
	t.mu.Lock()
	p.holders--
	if wc != nil {
		wc.idleSince = now
		// The oldest are first: drop those idle too long.
		for len(p.idle) > 0 && now.Sub(p.idle[0].idleSince) >= t.idleTimeout {
			drop = append(drop, p.idle[0])
			p.idle = p.idle[1:]
		}
		if !p.closed && len(p.idle) < t.maxIdlePerKey {
			p.idle = append(p.idle, wc)
		} else {
			drop = append(drop, wc)
		}
	}
	if p.holders == 0 && len(p.idle) == 0 && t.pools[p.key] == p {
		delete(t.pools, p.key)
	}
	t.mu.Unlock()
	for _, c := range drop {
		_ = c.Close()
	}
}

// close closes key's idle work connections, and those carrying its
// requests once they are done: their proxy left.
func (t *workConnTransport) close(key string) {
	t.mu.Lock()
	p := t.pools[key]
	var drop []*workConn
	if p != nil {
		delete(t.pools, key)
		p.closed = true
		drop, p.idle = p.idle, nil
	}
	t.mu.Unlock()
	for _, c := range drop {
		_ = c.Close()
	}
}

// returnBody hands its work connection back once the response body has
// been read to the end, and closes it otherwise.
type returnBody struct {
	io.ReadCloser
	once sync.Once
	done func(clean bool)
	fail func(err error) // a read that failed; once
}

func (b *returnBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err == io.EOF {
		b.once.Do(func() { b.done(true) })
	} else if err != nil {
		b.once.Do(func() {
			b.fail(err)
			b.done(false)
		})
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
	t *workConnTransport
}

func (b *upgradedBody) Read(p []byte) (int, error)  { return b.Reader.Read(p) }
func (b *upgradedBody) Write(p []byte) (int, error) { return b.workConn.Conn.Write(p) }
func (b *upgradedBody) Close() error {
	b.t.release(b.workConn)
	return b.workConn.Conn.Close()
}
