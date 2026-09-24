package vhost

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/textproto"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// testTransport is a workConnTransport to srv, counting dials.
func testTransport(t *testing.T, srv *httptest.Server) (*workConnTransport, *atomic.Int32) {
	t.Helper()
	var dials atomic.Int32
	return &workConnTransport{
		dial: func(ctx context.Context) (net.Conn, error) {
			dials.Add(1)
			return (&net.Dialer{}).DialContext(ctx, "tcp", srv.Listener.Addr().String())
		},
		responseHeaderTimeout: 2 * time.Second,
		idleTimeout:           time.Minute,
		maxIdlePerKey:         4,
	}, &dials
}

func get(t *testing.T, tr http.RoundTripper, ctx context.Context, url string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return resp, string(b)
}

func TestWorkConnTransportReusesAConnection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		io.WriteString(w, r.Method+" "+r.URL.RequestURI()+" "+string(b))
	}))
	defer srv.Close()
	tr, dials := testTransport(t, srv)
	for i := range 3 {
		if _, body := get(t, tr, context.Background(), srv.URL+"/a?b=1"); body != "GET /a?b=1 " {
			t.Fatalf("request %d: %q", i, body)
		}
	}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/p", strings.NewReader("hello"))
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "POST /p hello" {
		t.Fatalf("post: %q", b)
	}
	if n := dials.Load(); n != 1 {
		t.Fatalf("%d dials for four requests in a row, want 1", n)
	}
}

func TestWorkConnTransportRetriesAStaleConnection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	defer srv.Close()
	tr, dials := testTransport(t, srv)
	get(t, tr, context.Background(), srv.URL)
	srv.CloseClientConnections() // the origin drops the idle connection
	time.Sleep(50 * time.Millisecond)
	if _, body := get(t, tr, context.Background(), srv.URL); body != "ok" {
		t.Fatalf("after the idle connection closed: %q", body)
	}
	if n := dials.Load(); n != 2 {
		t.Fatalf("%d dials, want 2", n)
	}
}

func TestWorkConnTransportTimesOutAsANetError(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer srv.Close()
	defer close(release)
	tr, _ := testTransport(t, srv)
	tr.responseHeaderTimeout = 100 * time.Millisecond
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	_, err := tr.RoundTrip(req)
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("err %v, want a net.Error that times out (504)", err)
	}
}

func TestWorkConnTransportClosesWhenTheVisitorLeaves(t *testing.T) {
	sent := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/next" {
			return
		}
		io.WriteString(w, "first")
		w.(http.Flusher).Flush()
		close(sent)
		<-r.Context().Done() // until the proxy closes the connection
	}))
	defer srv.Close()
	tr, dials := testTransport(t, srv)
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	<-sent
	cancel()
	done := make(chan struct{})
	go func() { io.Copy(io.Discard, resp.Body); resp.Body.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the body did not end when the visitor left")
	}
	get(t, tr, context.Background(), srv.URL+"/next")
	if n := dials.Load(); n != 2 {
		t.Fatalf("%d dials: a connection closed mid-body was reused", n)
	}
}

func TestWorkConnTransportPassesOn1xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", "</style.css>; rel=preload")
		w.WriteHeader(http.StatusEarlyHints)
		io.WriteString(w, "ok")
	}))
	defer srv.Close()
	tr, _ := testTransport(t, srv)
	var got []int
	ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
		Got1xxResponse: func(code int, _ textproto.MIMEHeader) error { got = append(got, code); return nil },
	})
	resp, body := get(t, tr, ctx, srv.URL)
	if resp.StatusCode != http.StatusOK || body != "ok" || len(got) != 1 || got[0] != http.StatusEarlyHints {
		t.Fatalf("status %d body %q 1xx %v", resp.StatusCode, body, got)
	}
}

func TestWorkConnTransportUpgrades(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer c.Close()
		io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
		line, _ := brw.ReadString('\n')
		io.WriteString(c, "echo "+line)
	}))
	defer srv.Close()
	tr, _ := testTransport(t, srv)
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "echo")
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	rw, ok := resp.Body.(io.ReadWriteCloser)
	if resp.StatusCode != http.StatusSwitchingProtocols || !ok {
		t.Fatalf("status %d, body a ReadWriteCloser: %v", resp.StatusCode, ok)
	}
	defer rw.Close()
	io.WriteString(rw, "hi\n")
	line, _ := bufio.NewReader(rw).ReadString('\n')
	if line != "echo hi\n" {
		t.Fatalf("%q", line)
	}
}
