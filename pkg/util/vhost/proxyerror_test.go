package vhost

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestWorkConnTransportHeaderTimeoutPerRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
	}))
	defer srv.Close()
	tr, _ := testTransport(t, srv) // 2s by default
	ctx := WithResponseHeaderTimeout(context.Background(), 50*time.Millisecond)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	start := time.Now()
	_, err := tr.RoundTrip(req)
	var pe *ProxyError
	if !errors.As(err, &pe) || pe.Stage != StageHeaders {
		t.Fatalf("err %v, want a %s ProxyError", err, StageHeaders)
	}
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("err %v is not a timeout", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("took %s: the request's timeout was not used", d)
	}
}

func TestWorkConnTransportDialStage(t *testing.T) {
	tr := &workConnTransport{
		dial: func(context.Context) (net.Conn, error) { return nil, ErrNoRouteFound },
	}
	req, _ := http.NewRequest(http.MethodGet, "http://a.example/", nil)
	_, err := tr.RoundTrip(req)
	var pe *ProxyError
	if !errors.As(err, &pe) || pe.Stage != StageRoute {
		t.Fatalf("no route: %v", err)
	}
	tr.dial = func(context.Context) (net.Conn, error) { return nil, errors.New("no work connection") }
	if _, err = tr.RoundTrip(req); !errors.As(err, &pe) || pe.Stage != StageDial {
		t.Fatalf("dial: %v", err)
	}
}

func TestWorkConnTransportBodyErrorAndCounts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/cut" {
			// Promise more than is sent, then drop the connection.
			w.Header().Set("Content-Length", "100")
			io.WriteString(w, "partial")
			w.(http.Flusher).Flush()
			c, _, _ := http.NewResponseController(w).Hijack()
			c.Close()
			return
		}
		io.WriteString(w, "ok")
	}))
	defer srv.Close()
	tr, _ := testTransport(t, srv)
	var got []error
	tr.onError = func(_ *http.Request, err error) { got = append(got, err) }

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	if idle, active := tr.counts(); idle != 0 || active != 1 {
		t.Fatalf("while reading: idle %d active %d", idle, active)
	}
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if idle, active := tr.counts(); idle != 1 || active != 0 {
		t.Fatalf("after: idle %d active %d", idle, active)
	}

	req, _ = http.NewRequest(http.MethodGet, srv.URL+"/cut", nil)
	if resp, err = tr.RoundTrip(req); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(resp.Body); err == nil {
		t.Fatal("read the cut body whole")
	}
	resp.Body.Close()
	var pe *ProxyError
	if len(got) != 1 || !errors.As(got[0], &pe) || pe.Stage != StageBody {
		t.Fatalf("onError got %v, want one %s ProxyError", got, StageBody)
	}
	if _, active := tr.counts(); active != 0 {
		t.Fatalf("a broken connection still counts as active: %d", active)
	}
}
