package vhost

import (
	"net/http"
	"net/http/httputil"
	"testing"
)

func TestSetForwardedKeepsFrontProxyHeaders(t *testing.T) {
	in, out := forwardedPair(t, "127.0.0.1:1234")
	in.Header.Set("X-Forwarded-For", "203.0.113.5")
	in.Header.Set("X-Forwarded-Proto", "https")
	in.Header.Set("X-Forwarded-Host", "app.example.com")

	setForwarded(&httputil.ProxyRequest{In: in, Out: out})

	if got := out.Header.Get("X-Forwarded-Proto"); got != "https" {
		t.Fatalf("proto %q", got)
	}
	if got := out.Header.Get("X-Forwarded-For"); got != "203.0.113.5" {
		t.Fatalf("for %q", got)
	}
	if got := out.Header.Get("X-Forwarded-Host"); got != "app.example.com" {
		t.Fatalf("host %q", got)
	}
}

func TestSetForwardedAppendsNonLoopbackPeer(t *testing.T) {
	in, out := forwardedPair(t, "198.51.100.2:443")
	in.Header.Set("X-Forwarded-For", "203.0.113.5")
	in.Header.Set("X-Forwarded-Proto", "https")

	setForwarded(&httputil.ProxyRequest{In: in, Out: out})

	if got := out.Header.Get("X-Forwarded-For"); got != "203.0.113.5, 198.51.100.2" {
		t.Fatalf("for %q", got)
	}
	if got := out.Header.Get("X-Forwarded-Proto"); got != "https" {
		t.Fatalf("proto %q", got)
	}
}

func forwardedPair(t *testing.T, remote string) (in, out *http.Request) {
	t.Helper()
	in = httptestRequest()
	in.RemoteAddr = remote
	out = in.Clone(in.Context())
	return in, out
}

func httptestRequest() *http.Request {
	req, err := http.NewRequest(http.MethodGet, "http://app.example.com/x", nil)
	if err != nil {
		panic(err)
	}
	req.Host = "app.example.com"
	return req
}
