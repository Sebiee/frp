package proxy

import (
	"net"
	"testing"
	"time"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/util/xlog"
)

type gotProxy chan net.Conn

func (gotProxy) Run() error { return nil }
func (p gotProxy) InWorkConn(c net.Conn, _ *msg.StartWorkConn) {
	p <- c
}
func (gotProxy) SetInWorkConnCallback(func(*v1.ProxyBaseConfig, net.Conn, *msg.StartWorkConn) bool) {}
func (gotProxy) Close()                                                                             {}

// A work connection that arrives before the reply that starts its proxy
// waits for it, and is closed if the proxy does not start.
func TestInWorkConnWaitsForStart(t *testing.T) {
	got := make(gotProxy, 1)
	pw := &Wrapper{pxy: got, xl: xlog.New()}
	pw.Phase = ProxyPhaseWaitStart
	a, b := net.Pipe()
	defer b.Close()
	pw.InWorkConn(a, &msg.StartWorkConn{})
	time.Sleep(50 * time.Millisecond)
	pw.mu.Lock()
	pw.Phase = ProxyPhaseRunning
	pw.mu.Unlock()
	select {
	case c := <-got:
		if c != a {
			t.Fatal("another connection")
		}
	case <-time.After(time.Second):
		t.Fatal("the work connection was not handed to the started proxy")
	}

	// A proxy that fails to start: the connection is closed.
	pw = &Wrapper{pxy: got, xl: xlog.New()}
	pw.Phase = ProxyPhaseWaitStart
	a, b = net.Pipe()
	pw.InWorkConn(a, &msg.StartWorkConn{})
	pw.mu.Lock()
	pw.Phase = ProxyPhaseStartErr
	pw.mu.Unlock()
	_ = b.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := b.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Fatalf("not closed: %v", err)
	}
}

func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}
