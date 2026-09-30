//go:build linux

package client

import (
	"context"
	"net"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The hook sets TCP_USER_TIMEOUT and keepalive on the connection it gets.
func TestDeadServerHook(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, got, err := deadServerHook(3*time.Second)(context.Background(), c, ""); err != nil || got != c {
		t.Fatalf("hook: %v", err)
	}
	raw, _ := c.(*net.TCPConn).SyscallConn()
	var ut, ka, idle int
	_ = raw.Control(func(fd uintptr) {
		ut, _ = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT)
		ka, _ = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_KEEPALIVE)
		idle, _ = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_KEEPIDLE)
	})
	if ut != 3000 || ka != 1 || idle != 1 {
		t.Fatalf("TCP_USER_TIMEOUT %d ms, SO_KEEPALIVE %d, TCP_KEEPIDLE %d s", ut, ka, idle)
	}
}
