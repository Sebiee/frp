package net

import (
	"errors"
	"io"
	"net"
	"sync"

	libnet "github.com/fatedier/golib/net"
	"github.com/hashicorp/yamux"
)

// ErrNoHalfClose is CloseWrite's error for a connection whose sending
// half cannot end apart from the receiving one, such as a WebSocket.
var ErrNoHalfClose = errors.New("connection cannot close one way")

// WrappedConn is a connection frp wraps another with, which writes to it
// as they come: CloseWrite looks through it.
type WrappedConn interface {
	WrappedConn() net.Conn
}

// CloseWrite ends c's sending half: the peer reads EOF, and c can still
// read what the peer sends. It looks through frp's own wrappers to the
// stream under them: a yamux stream, whose Close ends only the sending
// half until the peer's ends too; a QUIC stream; a TCP or TLS connection.
func CloseWrite(c net.Conn) error {
	for c != nil {
		switch v := c.(type) {
		case *yamux.Stream:
			return v.Close()
		case interface{ CloseWrite() error }:
			return v.CloseWrite()
		case WrappedConn:
			c = v.WrappedConn()
		case *libnet.SharedConn:
			c = v.Conn
		default:
			return ErrNoHalfClose
		}
	}
	return ErrNoHalfClose
}

func (c *ContextConn) WrappedConn() net.Conn      { return c.Conn }
func (cc *CloseNotifyConn) WrappedConn() net.Conn { return cc.Conn }
func (statsConn *StatsConn) WrappedConn() net.Conn {
	return statsConn.Conn
}

// CloseWrite ends the stream's sending half; Close also stops reading.
func (conn *wrapQuicStream) CloseWrite() error { return conn.Stream.Close() }

// JoinHalfClose copies a to b and b to a until both directions end, then
// closes both. A direction that reaches EOF ends the other side's sending
// half (CloseWrite), so the rest still flows the other way. One that
// fails, or whose peer cannot close one way, closes both; err is the
// first such failure.
func JoinHalfClose(a, b net.Conn) (aToB, bToA int64, err error) {
	var (
		wg    sync.WaitGroup
		once  sync.Once
		first error
	)
	closeBoth := func(e error) {
		once.Do(func() {
			first = e
			_ = a.Close()
			_ = b.Close()
		})
	}
	pipe := func(dst, src net.Conn, n *int64) {
		defer wg.Done()
		var e error
		*n, e = io.Copy(dst, src)
		if e == nil {
			if e = CloseWrite(dst); e == nil {
				return
			}
		}
		closeBoth(e)
	}
	wg.Add(2)
	go pipe(b, a, &aToB)
	go pipe(a, b, &bToA)
	wg.Wait()
	closeBoth(nil)
	return aToB, bToA, first
}
