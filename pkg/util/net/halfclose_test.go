package net

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	libnet "github.com/fatedier/golib/net"
	"github.com/hashicorp/yamux"
	"github.com/stretchr/testify/require"
)

func tcpPair(t *testing.T) (client, server *net.TCPConn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	done := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		done <- c
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	s := <-done
	require.NotNil(t, s)
	t.Cleanup(func() { c.Close(); s.Close() })
	return c.(*net.TCPConn), s.(*net.TCPConn)
}

func yamuxPair(t *testing.T) (client, server *yamux.Stream) {
	t.Helper()
	a, b := tcpPair(t)
	cs, err := yamux.Client(a, nil)
	require.NoError(t, err)
	ss, err := yamux.Server(b, nil)
	require.NoError(t, err)
	t.Cleanup(func() { cs.Close(); ss.Close() })
	accepted := make(chan *yamux.Stream, 1)
	go func() {
		s, _ := ss.AcceptStream()
		accepted <- s
	}()
	c, err := cs.OpenStream()
	require.NoError(t, err)
	_, err = c.Write([]byte("x")) // the stream reaches the server with data
	require.NoError(t, err)
	s := <-accepted
	require.NotNil(t, s)
	b1 := make([]byte, 1)
	_, err = io.ReadFull(s, b1)
	require.NoError(t, err)
	return c, s
}

// A stream closed one way still carries the other way.
func requireHalfClosed(t *testing.T, closed, peer net.Conn) {
	t.Helper()
	_ = peer.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := peer.Read(make([]byte, 1))
	require.Equal(t, 0, n)
	require.ErrorIs(t, err, io.EOF)
	_, err = peer.Write([]byte("back"))
	require.NoError(t, err)
	b := make([]byte, 4)
	_ = closed.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = io.ReadFull(closed, b)
	require.NoError(t, err)
	require.Equal(t, "back", string(b))
}

func TestCloseWriteThroughWrappers(t *testing.T) {
	c, s := yamuxPair(t)
	var wrapped net.Conn = NewContextConn(context.Background(), WrapStatsConn(WrapCloseNotifyConn(c, nil), nil))
	require.NoError(t, CloseWrite(wrapped))
	requireHalfClosed(t, c, s)

	a, b := tcpPair(t)
	shared, _ := libnet.NewSharedConn(a)
	require.NoError(t, CloseWrite(NewContextConn(context.Background(), shared)))
	requireHalfClosed(t, a, b)

	p, _ := net.Pipe()
	require.ErrorIs(t, CloseWrite(NewContextConn(context.Background(), p)), ErrNoHalfClose)
}

func TestJoinHalfClose(t *testing.T) {
	require := require.New(t)
	// visitor <-> (a, b) <-> backend
	visitor, a := tcpPair(t)
	b, backend := yamuxPair(t)
	done := make(chan [2]int64, 1)
	go func() {
		in, out, err := JoinHalfClose(a, b)
		require.NoError(err)
		done <- [2]int64{in, out}
	}()

	_, err := visitor.Write([]byte("query"))
	require.NoError(err)
	require.NoError(visitor.CloseWrite())
	got, err := io.ReadAll(backend)
	require.NoError(err)
	require.Equal("query", string(got))

	// The backend answers after the visitor's EOF.
	_, err = backend.Write([]byte("result"))
	require.NoError(err)
	require.NoError(backend.Close())
	got, err = io.ReadAll(visitor)
	require.NoError(err)
	require.Equal("result", string(got))

	select {
	case n := <-done:
		require.Equal([2]int64{5, 6}, n)
	case <-time.After(5 * time.Second):
		t.Fatal("join did not end")
	}
}

func TestJoinHalfCloseWithoutHalfClose(t *testing.T) {
	visitor, a := tcpPair(t)
	b, backend := net.Pipe()
	done := make(chan struct{})
	go func() {
		_, _, err := JoinHalfClose(a, b)
		require.ErrorIs(t, err, ErrNoHalfClose)
		close(done)
	}()
	require.NoError(t, visitor.CloseWrite())
	// The pipe cannot close one way: both close.
	_, err := io.ReadAll(backend)
	require.NoError(t, err)
	_, err = io.ReadAll(visitor)
	require.NoError(t, err)
	<-done
}
