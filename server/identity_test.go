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

package server

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
	netpkg "github.com/fatedier/frp/pkg/util/net"
	"github.com/fatedier/frp/pkg/util/util"
)

// identityConn is a connection whose client an embedder authenticated
// before frps saw it, as its mutual TLS would.
type identityConn struct {
	net.Conn
	identity string
}

// connListener hands frps the connections a test dials.
type connListener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func (l *connListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *connListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (*connListener) Addr() net.Addr { return lifecycleTestAddr("embedder") }

// stream is a client's stream to frps, on yamux or QUIC.
type stream interface {
	io.ReadWriteCloser
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

// session is a client's connection to frps, carrying its streams.
type session interface{ open() (stream, error) }

type yamuxSession struct{ *yamux.Session }

func (s yamuxSession) open() (stream, error) { return s.OpenStream() }

type quicSession struct{ *quic.Conn }

func (s quicSession) open() (stream, error) { return s.OpenStreamSync(context.Background()) }

func freePort(t *testing.T, network string) int {
	t.Helper()
	if network == "udp" {
		c, err := net.ListenPacket("udp", "127.0.0.1:0")
		require.NoError(t, err)
		defer c.Close()
		return c.LocalAddr().(*net.UDPAddr).Port
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// identityServer runs frps for an embedder that names its clients
// (ServerConfig.Identity), and returns how a client of an identity, ""
// for none, opens a session to it.
func identityServer(t *testing.T) func(identity string) session {
	t.Helper()
	_, dial := identityService(t)
	return dial
}

// identityService is identityServer, with the frps it runs.
func identityService(t *testing.T) (*Service, func(identity string) session) {
	t.Helper()
	port := freePort(t, "tcp")
	cfg := &v1.ServerConfig{BindAddr: "127.0.0.1", BindPort: port, VhostHTTPPort: port, EnableTCPTLS: true}
	cfg.Identity = func(c net.Conn) string {
		if ic, ok := c.(*identityConn); ok {
			return ic.identity
		}
		return ""
	}
	require.NoError(t, cfg.Complete())
	svr, err := NewService(cfg)
	require.NoError(t, err)
	ln := &connListener{conns: make(chan net.Conn), closed: make(chan struct{})}
	go svr.HandleListener(ln, false)
	t.Cleanup(func() {
		_ = ln.Close()
		_ = svr.Close()
	})

	return svr, func(identity string) session {
		c, s := net.Pipe()
		ln.conns <- &identityConn{Conn: s, identity: identity}
		sess, err := yamux.Client(c, nil)
		require.NoError(t, err)
		t.Cleanup(func() { _ = sess.Close() })
		return yamuxSession{sess}
	}
}

// quicServer runs frps on QUIC, naming every client node/a when named
// (ServerConfig.QUICIdentity), and returns its address.
func quicServer(t *testing.T, named bool) string {
	t.Helper()
	port := freePort(t, "udp")
	cfg := &v1.ServerConfig{BindAddr: "127.0.0.1", BindPort: freePort(t, "tcp"), QUICBindAddr: "127.0.0.1", QUICBindPort: port}
	if named {
		cfg.QUICIdentity = func(tls.ConnectionState) string { return "node/a" }
	}
	require.NoError(t, cfg.Complete())
	svr, err := NewService(cfg)
	require.NoError(t, err)
	go svr.HandleQUICListener(svr.quicListener)
	t.Cleanup(func() { _ = svr.Close() })
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
}

// quicDial connects a client to frps on QUIC at addr.
func quicDial(t *testing.T, addr string) session {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := quic.DialAddr(ctx, addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"frp"}}, &quic.Config{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.CloseWithError(0, "") })
	return quicSession{c}
}

// testClient is a client logged in on a session, with its control.
type testClient struct {
	t      *testing.T
	sess   session
	stream stream
	ctl    io.ReadWriter // encrypted after the login
	runID  string
}

// login logs in on sess with m, and returns frps's refusal if it refused.
func login(t *testing.T, sess session, m msg.Login) (*testClient, error) {
	t.Helper()
	s, err := sess.open()
	require.NoError(t, err)
	ts := time.Now().Unix()
	m.PrivilegeKey, m.Timestamp = util.GetAuthKey("", ts), ts
	require.NoError(t, msg.WriteMsg(s, &m))
	_ = s.SetReadDeadline(time.Now().Add(5 * time.Second))
	var resp msg.LoginResp
	require.NoError(t, msg.ReadMsgInto(s, &resp))
	_ = s.SetReadDeadline(time.Time{})
	if resp.Error != "" {
		_ = s.Close()
		return nil, errors.New(resp.Error)
	}
	rw, err := netpkg.NewCryptoReadWriter(s, nil)
	require.NoError(t, err)
	return &testClient{t: t, sess: sess, stream: s, ctl: rw, runID: resp.RunID}, nil
}

// send writes m on the control.
func (c *testClient) send(m msg.Message) {
	c.t.Helper()
	require.NoError(c.t, msg.WriteMsg(c.ctl, m))
}

// await reads the control until a message of want's type, false if none
// comes within d. The control is unusable after false.
func (c *testClient) await(want msg.Message, d time.Duration) (msg.Message, bool) {
	_ = c.stream.SetReadDeadline(time.Now().Add(d))
	defer func() { _ = c.stream.SetReadDeadline(time.Time{}) }()
	for {
		m, err := msg.ReadMsg(c.ctl)
		if err != nil {
			return nil, false
		}
		if reflect.TypeOf(m) == reflect.TypeOf(want) {
			return m, true
		}
	}
}

// newProxy asks for proxy m, and returns frps's refusal if it refused.
func (c *testClient) newProxy(m msg.NewProxy) error {
	c.t.Helper()
	c.send(&m)
	got, ok := c.await(&msg.NewProxyResp{}, 5*time.Second)
	require.True(c.t, ok, "no answer to proxy [%s]", m.ProxyName)
	if resp := got.(*msg.NewProxyResp); resp.Error != "" {
		return errors.New(resp.Error)
	}
	return nil
}

// visit opens a visitor connection to proxy name on sess, as the client
// of runID, and returns frps's refusal if it refused.
func visit(t *testing.T, sess session, runID, name, sk string) error {
	t.Helper()
	s, err := sess.open()
	require.NoError(t, err)
	defer s.Close()
	ts := time.Now().Unix()
	require.NoError(t, msg.WriteMsg(s, &msg.NewVisitorConn{RunID: runID, ProxyName: name, SignKey: util.GetAuthKey(sk, ts), Timestamp: ts}))
	_ = s.SetReadDeadline(time.Now().Add(5 * time.Second))
	var resp msg.NewVisitorConnResp
	require.NoError(t, msg.ReadMsgInto(s, &resp))
	if resp.Error != "" {
		return errors.New(resp.Error)
	}
	return nil
}

// pooledWorkConn opens a work connection for c on sess, and writes 1 MiB
// on it while it waits, unread, in c's pool: frps takes what its stream
// window grants.
func (c *testClient) pooledWorkConn(sess session) (int, error) {
	c.t.Helper()
	s, err := sess.open()
	require.NoError(c.t, err)
	defer s.Close()
	ts := time.Now().Unix()
	require.NoError(c.t, msg.WriteMsg(s, &msg.NewWorkConn{RunID: c.runID, PrivilegeKey: util.GetAuthKey("", ts), Timestamp: ts}))
	_ = s.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	return s.Write(make([]byte, 1<<20))
}

func requireTimeout(t *testing.T, err error) {
	t.Helper()
	var ne net.Error
	require.True(t, errors.As(err, &ne) && ne.Timeout(), "err %v, want a write that times out", err)
}

func TestIdentityClientsGetSmallStreamWindows(t *testing.T) {
	const window = 256 << 10
	t.Run("yamux", func(t *testing.T) {
		dial := identityServer(t)
		node := dial("node/a")
		c, err := login(t, node, msg.Login{})
		require.NoError(t, err)
		n, err := c.pooledWorkConn(node)
		requireTimeout(t, err)
		require.LessOrEqual(t, n, window)

		plain := dial("")
		c, err = login(t, plain, msg.Login{})
		require.NoError(t, err)
		n, err = c.pooledWorkConn(plain)
		require.NoError(t, err)
		require.Equal(t, 1<<20, n, "a client with no identity keeps frp's 6 MiB window")
	})
	t.Run("quic", func(t *testing.T) {
		node := quicDial(t, quicServer(t, true))
		c, err := login(t, node, msg.Login{})
		require.NoError(t, err)
		n, err := c.pooledWorkConn(node)
		requireTimeout(t, err)
		require.LessOrEqual(t, n, window)

		plain := quicDial(t, quicServer(t, false))
		c, err = login(t, plain, msg.Login{})
		require.NoError(t, err)
		n, err = c.pooledWorkConn(plain)
		requireTimeout(t, err)
		require.Greater(t, n, window, "a server that names no QUIC client keeps quic-go's windows")
	})
}

func TestIdentityClientsRegisterOnlyHTTPAndTCPTLSProxies(t *testing.T) {
	dial := identityServer(t)
	node, err := login(t, dial("node/a"), msg.Login{})
	require.NoError(t, err)
	require.NoError(t, node.newProxy(msg.NewProxy{ProxyName: "web", ProxyType: "http", CustomDomains: []string{"app.example.com"}}))
	require.NoError(t, node.newProxy(msg.NewProxy{ProxyName: "db", ProxyType: "tcp-tls", CustomDomains: []string{"db.example.com"}}))
	for _, typ := range []string{"tcp", "udp", "stcp", "sudp", "xtcp"} {
		require.Error(t, node.newProxy(msg.NewProxy{ProxyName: "node-" + typ, ProxyType: typ, Sk: "key"}), typ)
	}

	plain, err := login(t, dial(""), msg.Login{})
	require.NoError(t, err)
	for _, typ := range []string{"tcp", "stcp"} {
		require.NoError(t, plain.newProxy(msg.NewProxy{ProxyName: "plain-" + typ, ProxyType: typ, Sk: "key"}), typ)
	}
}

func TestIdentityClientsCannotVisit(t *testing.T) {
	dial := identityServer(t)
	plainSess := dial("")
	plain, err := login(t, plainSess, msg.Login{})
	require.NoError(t, err)
	require.NoError(t, plain.newProxy(msg.NewProxy{ProxyName: "secret", ProxyType: "stcp", Sk: "key", AllowUsers: []string{"*"}}))
	require.NoError(t, visit(t, plainSess, plain.runID, "secret", "key"))

	nodeSess := dial("node/a")
	node, err := login(t, nodeSess, msg.Login{})
	require.NoError(t, err)
	require.Error(t, visit(t, nodeSess, node.runID, "secret", "key"))
	require.Error(t, visit(t, nodeSess, plain.runID, "secret", "key"))
}

func TestIdentityClientsCannotPunchHoles(t *testing.T) {
	dial := identityServer(t)
	hole := &msg.NatHoleVisitor{TransactionID: "t", ProxyName: "none", PreCheck: true}

	plain, err := login(t, dial(""), msg.Login{})
	require.NoError(t, err)
	plain.send(hole)
	_, ok := plain.await(&msg.NatHoleResp{}, 5*time.Second)
	require.True(t, ok, "a client with no identity is answered")

	node, err := login(t, dial("node/a"), msg.Login{})
	require.NoError(t, err)
	node.send(hole)
	_, ok = node.await(&msg.NatHoleResp{}, 500*time.Millisecond)
	require.False(t, ok, "a client with an identity is not")
}

func TestIdentityLoginsHaveShortPrintableFields(t *testing.T) {
	dial := identityServer(t)
	long := strings.Repeat("h", 9000)
	for field, m := range map[string]msg.Login{
		"version":   {Version: long},
		"hostname":  {Hostname: long},
		"os":        {Os: long},
		"arch":      {Arch: long},
		"user":      {User: long},
		"client id": {ClientID: strings.Repeat("c", 65)},
		"line":      {ClientID: "a\nb"},
	} {
		_, err := login(t, dial("node/a"), m)
		require.Error(t, err, field)
	}
	_, err := login(t, dial("node/a"), msg.Login{Version: "0.71.0", Hostname: "web-7f9c4", Os: "linux", Arch: "amd64", User: "web-7f9c4", ClientID: "replica-1"})
	require.NoError(t, err)
	_, err = login(t, dial(""), msg.Login{Hostname: long})
	require.NoError(t, err, "a client with no identity is not limited")
}

// relogin logs in on sess until frps admits it, within 5 seconds.
func relogin(t *testing.T, sess session) {
	t.Helper()
	eventually(t, func() error {
		_, err := login(t, sess, msg.Login{})
		return err
	})
}

// eventually retries f until it succeeds, within 5 seconds.
func eventually(t *testing.T, f func() error) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := f()
		if err == nil {
			return
		}
		require.True(t, time.Now().Before(deadline), "still failing: %v", err)
		time.Sleep(50 * time.Millisecond)
	}
}

func httpProxyMsg(name, domain string) msg.NewProxy {
	return msg.NewProxy{ProxyName: name, ProxyType: "http", CustomDomains: []string{domain}}
}

func TestIdentityClientsHaveLimits(t *testing.T) {
	t.Run("logins", func(t *testing.T) {
		dial := identityServer(t)
		sess := dial("node/a")
		var first *testClient
		for i := range 16 {
			c, err := login(t, sess, msg.Login{})
			require.NoError(t, err, "login %d", i)
			if first == nil {
				first = c
			}
		}
		_, err := login(t, sess, msg.Login{})
		require.Error(t, err)
		_, err = login(t, dial("node/a"), msg.Login{})
		require.Error(t, err, "on another connection too")
		_, err = login(t, dial("node/b"), msg.Login{})
		require.NoError(t, err, "another identity has its own")
		_, err = login(t, dial(""), msg.Login{})
		require.NoError(t, err)

		require.NoError(t, first.stream.Close())
		relogin(t, sess)
	})
	t.Run("proxies", func(t *testing.T) {
		dial := identityServer(t)
		a, err := login(t, dial("node/a"), msg.Login{})
		require.NoError(t, err)
		b, err := login(t, dial("node/a"), msg.Login{})
		require.NoError(t, err)
		for i := range 1024 {
			c := a
			if i%2 == 1 {
				c = b
			}
			require.NoError(t, c.newProxy(httpProxyMsg(fmt.Sprint("web", i), "app.example.com")), "proxy %d", i)
		}
		require.Error(t, a.newProxy(httpProxyMsg("web1024", "app.example.com")))
		other, err := login(t, dial("node/b"), msg.Login{})
		require.NoError(t, err)
		require.NoError(t, other.newProxy(httpProxyMsg("other", "other.example.com")))

		a.send(&msg.CloseProxy{ProxyName: "web0"})
		require.NoError(t, a.newProxy(httpProxyMsg("web1024", "app.example.com")))
	})
	t.Run("names", func(t *testing.T) {
		dial := identityServer(t)
		a, err := login(t, dial("node/a"), msg.Login{})
		require.NoError(t, err)
		for i := range 256 {
			require.NoError(t, a.newProxy(httpProxyMsg(fmt.Sprint("site", i), fmt.Sprintf("site%d.example.com", i))), "name %d", i)
		}
		require.Error(t, a.newProxy(httpProxyMsg("site256", "site256.example.com")))
		require.NoError(t, a.newProxy(httpProxyMsg("again", "site0.example.com")), "a name it has")

		a.send(&msg.CloseProxy{ProxyName: "site1"})
		require.NoError(t, a.newProxy(httpProxyMsg("site256", "site256.example.com")))
	})
}

// quicRelay forwards datagrams between one client and frps at addr, and
// reports whether frps sent a Retry: a QUIC version 1 long header packet
// of type 3 (RFC 9000, 17.2.5).
func quicRelay(t *testing.T, addr string) (string, *atomic.Bool) {
	t.Helper()
	front, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	back, err := net.Dial("udp", addr)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = front.Close()
		_ = back.Close()
	})
	var retried atomic.Bool
	var client atomic.Pointer[net.Addr]
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := front.ReadFrom(buf)
			if err != nil {
				return
			}
			client.Store(&from)
			_, _ = back.Write(buf[:n])
		}
	}()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, err := back.Read(buf)
			if err != nil {
				return
			}
			p := buf[:n]
			if n > 5 && p[0]&0xb0 == 0xb0 && binary.BigEndian.Uint32(p[1:5]) == 1 {
				retried.Store(true)
			}
			if to := client.Load(); to != nil {
				_, _ = front.WriteTo(p, *to)
			}
		}
	}()
	return front.LocalAddr().String(), &retried
}

func TestQUICValidatesAddressesWhenItNamesClients(t *testing.T) {
	for _, named := range []bool{true, false} {
		relay, retried := quicRelay(t, quicServer(t, named))
		_, err := login(t, quicDial(t, relay), msg.Login{})
		require.NoError(t, err)
		require.Equal(t, named, retried.Load(), "named %v", named)
	}
}

func TestQUICNegotiatesNoVersionWhenItNamesClients(t *testing.T) {
	for _, named := range []bool{true, false} {
		c, err := net.Dial("udp", quicServer(t, named))
		require.NoError(t, err)
		defer c.Close()
		p := make([]byte, 1200)
		p[0] = 0xc0
		binary.BigEndian.PutUint32(p[1:5], 0x1a2a3a4a)
		p[5] = 8
		p[14] = 8
		_, err = c.Write(p)
		require.NoError(t, err)
		_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := c.Read(p)
		answered := err == nil && n > 5 && binary.BigEndian.Uint32(p[1:5]) == 0
		require.Equal(t, !named, answered, "named %v: a version negotiation packet", named)
	}
}

// A proxy name is its identity's own. Another identity's proxy of the
// same name, registered while the owner reconnects, does not keep the
// owner from its proxy, and so from its name.
func TestIdentitiesHaveTheirOwnProxyNames(t *testing.T) {
	dial := identityServer(t)
	a, err := login(t, dial("node/a"), msg.Login{})
	require.NoError(t, err)
	require.NoError(t, a.newProxy(httpProxyMsg("web", "app.example.com")))
	replica, err := login(t, dial("node/a"), msg.Login{})
	require.NoError(t, err)
	require.Error(t, replica.newProxy(httpProxyMsg("web", "app.example.com")), "one identity's proxy name is one proxy's")

	b, err := login(t, dial("node/b"), msg.Login{})
	require.NoError(t, err)
	require.NoError(t, b.newProxy(httpProxyMsg("web", "squat.example.com")))

	require.NoError(t, a.stream.Close())
	again, err := login(t, dial("node/a"), msg.Login{})
	require.NoError(t, err)
	eventually(t, func() error { return again.newProxy(httpProxyMsg("web", "app.example.com")) })
}

// serveWorkConn opens a work connection on sess for the client of
// runID, and returns frps's refusal if it refused. frps keeps one it
// takes in the client's pool, and says nothing; once frps starts it, it
// answers each request on it with body.
func serveWorkConn(t *testing.T, sess session, runID, body string) error {
	t.Helper()
	s, err := sess.open()
	require.NoError(t, err)
	ts := time.Now().Unix()
	require.NoError(t, msg.WriteMsg(s, &msg.NewWorkConn{RunID: runID, PrivilegeKey: util.GetAuthKey("", ts), Timestamp: ts}))
	_ = s.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	var start msg.StartWorkConn
	err = msg.ReadMsgInto(s, &start)
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		_ = s.Close()
		if err != nil {
			return err
		}
		return errors.New(start.Error)
	}
	_ = s.SetReadDeadline(time.Time{})
	go func() {
		defer s.Close()
		if msg.ReadMsgInto(s, &start) == nil && start.Error == "" {
			answer(s, body, nil)
		}
	}()
	return nil
}

// A run ID is its identity's own. Another identity's client that logs
// in with it, after the owner's client left or while it is logged in,
// keeps the owner from neither, and replaces neither: each identity's
// work connections go to its own client.
func TestIdentitiesHaveTheirOwnRunIDs(t *testing.T) {
	svr, dial := identityService(t)
	a, err := login(t, dial("node/a"), msg.Login{})
	require.NoError(t, err)
	runID := a.runID
	require.NoError(t, a.stream.Close())

	bSess := dial("node/b")
	var b *testClient
	eventually(t, func() error {
		b, err = login(t, bSess, msg.Login{RunID: runID})
		return err
	})
	aSess := dial("node/a")
	a, err = login(t, aSess, msg.Login{RunID: runID})
	require.NoError(t, err, "the owner logs in again")

	require.NoError(t, serveWorkConn(t, bSess, runID, "node/b"))
	require.NoError(t, serveWorkConn(t, aSess, runID, "node/a"))
	require.Error(t, serveWorkConn(t, dial("node/c"), runID, "node/c"))
	require.NoError(t, a.newProxy(httpProxyMsg("web", "app.example.com")))
	require.NoError(t, b.newProxy(httpProxyMsg("web", "other.example.com")))
	require.Equal(t, "node/a", request(svr, "app.example.com"), "a work connection goes to its identity's client")
	require.Equal(t, "node/b", request(svr, "other.example.com"))

	c, err := login(t, dial("node/c"), msg.Login{RunID: runID})
	require.NoError(t, err, "while both are logged in")
	require.NoError(t, c.newProxy(httpProxyMsg("web", "third.example.com")))
	require.NoError(t, a.newProxy(httpProxyMsg("api", "app.example.com")), "and neither is replaced")
	require.NoError(t, b.newProxy(httpProxyMsg("api", "other.example.com")))
}
