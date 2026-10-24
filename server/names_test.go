package server

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/fatedier/frp/pkg/config"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
	netpkg "github.com/fatedier/frp/pkg/util/net"
	"github.com/fatedier/frp/pkg/util/vhost"
	"github.com/fatedier/frp/server/proxy"
)

func newNamesTestService(t *testing.T, onDomain func(domain string, added bool)) *Service {
	t.Helper()
	return newNamesTestServiceWith(t, func(cfg *v1.ServerConfig) { cfg.OnDomain = onDomain })
}

// newNamesTestServiceWith runs frps with the embedder's settings set.
func newNamesTestServiceWith(t *testing.T, set func(*v1.ServerConfig)) *Service {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())
	cfg := &v1.ServerConfig{BindAddr: "127.0.0.1", BindPort: port, VhostHTTPPort: port, EnableTCPTLS: true}
	set(cfg)
	require.NoError(t, cfg.Complete())
	svr, err := NewService(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { svr.Close() })
	return svr
}

// publish registers pc for the client identity node as frps does a
// client's NewProxy, and returns the proxy's Close: node leaving. The
// node's work connections fail with its name, which reach reports.
func publish(t *testing.T, svr *Service, node string, pc v1.ProxyConfigurer) (func(), error) {
	t.Helper()
	return publishWith(t, svr, node, pc, func() (*proxy.WorkConn, error) { return nil, errors.New(node) })
}

// publishWith is publish with the node's work connections from
// workConn.
func publishWith(t *testing.T, svr *Service, node string, pc v1.ProxyConfigurer, workConn proxy.GetWorkConnFn) (func(), error) {
	t.Helper()
	m := &msg.NewProxy{}
	pc.MarshalToMsg(m)
	conf, err := config.NewProxyConfigurerFromMsg(m, svr.cfg)
	if err != nil {
		return nil, err
	}
	pxy, err := proxy.NewProxy(netpkg.WithIdentity(context.Background(), node), &proxy.Options{
		Configurer:         conf,
		ResourceController: svr.rc,
		ServerCfg:          svr.cfg,
		GetWorkConnFn:      workConn,
	})
	require.NoError(t, err)
	if _, err := pxy.Run(); err != nil {
		return nil, err
	}
	leave := sync.OnceFunc(pxy.Close)
	t.Cleanup(leave)
	return leave, nil
}

// reach is the node a request for host, path and HTTP user goes to, or
// "none".
func reach(svr *Service, host, path, user string) string {
	_, err := svr.rc.HTTPReverseProxy.CreateConnection(&vhost.RequestRouteInfo{Host: host, URL: path, HTTPUser: user}, false)
	if errors.Is(err, vhost.ErrNoRouteFound) {
		return "none"
	}
	return err.Error()
}

func httpProxy(name, domain, user string, locations ...string) v1.ProxyConfigurer {
	c := &v1.HTTPProxyConfig{DomainConfig: v1.DomainConfig{CustomDomains: []string{domain}}, Locations: locations, RouteByHTTPUser: user}
	c.Name, c.Type = name, string(v1.ProxyTypeHTTP)
	return c
}

func tcpTLSProxy(name, domain string) v1.ProxyConfigurer {
	c := &v1.TCPTLSProxyConfig{CustomDomains: []string{domain}}
	c.Name, c.Type = name, string(v1.ProxyTypeTCPTLS)
	return c
}

func TestNameBelongsToOneIdentity(t *testing.T) {
	svr := newNamesTestService(t, nil)
	_, err := publish(t, svr, "victim", httpProxy("web", "app.example.com", ""))
	require.NoError(t, err)

	for _, pc := range []v1.ProxyConfigurer{
		httpProxy("same", "app.example.com", ""),
		httpProxy("root", "app.example.com", "", "/"),
		httpProxy("login", "app.example.com", "", "/login"),
		httpProxy("alice", "app.example.com", "alice"),
		tcpTLSProxy("tcp", "app.example.com"),
	} {
		_, err := publish(t, svr, "attacker", pc)
		require.Error(t, err, pc.GetBaseConfig().Name)
	}
	require.Equal(t, "victim", reach(svr, "app.example.com", "/", ""))
	require.Equal(t, "victim", reach(svr, "app.example.com", "/login", ""))
	require.Equal(t, "victim", reach(svr, "app.example.com", "/", "alice"))

	_, err = publish(t, svr, "victim", httpProxy("api", "app.example.com", "", "/api"))
	require.NoError(t, err, "one identity has as many locations as it likes")
	_, err = publish(t, svr, "victim", httpProxy("bob", "app.example.com", "bob"))
	require.NoError(t, err, "and HTTP users")
	require.Equal(t, "victim", reach(svr, "app.example.com", "/api/items", ""))
}

func TestNamesAreCanonical(t *testing.T) {
	var added []string
	svr := newNamesTestService(t, func(domain string, up bool) {
		if up {
			added = append(added, domain)
		}
	})
	for _, name := range []string{
		"app.example.com.",
		"app.example.com:443",
		"app..example.com",
		".app.example.com",
		"203.0.113.7",
		"[2001:db8::1]",
		"*",
		"app.*.example.com",
		"*.*.example.com",
		"*.com",
		"app_1.example.com",
	} {
		_, err := publish(t, svr, "node", httpProxy("web", name, ""))
		require.Error(t, err, name)
	}
	_, err := publish(t, svr, "node", tcpTLSProxy("db", "db.example.com."))
	require.Error(t, err)

	_, err = publish(t, svr, "node", httpProxy("web", "App.Example.com", ""))
	require.NoError(t, err)
	_, err = publish(t, svr, "node", httpProxy("wild", "*.Example.org", ""))
	require.NoError(t, err)
	require.Equal(t, []string{"app.example.com", "*.example.org"}, added)
	require.Equal(t, "node", reach(svr, "app.example.com", "/", ""))
	require.Equal(t, "node", reach(svr, "x.example.org", "/", ""))
}

func TestExactNameMissesStayWithItsIdentity(t *testing.T) {
	svr := newNamesTestService(t, nil)
	_, err := publish(t, svr, "wild", httpProxy("wild", "*.example.com", ""))
	require.NoError(t, err)
	leave, err := publish(t, svr, "victim", httpProxy("app", "app.example.com", "", "/api"))
	require.NoError(t, err)
	_, err = publish(t, svr, "victim", httpProxy("vault", "vault.example.com", "alice"))
	require.NoError(t, err)

	for _, c := range []struct{ host, path, user, want string }{
		{"app.example.com", "/api/items", "", "victim"},
		{"app.example.com", "/login", "", "none"},
		{"app.example.com", "/", "", "none"},
		{"vault.example.com", "/", "alice", "victim"},
		{"vault.example.com", "/", "bob", "none"},
		{"vault.example.com", "/", "", "none"},
		{"other.example.com", "/", "", "wild"},
	} {
		require.Equal(t, c.want, reach(svr, c.host, c.path, c.user), fmt.Sprintf("%s%s user=%q", c.host, c.path, c.user))
	}

	leave()
	require.Equal(t, "none", reach(svr, "app.example.com", "/api/items", ""), "while its tunnel is away")

	_, err = publish(t, svr, "victim", httpProxy("wild2", "*.example.org", ""))
	require.NoError(t, err)
	_, err = publish(t, svr, "victim", httpProxy("api", "api.example.org", "", "/v1"))
	require.NoError(t, err)
	require.Equal(t, "victim", reach(svr, "api.example.org", "/", ""), "its own wildcard still takes its misses")
}

func TestNameWaitsForItsIdentity(t *testing.T) {
	svr := newNamesTestService(t, nil)
	leave, err := publish(t, svr, "victim", httpProxy("web", "app.example.com", ""))
	require.NoError(t, err)
	leaveDB, err := publish(t, svr, "victim", tcpTLSProxy("db", "db.example.com"))
	require.NoError(t, err)
	leave()
	leaveDB()

	for _, pc := range []v1.ProxyConfigurer{
		httpProxy("web", "app.example.com", ""),
		tcpTLSProxy("tcp", "app.example.com"),
		httpProxy("db", "db.example.com", ""),
		tcpTLSProxy("db", "db.example.com"),
	} {
		_, err := publish(t, svr, "attacker", pc)
		require.Error(t, err, pc.GetBaseConfig().Name)
	}

	_, err = publish(t, svr, "victim", httpProxy("web", "app.example.com", ""))
	require.NoError(t, err, "its owner gets it back")
	require.Equal(t, "victim", reach(svr, "app.example.com", "/", ""))
	_, err = publish(t, svr, "victim", httpProxy("db", "db.example.com", ""))
	require.NoError(t, err, "as either kind")
}

func TestLocationsAreBounded(t *testing.T) {
	svr := newNamesTestService(t, nil)
	locations := func(from, n int) []string {
		var l []string
		for i := range n {
			l = append(l, fmt.Sprintf("/p%d", from+i))
		}
		return l
	}
	_, err := publish(t, svr, "node", httpProxy("many", "a.example.com", "", locations(0, 65)...))
	require.Error(t, err)
	for _, l := range []string{"//admin", "admin", "/a/../admin", "/a/./b", "/a//b", "/."} {
		_, err := publish(t, svr, "node", httpProxy("unclean", "b.example.com", "", l))
		require.Error(t, err, l)
	}

	_, err = publish(t, svr, "node", httpProxy("full", "c.example.com", "", locations(0, 64)...))
	require.NoError(t, err)
	_, err = publish(t, svr, "node", httpProxy("more", "c.example.com", "", "/more"))
	require.Error(t, err, "a domain has at most 64 routes")
	_, err = publish(t, svr, "node", httpProxy("user", "c.example.com", "alice"))
	require.Error(t, err, "of all its HTTP users")
	require.Equal(t, "node", reach(svr, "c.example.com", "/p63", ""))

	_, err = publish(t, svr, "node", httpProxy("clean", "d.example.com", "", "", "/", "/api/", "/static"))
	require.NoError(t, err)
}

// An embedder restoring, after frps restarted, the names its clients
// had binds each to its client identity before they log in: another
// identity is refused it for the grace, and its owner has it back.
func TestEmbedderRestoresNames(t *testing.T) {
	type refusal struct{ domain, refused, owner string }
	var refusals []refusal
	svr := newNamesTestServiceWith(t, func(cfg *v1.ServerConfig) {
		cfg.ReservedDomain = func(d string) bool { return d == "tunnel.example.com" }
		cfg.OnDomainOwned = func(d, refused, owner string) { refusals = append(refusals, refusal{d, refused, owner}) }
	})
	require.NoError(t, svr.BindDomain("app.example.com", "victim"))
	require.NoError(t, svr.BindDomain("db.example.com", "victim"))
	require.Error(t, svr.BindDomain("app.example.com", "attacker"))
	require.Error(t, svr.BindDomain("tunnel.example.com", "victim"))
	owner, ok := svr.DomainOwner("App.example.com")
	require.True(t, ok)
	require.Equal(t, "victim", owner)
	_, ok = svr.DomainOwner("other.example.com")
	require.False(t, ok)

	_, err := publish(t, svr, "attacker", httpProxy("web", "app.example.com", ""))
	require.Error(t, err)
	_, err = publish(t, svr, "attacker", tcpTLSProxy("db", "db.example.com"))
	require.Error(t, err)
	require.Equal(t, []refusal{{"app.example.com", "attacker", "victim"}, {"db.example.com", "attacker", "victim"}}, refusals)

	_, err = publish(t, svr, "victim", httpProxy("web", "app.example.com", ""))
	require.NoError(t, err)
	require.Equal(t, "victim", reach(svr, "app.example.com", "/", ""))
}

// The embedder sets the grace, and may change it while names are in
// theirs: each follows it.
func TestEmbedderSetsTheGrace(t *testing.T) {
	svr := newNamesTestService(t, nil)
	leave, err := publish(t, svr, "victim", httpProxy("web", "app.example.com", ""))
	require.NoError(t, err)
	leave()
	_, err = publish(t, svr, "attacker", httpProxy("web", "app.example.com", ""))
	require.Error(t, err, "10 minutes until set")

	time.Sleep(20 * time.Millisecond)
	svr.SetDomainGrace(10 * time.Millisecond)
	_, err = publish(t, svr, "attacker", httpProxy("web", "app.example.com", ""))
	require.NoError(t, err, "a name past the new grace is free")
	_, ok := svr.DomainOwner("app.example.com")
	require.True(t, ok)
}

// origin answers each request on its node's work connections with the
// node's name, and keeps the connection open after, as frpc does for an
// origin that keeps connections alive. With hold set, it tells requests
// of each request, and answers once hold is closed.
type origin struct {
	node     string
	hold     chan struct{}
	requests chan struct{}
	closed   atomic.Int32 // work connections frps closed
}

func (o *origin) workConn() (*proxy.WorkConn, error) {
	c, conn := net.Pipe()
	go func() {
		defer o.closed.Add(1)
		defer conn.Close()
		var start msg.StartWorkConn
		if msg.ReadMsgInto(conn, &start) != nil {
			return
		}
		br := bufio.NewReader(conn)
		for {
			req, err := http.ReadRequest(br)
			if err != nil {
				return
			}
			if o.hold != nil {
				o.requests <- struct{}{}
				<-o.hold
			}
			_, _ = io.Copy(io.Discard, req.Body)
			resp := &http.Response{
				StatusCode: http.StatusOK, ProtoMajor: 1, ProtoMinor: 1,
				ContentLength: int64(len(o.node)), Body: io.NopCloser(strings.NewReader(o.node)),
			}
			if resp.Write(conn) != nil {
				return
			}
		}
	}()
	return proxy.NewWorkConn(msg.NewConn(c, msg.NewV1ReadWriter(c))), nil
}

// request is a visitor's request for host: the body frps answered with.
func request(svr *Service, host string) string {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = host
	svr.VhostHTTP().ServeHTTP(rec, req)
	return rec.Body.String()
}

func idleWorkConns(svr *Service) int {
	_, idle, _ := svr.WorkConns()
	return idle
}

// A proxy's idle work connections go with it: frps closes them, so
// neither another identity that has the name next, nor its proxy of the
// same name, gets a connection to the node that left.
func TestIdleWorkConnsLeaveWithTheirProxy(t *testing.T) {
	svr := newNamesTestService(t, nil)
	svr.SetDomainGrace(0)
	b := &origin{node: "node/b"}
	leave, err := publishWith(t, svr, "node/b", httpProxy("web", "app.example.com", ""), b.workConn)
	require.NoError(t, err)
	require.Equal(t, "node/b", request(svr, "app.example.com"))
	require.Equal(t, 1, idleWorkConns(svr))

	leave()
	require.Eventually(t, func() bool { return b.closed.Load() == 1 }, 5*time.Second, 10*time.Millisecond)
	require.Zero(t, idleWorkConns(svr))

	a := &origin{node: "node/a"}
	_, err = publishWith(t, svr, "node/a", httpProxy("web", "app.example.com", ""), a.workConn)
	require.NoError(t, err)
	require.Equal(t, "node/a", request(svr, "app.example.com"))
}

// A work connection carrying a request when its proxy leaves is closed
// once the request is done, not kept idle.
func TestWorkConnsInFlightLeaveWithTheirProxy(t *testing.T) {
	svr := newNamesTestService(t, nil)
	b := &origin{node: "node/b", hold: make(chan struct{}), requests: make(chan struct{}, 1)}
	leave, err := publishWith(t, svr, "node/b", httpProxy("web", "app.example.com", ""), b.workConn)
	require.NoError(t, err)
	got := make(chan string)
	go func() { got <- request(svr, "app.example.com") }()
	<-b.requests
	leave()
	close(b.hold)
	require.Equal(t, "node/b", <-got)
	require.Zero(t, idleWorkConns(svr))
	require.Eventually(t, func() bool { return b.closed.Load() == 1 }, 5*time.Second, 10*time.Millisecond)
}
