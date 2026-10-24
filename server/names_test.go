package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"

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
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())
	cfg := &v1.ServerConfig{BindAddr: "127.0.0.1", BindPort: port, VhostHTTPPort: port, EnableTCPTLS: true, OnDomain: onDomain}
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
		GetWorkConnFn:      func() (*proxy.WorkConn, error) { return nil, errors.New(node) },
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
