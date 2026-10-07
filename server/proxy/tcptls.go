package proxy

import (
	"net"
	"reflect"
	"strings"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	netpkg "github.com/fatedier/frp/pkg/util/net"
	"github.com/fatedier/frp/server/metrics"
)

func init() {
	RegisterProxyFactory(reflect.TypeFor[*v1.TCPTLSProxyConfig](), NewTCPTLSProxy)
}

// TCPTLSProxy is a tcp-tls proxy: the embedder ends TLS for its names
// and dials it for each stream (TCPTLSRoutes).
type TCPTLSProxy struct {
	*BaseProxy
	cfg *v1.TCPTLSProxyConfig

	closeFuncs []func()
}

func NewTCPTLSProxy(baseProxy *BaseProxy) Proxy {
	unwrapped, ok := baseProxy.GetConfigurer().(*v1.TCPTLSProxyConfig)
	if !ok {
		return nil
	}
	return &TCPTLSProxy{BaseProxy: baseProxy, cfg: unwrapped}
}

func (pxy *TCPTLSProxy) Run() (remoteAddr string, err error) {
	defer func() {
		if err != nil {
			pxy.Close()
		}
	}()
	identity := netpkg.IdentityFromContext(pxy.ctx)
	for _, domain := range pxy.cfg.CustomDomains {
		var unregister func()
		unregister, err = pxy.rc.TCPTLSRoutes.Register(pxy.name, identity, domain, pxy.cfg.ALPN, pxy.dial)
		if err != nil {
			return "", err
		}
		pxy.closeFuncs = append(pxy.closeFuncs, unregister)
		pxy.xl.Infof("tcp-tls proxy for host [%s] alpn %q group [%s]", domain, pxy.cfg.ALPN, identity)
	}
	return strings.Join(pxy.cfg.CustomDomains, ","), nil
}

// dial is a work connection for one stream from src. The stream is the
// bytes as they come: validation refuses the wrappers a tcp proxy may
// put around it.
func (pxy *TCPTLSProxy) dial(src net.Addr) (net.Conn, error) {
	workConn, err := pxy.GetWorkConnFromPool(src, nil)
	if err != nil {
		return nil, err
	}
	name, proxyType := pxy.GetName(), pxy.GetConfigurer().GetBaseConfig().Type
	metrics.Server.OpenConnection(name, proxyType)
	return netpkg.WrapStatsConn(workConn, func(totalRead, totalWrite int64) {
		metrics.Server.CloseConnection(name, proxyType)
		metrics.Server.AddTrafficIn(name, proxyType, totalWrite)
		metrics.Server.AddTrafficOut(name, proxyType, totalRead)
	}), nil
}

func (pxy *TCPTLSProxy) Close() {
	pxy.BaseProxy.Close()
	for _, closeFn := range pxy.closeFuncs {
		closeFn()
	}
}
