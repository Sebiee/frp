package proxy

import (
	"net"
	"reflect"
	"strconv"
	"time"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
	netpkg "github.com/fatedier/frp/pkg/util/net"
)

func init() {
	RegisterProxyFactory(reflect.TypeFor[*v1.TCPTLSProxyConfig](), NewTCPTLSProxy)
}

// localKeepAlive keeps the connection to the local service alive while a
// session sits idle for hours, as database tools leave them, and finds
// a service that went away within about a minute.
var localKeepAlive = net.KeepAliveConfig{Enable: true, Idle: 30 * time.Second, Interval: 10 * time.Second, Count: 3}

// TCPTLSProxy is a tcp-tls proxy: the server ended the stream's TLS, and
// each work connection carries the decrypted stream to the local service
// as it comes, closed one way at a time.
type TCPTLSProxy struct {
	*BaseProxy
}

func NewTCPTLSProxy(baseProxy *BaseProxy, _ v1.ProxyConfigurer) Proxy {
	return &TCPTLSProxy{BaseProxy: baseProxy}
}

func (pxy *TCPTLSProxy) InWorkConn(conn net.Conn, m *msg.StartWorkConn) {
	if pxy.inWorkConnCallback != nil && !pxy.inWorkConnCallback(pxy.baseCfg, conn, m) {
		return
	}
	pxy.handleStream(conn, m)
}

func (pxy *TCPTLSProxy) handleStream(workConn net.Conn, m *msg.StartWorkConn) {
	xl := pxy.xl
	baseCfg := pxy.baseCfg
	addr := net.JoinHostPort(baseCfg.LocalIP, strconv.Itoa(baseCfg.LocalPort))
	d := net.Dialer{Timeout: 10 * time.Second, KeepAliveConfig: localKeepAlive}
	localConn, err := d.DialContext(pxy.ctx, "tcp", addr)
	if err != nil {
		workConn.Close()
		xl.Errorf("connect to local service [%s] error: %v", addr, err)
		return
	}
	if v := baseCfg.Transport.ProxyProtocolVersion; v != "" && m.SrcAddr != "" && m.SrcPort != 0 {
		if m.DstAddr == "" {
			m.DstAddr = "127.0.0.1"
		}
		src, err1 := net.ResolveTCPAddr("tcp", net.JoinHostPort(m.SrcAddr, strconv.Itoa(int(m.SrcPort))))
		dst, err2 := net.ResolveTCPAddr("tcp", net.JoinHostPort(m.DstAddr, strconv.Itoa(int(m.DstPort))))
		if err1 == nil && err2 == nil {
			if _, err := netpkg.BuildProxyProtocolHeaderStruct(src, dst, v).WriteTo(localConn); err != nil {
				workConn.Close()
				localConn.Close()
				xl.Errorf("write proxy protocol header to local conn error: %v", err)
				return
			}
		}
	}
	in, out, err := netpkg.JoinHalfClose(workConn, localConn)
	xl.Debugf("tcp-tls stream closed, in %d out %d bytes", in, out)
	if err != nil {
		xl.Tracef("tcp-tls stream error: %v", err)
	}
}
