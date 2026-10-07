package validation

import (
	"testing"

	"github.com/stretchr/testify/require"

	v1 "github.com/fatedier/frp/pkg/config/v1"
)

func TestValidateTCPTLSProxy(t *testing.T) {
	good := func() *v1.TCPTLSProxyConfig {
		c := &v1.TCPTLSProxyConfig{CustomDomains: []string{"db.example.com"}, ALPN: []string{"postgresql"}}
		c.Name, c.Type, c.LocalPort = "db", "tcp-tls", 5432
		c.Complete()
		return c
	}
	require.NoError(t, ValidateProxyConfigurerForClient(good()))
	require.NoError(t, ValidateProxyConfigurerForServer(good(), &v1.ServerConfig{EnableTCPTLS: true}))
	require.ErrorContains(t, ValidateProxyConfigurerForServer(good(), &v1.ServerConfig{}), "not supported")

	for name, change := range map[string]func(*v1.TCPTLSProxyConfig){
		"no domains":  func(c *v1.TCPTLSProxyConfig) { c.CustomDomains = nil },
		"wildcard":    func(c *v1.TCPTLSProxyConfig) { c.CustomDomains = []string{"*.example.com"} },
		"bad name":    func(c *v1.TCPTLSProxyConfig) { c.CustomDomains = []string{"db_1.example.com"} },
		"empty alpn":  func(c *v1.TCPTLSProxyConfig) { c.ALPN = []string{""} },
		"acme alpn":   func(c *v1.TCPTLSProxyConfig) { c.ALPN = []string{"acme-tls/1"} },
		"encryption":  func(c *v1.TCPTLSProxyConfig) { c.Transport.UseEncryption = true },
		"compression": func(c *v1.TCPTLSProxyConfig) { c.Transport.UseCompression = true },
		"plugin":      func(c *v1.TCPTLSProxyConfig) { c.Plugin.Type = "http_proxy" },
	} {
		c := good()
		change(c)
		require.Error(t, validateTCPTLSProxyConfig(c), name)
	}
}
