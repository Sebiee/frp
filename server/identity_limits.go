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
	"fmt"
	"sync"

	v1 "github.com/fatedier/frp/pkg/config/v1"
)

// What one client identity (ServerConfig.Identity, QUICIdentity) may hold
// at once, across all its connections: logged-in clients, each with a
// pool of work connections; their proxies; and the names those route,
// each of which costs the embedder state, a certificate perhaps. Replicas
// sharing a certificate each log in and publish every name: 64 logins
// leave room for about 20 of them on one server, each with a tunnel it is
// replacing and old ones still carrying streams, and 4096 proxies for
// that many logins of a cluster's usual few dozen names. A client without
// an identity has none of these limits.
const (
	maxControlsPerIdentity = 64
	maxProxiesPerIdentity  = 4096
	maxNamesPerIdentity    = 256
)

// identityHoldings counts the proxies of each identity, and the names
// they route.
type identityHoldings struct {
	mu sync.Mutex
	by map[string]*holding
}

type holding struct {
	proxies int
	names   map[string]int // the proxies routing each name
}

// add counts a proxy of identity that routes names, unless that takes
// identity past a limit.
func (h *identityHoldings) add(identity string, names []string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.by == nil {
		h.by = make(map[string]*holding)
	}
	hd := h.by[identity]
	if hd == nil {
		hd = &holding{names: make(map[string]int)}
		h.by[identity] = hd
	}
	hd.proxies++
	for _, name := range names {
		hd.names[name]++
	}
	var err error
	switch {
	case hd.proxies > maxProxiesPerIdentity:
		err = fmt.Errorf("identity [%s] has %d proxies, the most it may", identity, maxProxiesPerIdentity)
	case len(hd.names) > maxNamesPerIdentity:
		err = fmt.Errorf("identity [%s] has %d names, the most it may", identity, maxNamesPerIdentity)
	}
	if err != nil {
		h.removeLocked(identity, names)
	}
	return err
}

// remove uncounts a proxy add counted.
func (h *identityHoldings) remove(identity string, names []string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.removeLocked(identity, names)
}

func (h *identityHoldings) removeLocked(identity string, names []string) {
	hd := h.by[identity]
	hd.proxies--
	for _, name := range names {
		if hd.names[name]--; hd.names[name] == 0 {
			delete(hd.names, name)
		}
	}
	if hd.proxies == 0 {
		delete(h.by, identity)
	}
}

// proxyNames are the names a proxy routes, as its proxy builds them.
func proxyNames(conf v1.ProxyConfigurer, subDomainHost string) []string {
	var domains []string
	subDomain := ""
	switch c := conf.(type) {
	case *v1.HTTPProxyConfig:
		domains, subDomain = c.CustomDomains, c.SubDomain
	case *v1.TCPTLSProxyConfig:
		domains = c.CustomDomains
	}
	names := make([]string, 0, len(domains)+1)
	for _, d := range domains {
		if d != "" {
			names = append(names, d)
		}
	}
	if subDomain != "" {
		names = append(names, subDomain+"."+subDomainHost)
	}
	return names
}
