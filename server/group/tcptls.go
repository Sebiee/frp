package group

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
)

// The kinds of proxy a name can belong to: a name is one or the other.
const (
	DomainKindHTTP   = "http"
	DomainKindTCPTLS = "tcp-tls"
)

// DomainClaimedError refuses a proxy whose name the other kind holds.
type DomainClaimedError struct {
	Domain, Refused, Holder string
}

func (e *DomainClaimedError) Error() string {
	return fmt.Sprintf("domain [%s] belongs to %s proxies, it cannot have %s ones too", e.Domain, e.Holder, e.Refused)
}

// DomainClaims holds each name for one kind of proxy, http or tcp-tls,
// while any proxy of that kind has it. The first kind to claim a name
// keeps it; the other kind is refused until the last claim is released.
type DomainClaims struct {
	// OnConflict, when set, is told of each refused claim.
	OnConflict func(domain, refused, holder string)
	// Reserved, when set, are names no proxy may claim: an embedder's
	// own, such as the name its clients log in on.
	Reserved func(domain string) bool

	mu sync.Mutex
	m  map[string]*domainClaim
}

type domainClaim struct {
	kind string
	n    int
}

func NewDomainClaims() *DomainClaims {
	return &DomainClaims{m: make(map[string]*domainClaim)}
}

// Claim holds domain for kind until release is called, or refuses it
// with a *DomainClaimedError. A nil c claims nothing.
func (c *DomainClaims) Claim(domain, kind string) (release func(), err error) {
	if c == nil {
		return func() {}, nil
	}
	domain = strings.ToLower(domain)
	if c.Reserved != nil && c.Reserved(domain) {
		return nil, fmt.Errorf("domain [%s] is reserved", domain)
	}
	c.mu.Lock()
	cl := c.m[domain]
	if cl != nil && cl.kind != kind {
		holder := cl.kind
		c.mu.Unlock()
		if c.OnConflict != nil {
			c.OnConflict(domain, kind, holder)
		}
		return nil, &DomainClaimedError{Domain: domain, Refused: kind, Holder: holder}
	}
	if cl == nil {
		cl = &domainClaim{kind: kind}
		c.m[domain] = cl
	}
	cl.n++
	c.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			c.mu.Lock()
			defer c.mu.Unlock()
			if cl.n--; cl.n == 0 && c.m[domain] == cl {
				delete(c.m, domain)
			}
		})
	}, nil
}

// ErrTCPTLSNoRoute is TCPTLSRoute.Dial's error when the name has no
// route left, or none of its members gave a work connection.
var ErrTCPTLSNoRoute = errors.New("tcp-tls: no route")

// TCPTLSDialFunc opens a work connection to one proxy for a stream from
// src.
type TCPTLSDialFunc func(src net.Addr) (net.Conn, error)

// TCPTLSRoutes are the tcp-tls proxies by name. The proxies of one
// client identity (ServerConfig.Identity) for a name share its route,
// and its streams are spread across them; another identity cannot take
// it. A client without an identity shares a name with no other proxy.
type TCPTLSRoutes struct {
	claims   *DomainClaims
	onDomain func(domain string, added bool)

	mu     sync.RWMutex
	routes map[string]*tcpTLSRoute
}

type tcpTLSRoute struct {
	identity string
	alpn     []string
	members  []tcpTLSMember
	next     atomic.Uint64
}

type tcpTLSMember struct {
	proxy string
	dial  TCPTLSDialFunc
}

// NewTCPTLSRoutes makes the routes, which claim their names in claims.
// onDomain, when set, is told when a name gains its first route and
// loses its last.
func NewTCPTLSRoutes(claims *DomainClaims, onDomain func(domain string, added bool)) *TCPTLSRoutes {
	return &TCPTLSRoutes{claims: claims, onDomain: onDomain, routes: make(map[string]*tcpTLSRoute)}
}

// Register adds proxy, of the client identity, to domain's route, until
// unregister is called.
func (r *TCPTLSRoutes) Register(proxy, identity, domain string, alpn []string, dial TCPTLSDialFunc) (unregister func(), err error) {
	domain = strings.ToLower(domain)
	release, err := r.claims.Claim(domain, DomainKindTCPTLS)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	rt := r.routes[domain]
	switch {
	case rt == nil:
		rt = &tcpTLSRoute{identity: identity, alpn: slices.Clone(alpn)}
		r.routes[domain] = rt
		if r.onDomain != nil {
			r.onDomain(domain, true)
		}
	case identity == "" || rt.identity != identity:
		release()
		return nil, fmt.Errorf("tcp-tls: domain [%s] is already used by another client", domain)
	case !sameProtocols(rt.alpn, alpn):
		release()
		return nil, fmt.Errorf("tcp-tls: domain [%s]: alpn %q differs from its other proxies' %q", domain, alpn, rt.alpn)
	case slices.ContainsFunc(rt.members, func(m tcpTLSMember) bool { return m.proxy == proxy }):
		release()
		return nil, fmt.Errorf("tcp-tls: domain [%s]: proxy [%s] is already registered", domain, proxy)
	}
	rt.members = append(rt.members, tcpTLSMember{proxy: proxy, dial: dial})
	var once sync.Once
	return func() {
		once.Do(func() {
			r.unregister(proxy, domain, rt)
			release()
		})
	}, nil
}

// sameProtocols is whether a and b list the same protocols, in any
// order: the client's preference picks one.
func sameProtocols(a, b []string) bool {
	return slices.Equal(slices.Sorted(slices.Values(a)), slices.Sorted(slices.Values(b)))
}

func (r *TCPTLSRoutes) unregister(proxy, domain string, rt *tcpTLSRoute) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rt.members = slices.DeleteFunc(slices.Clone(rt.members), func(m tcpTLSMember) bool { return m.proxy == proxy })
	if len(rt.members) == 0 && r.routes[domain] == rt {
		delete(r.routes, domain)
		if r.onDomain != nil {
			r.onDomain(domain, false)
		}
	}
}

// TCPTLSRoute is one name's route as an embedder sees it when a stream
// arrives: the client identity whose proxies serve it, and the ALPN
// protocols they accept.
type TCPTLSRoute struct {
	Domain string
	Group  string
	ALPN   []string

	r *TCPTLSRoutes
}

// Get returns domain's route, if it has one.
func (r *TCPTLSRoutes) Get(domain string) (TCPTLSRoute, bool) {
	domain = strings.ToLower(domain)
	r.mu.RLock()
	defer r.mu.RUnlock()
	rt, ok := r.routes[domain]
	if !ok {
		return TCPTLSRoute{}, false
	}
	return TCPTLSRoute{Domain: domain, Group: rt.identity, ALPN: slices.Clone(rt.alpn), r: r}, true
}

// Dial opens a work connection for a stream from src: from the route's
// next member in turn, and from each other member in turn while one
// gives none. Nothing of the stream was sent, so a retry is safe. A
// route that another group took since Get is no route: the stream's
// handshake was for this one.
func (t TCPTLSRoute) Dial(src net.Addr) (net.Conn, error) {
	if t.r == nil {
		return nil, ErrTCPTLSNoRoute
	}
	t.r.mu.RLock()
	rt := t.r.routes[t.Domain]
	var members []tcpTLSMember
	var start uint64
	if rt != nil && rt.identity == t.Group {
		members = rt.members // replaced, never changed in place
		start = rt.next.Add(1) - 1
	}
	t.r.mu.RUnlock()
	errs := []error{ErrTCPTLSNoRoute}
	for i := range members {
		m := members[(start+uint64(i))%uint64(len(members))]
		c, err := m.dial(src)
		if err == nil {
			return c, nil
		}
		errs = append(errs, fmt.Errorf("proxy [%s]: %w", m.proxy, err))
	}
	return nil, errors.Join(errs...)
}
