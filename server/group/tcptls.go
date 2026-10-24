package group

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"k8s.io/apimachinery/pkg/util/validation"
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

// DomainOwnedError refuses a proxy whose name another client identity
// holds.
type DomainOwnedError struct {
	Domain string
}

func (e *DomainOwnedError) Error() string {
	return fmt.Sprintf("domain [%s] is already used by another client", e.Domain)
}

// DomainClaims holds each name for one client identity
// (ServerConfig.Identity) and one kind of proxy, http or tcp-tls, while
// any proxy has it: all of a name's locations, HTTP users and routes are
// one identity's. The first to claim a name keeps it; another identity,
// and the other kind, are refused until the last claim is released.
type DomainClaims struct {
	// OnConflict, when set, is told of each claim refused because the
	// other kind holds the name.
	OnConflict func(domain, refused, holder string)
	// Reserved, when set, are names no proxy may claim: an embedder's
	// own, such as the name its clients log in on.
	Reserved func(domain string) bool

	mu sync.Mutex
	m  map[string]*domainClaim
}

type domainClaim struct {
	identity string
	kind     string
	n        int
}

func NewDomainClaims() *DomainClaims {
	return &DomainClaims{m: make(map[string]*domainClaim)}
}

// Claim holds domain, as name, for kind and the client identity until
// release is called. name is its canonical form (canonicalDomain), the
// one to route by. It refuses a name that has none, a reserved one, one
// the other kind holds, with a *DomainClaimedError, and one another
// identity holds, with a *DomainOwnedError. A nil c claims nothing.
func (c *DomainClaims) Claim(domain, kind, identity string) (name string, release func(), err error) {
	name, err = canonicalDomain(domain, kind)
	if err != nil {
		return "", nil, err
	}
	if c == nil {
		return name, func() {}, nil
	}
	if c.Reserved != nil && c.Reserved(name) {
		return "", nil, fmt.Errorf("domain [%s] is reserved", name)
	}
	c.mu.Lock()
	cl := c.m[name]
	switch {
	case cl == nil:
		cl = &domainClaim{identity: identity, kind: kind}
		c.m[name] = cl
	case cl.kind != kind:
		holder := cl.kind
		c.mu.Unlock()
		if c.OnConflict != nil {
			c.OnConflict(name, kind, holder)
		}
		return "", nil, &DomainClaimedError{Domain: name, Refused: kind, Holder: holder}
	case cl.identity != identity:
		c.mu.Unlock()
		return "", nil, &DomainOwnedError{Domain: name}
	}
	cl.n++
	c.mu.Unlock()
	var once sync.Once
	return name, func() {
		once.Do(func() {
			c.mu.Lock()
			defer c.mu.Unlock()
			if cl.n--; cl.n == 0 && c.m[name] == cl {
				delete(c.m, name)
			}
		})
	}, nil
}

// canonicalDomain is domain as frps keys and routes it, in lower case.
// It refuses what a request's host is never compared with, or could be
// spelled another way: a port, a trailing dot, an empty or invalid
// label, an IP address, and a * anywhere but as the first label of an
// http name with two more.
func canonicalDomain(domain, kind string) (string, error) {
	name := strings.ToLower(domain)
	rest, wildcard := strings.CutPrefix(name, "*.")
	labels := strings.Split(rest, ".")
	valid := len(name) <= 253 && !numeric(labels[len(labels)-1])
	if wildcard {
		valid = valid && kind == DomainKindHTTP && len(labels) >= 2
	}
	for _, label := range labels {
		valid = valid && len(validation.IsDNS1123Label(label)) == 0
	}
	if !valid {
		return "", fmt.Errorf("domain [%s] is not a host name: want letters, digits, - and dots, "+
			"no port, trailing dot or IP address, and * only as the first label of an http name", domain)
	}
	return name, nil
}

// numeric is whether a top-level label makes the name an IPv4 address
// to a URL parser: all digits, or 0x and hex digits.
func numeric(label string) bool {
	digits := "0123456789"
	if rest, ok := strings.CutPrefix(label, "0x"); ok {
		label, digits = rest, "0123456789abcdef"
	}
	return strings.Trim(label, digits) == ""
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
	domain, release, err := r.claims.Claim(domain, DomainKindTCPTLS, identity)
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
