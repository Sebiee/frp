package vhost

import (
	"cmp"
	"errors"
	"fmt"
	"iter"
	"slices"
	"strings"
	"sync"
)

var ErrRouterConfigConflict = errors.New("router config conflict")

// maxRoutesPerDomain bounds a domain's routes, every location of every
// HTTP user: Add and Del sort and copy them, and each request scans
// them, under the routers' lock.
const maxRoutesPerDomain = 64

var errDomainFull = fmt.Errorf("router: a domain has at most %d routes", maxRoutesPerDomain)

type routerByHTTPUser map[string][]*Router

type Routers struct {
	indexByDomain map[string]routerByHTTPUser

	// OnDomain is called when a domain is inserted into indexByDomain and
	// when that entry is deleted. added is true for the insert.
	OnDomain func(domain string, added bool)
	// Owner, when set, names the client identity a domain belongs to, if
	// any. A request for a domain that belongs to one goes to no other
	// identity's wildcard domain: not for a path or HTTP user its routes
	// miss, nor while it has none. It is called with the routers locked.
	Owner func(domain string) (identity string, ok bool)

	mutex sync.RWMutex
}

type Router struct {
	domain   string
	location string
	httpUser string

	// store any object here
	payload any
}

func NewRouters() *Routers {
	return &Routers{
		indexByDomain: make(map[string]routerByHTTPUser),
	}
}

func (r *Routers) Add(domain, location, httpUser string, payload any) error {
	domain = strings.ToLower(domain)

	r.mutex.Lock()
	defer r.mutex.Unlock()

	if _, exist := r.exist(domain, location, httpUser); exist {
		return ErrRouterConfigConflict
	}

	routersByHTTPUser, domainAlreadyKnown := r.indexByDomain[domain]
	routes := 0
	for _, vrs := range routersByHTTPUser {
		routes += len(vrs)
	}
	if routes >= maxRoutesPerDomain {
		return errDomainFull
	}
	if !domainAlreadyKnown {
		routersByHTTPUser = make(map[string][]*Router)
	}
	vrs, found := routersByHTTPUser[httpUser]
	if !found {
		vrs = make([]*Router, 0, 1)
	}

	vr := &Router{
		domain:   domain,
		location: location,
		httpUser: httpUser,
		payload:  payload,
	}
	vrs = append(vrs, vr)

	slices.SortFunc(vrs, func(a, b *Router) int {
		return -cmp.Compare(a.location, b.location)
	})

	routersByHTTPUser[httpUser] = vrs
	r.indexByDomain[domain] = routersByHTTPUser
	if !domainAlreadyKnown && r.OnDomain != nil {
		r.OnDomain(domain, true)
	}
	return nil
}

func (r *Routers) Del(domain, location, httpUser string) {
	domain = strings.ToLower(domain)

	r.mutex.Lock()
	defer r.mutex.Unlock()

	routersByHTTPUser, found := r.indexByDomain[domain]
	if !found {
		return
	}

	vrs, found := routersByHTTPUser[httpUser]
	if !found {
		return
	}

	if len(vrs) > 1 {
		newVrs := make([]*Router, 0)
		for _, vr := range vrs {
			if vr.location != location {
				newVrs = append(newVrs, vr)
			}
		}
		routersByHTTPUser[httpUser] = newVrs
	} else if vrs[0].location == location {
		delete(routersByHTTPUser, httpUser)
		if len(routersByHTTPUser) == 0 {
			delete(r.indexByDomain, domain)
			if r.OnDomain != nil {
				r.OnDomain(domain, false)
			}
		}
	}

}

// Get returns the best location match for an exact host and exact HTTP user.
// It does not apply all-users, wildcard-domain, or catch-all-domain fallback.
func (r *Routers) Get(host, path, httpUser string) (vr *Router, exist bool) {
	host = strings.ToLower(host)

	r.mutex.RLock()
	defer r.mutex.RUnlock()

	return r.getLocked(host, path, httpUser)
}

// getLocked performs an exact-host lookup; host must already be lower-cased.
func (r *Routers) getLocked(host, path, httpUser string) (vr *Router, exist bool) {
	routersByHTTPUser, found := r.indexByDomain[host]
	if !found {
		return
	}

	vrs, found := routersByHTTPUser[httpUser]
	if !found {
		return
	}

	for _, vr = range vrs {
		if strings.HasPrefix(path, vr.location) {
			return vr, true
		}
	}
	return
}

func (r *Routers) getByRoute(host, path, httpUser string) (*Router, bool) {
	host = strings.ToLower(host)

	r.mutex.RLock()
	defer r.mutex.RUnlock()

	vr, ok := r.getExactOrAllUsersLocked(host, path, httpUser)
	if ok {
		return vr, true
	}
	// A host that belongs to an identity takes only that identity's
	// wildcards: another's would get the requests its own routes miss.
	owner, owned := r.owner(host)
	for wildcard := range wildcards(host) {
		vr, ok = r.getExactOrAllUsersLocked(wildcard, path, httpUser)
		if !ok {
			continue
		}
		if owned {
			if wildcardOwner, ok := r.owner(wildcard); !ok || wildcardOwner != owner {
				continue
			}
		}
		return vr, true
	}
	return nil, false
}

// wildcards are the wildcard domains that may route host, the longest
// first: test.example.com's are *.example.com, then "*", which routes
// every domain. A two-label host has only "*", so example.com does not
// match *.com.
func wildcards(host string) iter.Seq[string] {
	return func(yield func(string) bool) {
		for rest := host; ; {
			i := strings.IndexByte(rest, '.')
			if i < 0 || !strings.Contains(rest[i+1:], ".") {
				break
			}
			rest = rest[i+1:]
			if !yield("*." + rest) {
				return
			}
		}
		yield("*")
	}
}

func (r *Routers) owner(domain string) (string, bool) {
	if r.Owner == nil {
		return "", false
	}
	return r.Owner(domain)
}

func (r *Routers) getExactOrAllUsersLocked(host, path, httpUser string) (*Router, bool) {
	vr, ok := r.getLocked(host, path, httpUser)
	if ok {
		return vr, true
	}
	// Try to check if there is one proxy that doesn't specify routeByHTTPUser, it means match all.
	vr, ok = r.getLocked(host, path, "")
	if ok {
		return vr, true
	}
	return nil, false
}

func (r *Routers) exist(host, path, httpUser string) (route *Router, exist bool) {
	routersByHTTPUser, found := r.indexByDomain[host]
	if !found {
		return
	}
	routers, found := routersByHTTPUser[httpUser]
	if !found {
		return
	}

	for _, route = range routers {
		if path == route.location {
			return route, true
		}
	}
	return
}
