package group

import (
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

type domainEvent struct {
	domain string
	added  bool
}

func dialer(name string, calls *[]string, err error) TCPTLSDialFunc {
	return func(net.Addr) (net.Conn, error) {
		*calls = append(*calls, name)
		if err != nil {
			return nil, err
		}
		c, _ := net.Pipe()
		return c, nil
	}
}

func TestTCPTLSRoutesGroupByIdentity(t *testing.T) {
	require := require.New(t)
	var events []domainEvent
	r := NewTCPTLSRoutes(NewDomainClaims(), func(d string, added bool) { events = append(events, domainEvent{d, added}) })
	var calls []string

	un1, err := r.Register("a", "node/1", "DB.example.com", []string{"postgresql"}, dialer("a", &calls, nil))
	require.NoError(err)
	un2, err := r.Register("b", "node/1", "db.example.com", []string{"postgresql"}, dialer("b", &calls, nil))
	require.NoError(err)
	_, err = r.Register("c", "node/2", "db.example.com", []string{"postgresql"}, dialer("c", &calls, nil))
	require.ErrorContains(err, "another client")
	_, err = r.Register("d", "node/1", "db.example.com", nil, dialer("d", &calls, nil))
	require.ErrorContains(err, "alpn")
	require.Equal([]domainEvent{{"db.example.com", true}}, events)

	rt, ok := r.Get("db.example.com")
	require.True(ok)
	require.Equal("node/1", rt.Group)
	require.Equal([]string{"postgresql"}, rt.ALPN)
	for range 4 {
		c, err := rt.Dial(nil)
		require.NoError(err)
		c.Close()
	}
	require.Equal([]string{"a", "b", "a", "b"}, calls)

	un1()
	un1() // once
	_, ok = r.Get("db.example.com")
	require.True(ok)
	require.Len(events, 1)
	un2()
	_, ok = r.Get("db.example.com")
	require.False(ok)
	require.Equal([]domainEvent{{"db.example.com", true}, {"db.example.com", false}}, events)
	_, err = rt.Dial(nil)
	require.ErrorIs(err, ErrTCPTLSNoRoute)

	// The name is free again, for anyone.
	_, err = r.Register("c", "node/2", "db.example.com", nil, dialer("c", &calls, nil))
	require.NoError(err)
}

func TestTCPTLSRoutesNoIdentityIsAlone(t *testing.T) {
	r := NewTCPTLSRoutes(NewDomainClaims(), nil)
	var calls []string
	_, err := r.Register("a", "", "db.example.com", nil, dialer("a", &calls, nil))
	require.NoError(t, err)
	_, err = r.Register("b", "", "db.example.com", nil, dialer("b", &calls, nil))
	require.Error(t, err)
}

func TestTCPTLSRouteDialTriesEachMember(t *testing.T) {
	require := require.New(t)
	r := NewTCPTLSRoutes(NewDomainClaims(), nil)
	var calls []string
	down := errors.New("no work connection")
	_, err := r.Register("a", "n", "db.example.com", nil, dialer("a", &calls, down))
	require.NoError(err)
	_, err = r.Register("b", "n", "db.example.com", nil, dialer("b", &calls, nil))
	require.NoError(err)
	rt, _ := r.Get("db.example.com")
	c, err := rt.Dial(nil)
	require.NoError(err)
	c.Close()
	require.Equal([]string{"a", "b"}, calls)

	calls = nil
	_, err = r.Register("x", "n", "x.example.com", nil, dialer("x", &calls, down))
	require.NoError(err)
	rt, _ = r.Get("x.example.com")
	_, err = rt.Dial(nil)
	require.ErrorIs(err, ErrTCPTLSNoRoute)
	require.ErrorIs(err, down)
}

func TestDomainClaims(t *testing.T) {
	require := require.New(t)
	c := NewDomainClaims()
	type conflict struct{ domain, refused, holder string }
	var conflicts []conflict
	c.OnConflict = func(d, refused, holder string) { conflicts = append(conflicts, conflict{d, refused, holder}) }

	rel1, err := c.Claim("app.example.com", DomainKindHTTP)
	require.NoError(err)
	rel2, err := c.Claim("APP.example.com", DomainKindHTTP)
	require.NoError(err)
	_, err = c.Claim("app.example.com", DomainKindTCPTLS)
	var claimed *DomainClaimedError
	require.ErrorAs(err, &claimed)
	require.Equal(DomainKindHTTP, claimed.Holder)
	require.Equal([]conflict{{"app.example.com", DomainKindTCPTLS, DomainKindHTTP}}, conflicts)

	rel1()
	rel1() // once
	_, err = c.Claim("app.example.com", DomainKindTCPTLS)
	require.Error(err)
	rel2()
	rel3, err := c.Claim("app.example.com", DomainKindTCPTLS)
	require.NoError(err)
	_, err = c.Claim("app.example.com", DomainKindHTTP)
	require.ErrorAs(err, &claimed)
	require.Equal(DomainKindTCPTLS, claimed.Holder)
	rel3()

	var none *DomainClaims
	rel, err := none.Claim("x", DomainKindHTTP)
	require.NoError(err)
	rel()
}

func TestTCPTLSRoutesClaimTheName(t *testing.T) {
	claims := NewDomainClaims()
	r := NewTCPTLSRoutes(claims, nil)
	rel, err := claims.Claim("app.example.com", DomainKindHTTP)
	require.NoError(t, err)
	_, err = r.Register("a", "n", "app.example.com", nil, nil)
	var claimed *DomainClaimedError
	require.ErrorAs(t, err, &claimed)
	rel()
	un, err := r.Register("a", "n", "app.example.com", nil, nil)
	require.NoError(t, err)
	_, err = claims.Claim("app.example.com", DomainKindHTTP)
	require.Error(t, err)
	un()
	_, err = claims.Claim("app.example.com", DomainKindHTTP)
	require.NoError(t, err)
}

func TestDomainClaimsReserved(t *testing.T) {
	c := NewDomainClaims()
	c.Reserved = func(d string) bool { return d == "tunnel.example.com" }
	_, err := c.Claim("Tunnel.example.com", DomainKindTCPTLS)
	require.ErrorContains(t, err, "reserved")
	_, err = c.Claim("tunnel.example.com", DomainKindHTTP)
	require.ErrorContains(t, err, "reserved")
	r := NewTCPTLSRoutes(c, nil)
	_, err = r.Register("a", "n", "tunnel.example.com", nil, nil)
	require.ErrorContains(t, err, "reserved")
}

func TestTCPTLSRoutesALPNInAnyOrder(t *testing.T) {
	r := NewTCPTLSRoutes(NewDomainClaims(), nil)
	_, err := r.Register("a", "n", "db.example.com", []string{"x", "y"}, nil)
	require.NoError(t, err)
	_, err = r.Register("b", "n", "db.example.com", []string{"y", "x"}, nil)
	require.NoError(t, err)
}

// A stream whose handshake was for one group never goes to another
// that took the name since.
func TestTCPTLSRouteDialStaysInItsGroup(t *testing.T) {
	r := NewTCPTLSRoutes(NewDomainClaims(), nil)
	var calls []string
	un, err := r.Register("a", "node/1", "db.example.com", nil, dialer("a", &calls, nil))
	require.NoError(t, err)
	rt, _ := r.Get("db.example.com")
	un()
	_, err = r.Register("b", "node/2", "db.example.com", nil, dialer("b", &calls, nil))
	require.NoError(t, err)
	_, err = rt.Dial(nil)
	require.ErrorIs(t, err, ErrTCPTLSNoRoute)
	require.Empty(t, calls)
}
