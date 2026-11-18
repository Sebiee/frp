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
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/fatedier/frp/pkg/msg"
)

// replica logs in a client of identity, as one of the replicas that
// publish the identity's names.
func replica(t *testing.T, dial func(string) session, identity string) *testClient {
	t.Helper()
	c, err := login(t, dial(identity), msg.Login{})
	require.NoError(t, err)
	return c
}

// serve publishes the name every replica publishes.
func (c *testClient) serve() {
	c.t.Helper()
	require.NoError(c.t, c.newProxy(msg.NewProxy{ProxyName: c.runID + ".web", ProxyType: "http", CustomDomains: []string{"app.example.com"}}))
}

// retire takes the name back, as a client does with a login it keeps only
// while its streams end.
func (c *testClient) retire() {
	c.t.Helper()
	c.send(&msg.CloseProxy{ProxyName: c.runID + ".web"})
}

// ask asks whether c may leave for a server where it logged in as runID
// and got the count peers.
func (c *testClient) ask(runID string, peers int) (granted bool, serving int) {
	c.t.Helper()
	c.send(&msg.Leave{RunID: runID, Peers: peers})
	return c.leaveAnswer(runID)
}

func (c *testClient) stay() {
	c.t.Helper()
	c.send(&msg.Leave{Stay: true})
	c.leaveAnswer("")
}

func (c *testClient) leaveAnswer(runID string) (granted bool, serving int) {
	c.t.Helper()
	got, ok := c.await(&msg.LeaveResp{}, 5*time.Second)
	require.True(c.t, ok, "no answer to the leave")
	resp := got.(*msg.LeaveResp)
	require.Equal(c.t, runID, resp.RunID)
	return resp.Granted, resp.Serving
}

// A login answer counts the identity's logins on the server that serve,
// and those that have not published yet, the new one among them. A login
// that took its proxies back, and one that was granted a leave, do not
// count; nor do another identity's.
func TestLoginAnswerCountsTheIdentitysLogins(t *testing.T) {
	svr, dial := identityService(t)
	// counted is what a login of node/a would be told, less itself.
	counted := func() int { return svr.ctlManager.peers("node/a") }
	a1 := replica(t, dial, "node/a")
	require.Equal(t, 1, a1.peers, "the new login counts")
	a2 := replica(t, dial, "node/a")
	require.Equal(t, 2, a2.peers, "a login that has not published yet counts")
	a1.serve()
	a2.serve()
	a3 := replica(t, dial, "node/a")
	require.Equal(t, 3, a3.peers, "logins that serve count")
	require.Equal(t, 1, replica(t, dial, "node/b").peers, "each identity has its own count")
	require.Zero(t, replica(t, dial, "").peers, "a client without an identity gets no count")
	require.Equal(t, 3, counted())

	// a3 came to look, and goes.
	require.NoError(t, a3.stream.Close())
	require.Eventually(t, func() bool { return counted() == 2 }, 5*time.Second, 10*time.Millisecond,
		"a login that closed still counts")

	// An old login that a client keeps while its streams end: it had
	// proxies and has none.
	a2.retire()
	require.Eventually(t, func() bool { return counted() == 1 }, 5*time.Second, 10*time.Millisecond,
		"a login that took its proxies back still counts")
	require.Equal(t, 2, replica(t, dial, "node/a").peers)
	require.Equal(t, 3, svr.Clients()["node/a"], "it is still logged in")
}

// A login may leave when more logins of its identity serve on its server
// than the other server counted. The server then counts it as gone, so a
// grant leaves a serving login behind; a stay takes the grant back.
func TestLeaveIsGrantedWhenTheSpreadGetsMoreEven(t *testing.T) {
	var granted, refused atomic.Int64
	svr, dial := identityService(t)
	svr.cfg.OnLeave = func(identity string, ok bool) {
		require.Equal(t, "node/a", identity)
		if ok {
			granted.Add(1)
		} else {
			refused.Add(1)
		}
	}
	a1, a2 := replica(t, dial, "node/a"), replica(t, dial, "node/a")

	ok, serving := a1.ask("there", 1)
	require.False(t, ok, "a login that serves nothing has nothing to take along")
	require.Zero(t, serving)

	a1.serve()
	a2.serve()
	ok, serving = a1.ask("there", 2)
	require.False(t, ok, "2 here, 2 there with it: no better")
	require.Equal(t, 2, serving)
	ok, _ = a1.ask("there", 0)
	require.False(t, ok, "a count below 1 is no login's")

	ok, serving = a1.ask("there", 1)
	require.True(t, ok, "2 here, 1 there with it")
	require.Equal(t, 2, serving)
	ok, serving = a2.ask("elsewhere", 1)
	require.False(t, ok, "the last serving login may not leave")
	require.Equal(t, 1, serving)
	require.Equal(t, 1+1, replica(t, dial, "node/a").peers, "a login that was granted a leave does not count")

	a1.stay()
	ok, serving = a2.ask("elsewhere", 1)
	require.True(t, ok, "after the stay, 2 serve again")
	require.Equal(t, 2, serving)

	require.Equal(t, int64(2), granted.Load())
	require.Equal(t, int64(4), refused.Load())
	require.Equal(t, map[string]int{"node/a": 3}, svr.Clients(), "a leave closes no login")
}

// A client whose other login is on the same server would leave for where
// it is: never granted, whatever count it brings.
func TestLeaveForTheSameServerIsRefused(t *testing.T) {
	dial := identityServer(t)
	a1, a2, a3 := replica(t, dial, "node/a"), replica(t, dial, "node/a"), replica(t, dial, "node/a")
	for _, c := range []*testClient{a1, a2, a3} {
		c.serve()
	}
	look := replica(t, dial, "node/a")
	require.Equal(t, 4, look.peers)
	ok, serving := a1.ask(look.runID, look.peers)
	require.False(t, ok)
	require.Equal(t, 3, serving)
	ok, _ = a1.ask(look.runID, 1)
	require.False(t, ok, "its other login is here")

	// Another identity's login of that run ID is not its own.
	other, err := login(t, dial("node/b"), msg.Login{RunID: "shared"})
	require.NoError(t, err)
	require.Equal(t, "shared", other.runID)
	ok, _ = a1.ask("shared", 1)
	require.True(t, ok)
}

// Logins that ask at the same moment are answered one at a time: of 8
// that serve, asking to leave for a server with 5, 3 may go, as the fourth
// would leave 4 here for 6 there. Of 2, asking for the last place on an
// empty server, one may.
func TestLeavesAskedTogetherCannotAllBeGranted(t *testing.T) {
	for _, tc := range []struct{ logins, peers, want int }{{8, 5, 3}, {2, 1, 1}, {3, 1, 2}} {
		t.Run(fmt.Sprintf("%d logins for a server with %d", tc.logins, tc.peers), func(t *testing.T) {
			dial := identityServer(t)
			clients := make([]*testClient, tc.logins)
			for i := range clients {
				clients[i] = replica(t, dial, "node/a")
				clients[i].serve()
			}
			var (
				wg      sync.WaitGroup
				start   = make(chan struct{})
				granted atomic.Int64
				failed  atomic.Int64
			)
			for _, c := range clients {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					if msg.WriteMsg(c.ctl, &msg.Leave{RunID: "there", Peers: tc.peers}) != nil {
						failed.Add(1)
						return
					}
					got, ok := c.await(&msg.LeaveResp{}, 5*time.Second)
					switch {
					case !ok:
						failed.Add(1)
					case got.(*msg.LeaveResp).Granted:
						granted.Add(1)
					}
				}()
			}
			close(start)
			wg.Wait()
			require.Zero(t, failed.Load())
			require.Equal(t, int64(tc.want), granted.Load())
			require.Equal(t, tc.logins-tc.want+1, replica(t, dial, "node/a").peers, "those that stay serve")
		})
	}
}

// A client without an identity gets no answer: it got no count either, so
// it does not ask. Its control stays up.
func TestClientWithoutIdentityGetsNoLeaveAnswer(t *testing.T) {
	dial := identityServer(t)
	plain := replica(t, dial, "")
	plain.send(&msg.Leave{RunID: "there", Peers: 1})
	plain.send(&msg.Ping{})
	got, ok := plain.await(&msg.LeaveResp{}, 300*time.Millisecond)
	require.False(t, ok, "answer %v", got)
}
