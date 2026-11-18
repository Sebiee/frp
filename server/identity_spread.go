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
	"github.com/fatedier/frp/pkg/msg"
)

// Where a balancer puts several servers behind one address, the logins of
// one client identity (replicas that publish the same names) should be
// spread evenly over the servers, and a server left without one serves
// none of the names. Only the servers can count, so:
//
//   - a login answer says how many logins of the identity this server has
//     (LoginResp.Peers): those that serve, and those that have not
//     published yet, the new one among them;
//   - a client that carries its proxies on this server, and has logged in
//     on another one too, asks this one whether it may leave for the other
//     (msg.Leave, with the other's count). This server grants it when more
//     logins serve here than the other one counted, and from then on does
//     not count the client: so a grant leaves a serving login behind, and
//     the clients that ask together cannot all go.
//
// A login serves while it has a proxy and no leave. One that had proxies
// and has none now, as a client keeps an old login while its streams end,
// counts nowhere. A client without an identity gets no count and no answer.

// spread reports how ctl counts for its identity: as a login that serves,
// as one that has not published yet, or not at all. It takes no lock a
// login holds while it writes to its client.
func (ctl *Control) spread() (serving, arriving bool) {
	ctl.mu.RLock()
	defer ctl.mu.RUnlock()
	if !ctl.published {
		return false, true
	}
	return len(ctl.proxies) > 0 && !ctl.leaving, false
}

func (ctl *Control) setLeaving(leaving bool) {
	ctl.mu.Lock()
	ctl.leaving = leaving
	ctl.mu.Unlock()
}

// spreadOf counts identity's logins that serve, and those that have not
// published yet.
func (cm *ControlManager) spreadOf(identity string) (serving, arriving int) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	for key, entry := range cm.ctlsByRunID {
		if key.identity != identity {
			continue
		}
		s, a := entry.ctl.spread()
		if s {
			serving++
		}
		if a {
			arriving++
		}
	}
	return serving, arriving
}

// peers is the count a login answer gives a client of identity.
func (cm *ControlManager) peers(identity string) int {
	cm.spreadMu.Lock()
	defer cm.spreadMu.Unlock()
	serving, arriving := cm.spreadOf(identity)
	return serving + arriving
}

// leave answers ctl's question, one at a time: it may leave when it
// serves, its other login is not on this server, and more logins of its
// identity serve here than the other server counted. serving is how many
// served when it asked.
func (cm *ControlManager) leave(ctl *Control, m *msg.Leave) (granted bool, serving int) {
	cm.spreadMu.Lock()
	defer cm.spreadMu.Unlock()
	if m.Stay {
		ctl.setLeaving(false)
		serving, _ = cm.spreadOf(ctl.identity)
		return false, serving
	}
	serving, _ = cm.spreadOf(ctl.identity)
	cm.mu.RLock()
	_, here := cm.ctlsByRunID[runKey{ctl.identity, m.RunID}]
	cm.mu.RUnlock()
	if serves, _ := ctl.spread(); !serves || here || m.Peers < 1 || serving <= m.Peers {
		return false, serving
	}
	ctl.setLeaving(true)
	return true, serving
}

func (ctl *Control) handleLeave(m msg.Message) {
	inMsg := m.(*msg.Leave)
	granted, serving := ctl.manager.leave(ctl, inMsg)
	switch {
	case inMsg.Stay:
		ctl.xl.Infof("the client stays: %d logins of its identity serve here", serving)
	case granted:
		ctl.xl.Infof("the client may leave for a server with %d logins of its identity: %d served here", inMsg.Peers, serving)
	default:
		ctl.xl.Debugf("the client may not leave for a server with %d logins of its identity: %d serve here", inMsg.Peers, serving)
	}
	if !inMsg.Stay && ctl.sessionCtx.ServerCfg.OnLeave != nil {
		ctl.sessionCtx.ServerCfg.OnLeave(ctl.identity, granted)
	}
	_ = ctl.msgDispatcher.Send(&msg.LeaveResp{RunID: inMsg.RunID, Granted: granted, Serving: serving})
}
