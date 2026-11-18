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

//go:build !frps

package client

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/fatedier/frp/pkg/auth"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
)

// leaveControl is a control whose login got the count peers, and the
// server's end of its connection.
func leaveControl(t *testing.T, peers int) (*Control, net.Conn) {
	t.Helper()
	authRuntime, err := auth.BuildClientAuth(&v1.AuthClientConfig{Method: v1.AuthMethodToken, Token: "token"})
	require.NoError(t, err)
	conn, server := net.Pipe()
	t.Cleanup(func() {
		_ = conn.Close()
		_ = server.Close()
	})
	ctl, err := NewControl(context.Background(), &SessionContext{
		Common: &v1.ClientCommonConfig{},
		RunID:  "here",
		Conn:   msg.NewConn(conn, msg.NewV1ReadWriter(conn)),
		Auth:   authRuntime,
		Peers:  peers,
	})
	require.NoError(t, err)
	go ctl.msgDispatcher.Run()
	return ctl, server
}

// A server that gave no count with the login does not know the leave
// message, and would close the control at it: the client sends it none.
func TestLeaveIsNotSentToAServerWithoutACount(t *testing.T) {
	ctl, server := leaveControl(t, 0)
	_, err := ctl.leave(context.Background(), &msg.Leave{RunID: "there", Peers: 1})
	require.ErrorIs(t, err, ErrLeaveUnknown)
	_ = server.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	_, err = server.Read(make([]byte, 1))
	require.Error(t, err, "the server got a message")
}

func TestLeaveWaitsForItsAnswer(t *testing.T) {
	ctl, server := leaveControl(t, 2)
	rw := msg.NewV1ReadWriter(server)
	asked := make(chan *msg.Leave, 1)
	go func() {
		// An answer no one waits for is dropped.
		_ = rw.WriteMsg(&msg.LeaveResp{RunID: "earlier", Granted: true})
		var m msg.Leave
		if rw.ReadMsgInto(&m) == nil {
			asked <- &m
			_ = rw.WriteMsg(&msg.LeaveResp{RunID: m.RunID, Granted: true, Serving: 3})
		}
	}()
	resp, err := ctl.leave(context.Background(), &msg.Leave{RunID: "there", Peers: 1})
	require.NoError(t, err)
	require.Equal(t, &msg.LeaveResp{RunID: "there", Granted: true, Serving: 3}, resp)
	require.Equal(t, &msg.Leave{RunID: "there", Peers: 1}, <-asked)
}

// A question without an answer ends with its context, or with the control.
func TestLeaveEndsWithoutAnAnswer(t *testing.T) {
	ctl, server := leaveControl(t, 2)
	go func() {
		var m msg.Leave
		_ = msg.NewV1ReadWriter(server).ReadMsgInto(&m)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := ctl.leave(ctx, &msg.Leave{RunID: "there", Peers: 1})
	require.ErrorIs(t, err, context.DeadlineExceeded)

	done := make(chan error, 1)
	go func() {
		_, err := ctl.leave(context.Background(), &msg.Leave{RunID: "there", Peers: 1})
		done <- err
	}()
	go func() {
		var m msg.Leave
		_ = msg.NewV1ReadWriter(server).ReadMsgInto(&m)
		close(ctl.doneCh)
	}()
	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("the question outlived its control")
	}
}
