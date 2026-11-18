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

package msg

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestV1MessageTypeIDsAreStable(t *testing.T) {
	require.Equal(t, byte('o'), TypeLogin)
	require.Equal(t, byte('1'), TypeLoginResp)
	require.Equal(t, byte('p'), TypeNewProxy)
	require.Equal(t, byte('2'), TypeNewProxyResp)
	require.Equal(t, byte('c'), TypeCloseProxy)
	require.Equal(t, byte('w'), TypeNewWorkConn)
	require.Equal(t, byte('r'), TypeReqWorkConn)
	require.Equal(t, byte('s'), TypeStartWorkConn)
	require.Equal(t, byte('v'), TypeNewVisitorConn)
	require.Equal(t, byte('3'), TypeNewVisitorConnResp)
	require.Equal(t, byte('h'), TypePing)
	require.Equal(t, byte('4'), TypePong)
	require.Equal(t, byte('u'), TypeUDPPacket)
	require.Equal(t, byte('i'), TypeNatHoleVisitor)
	require.Equal(t, byte('n'), TypeNatHoleClient)
	require.Equal(t, byte('m'), TypeNatHoleResp)
	require.Equal(t, byte('5'), TypeNatHoleSid)
	require.Equal(t, byte('6'), TypeNatHoleReport)
	require.Equal(t, byte('l'), TypeLeave)
	require.Equal(t, byte('7'), TypeLeaveResp)
}

func TestMessageTypeMapIsCompleteAndUnique(t *testing.T) {
	require.Len(t, msgTypeMap, 20)

	msgTypes := make(map[reflect.Type]struct{}, len(msgTypeMap))

	for _, m := range msgTypeMap {
		msgType := reflect.TypeOf(m)
		require.NotContains(t, msgTypes, msgType)
		msgTypes[msgType] = struct{}{}
	}
}

// A leave and its answer cross both wire protocols. A login answer without
// a count is the bytes it was before the count, and a peer from before the
// count reads one with it as it read the others.
func TestLeaveMessagesAndTheLoginCount(t *testing.T) {
	for _, wireProtocol := range []string{"v1", "v2"} {
		var buf bytes.Buffer
		rw := NewReadWriter(&buf, wireProtocol)
		for _, in := range []Message{
			&Leave{RunID: "there", Peers: 2},
			&Leave{RunID: "there", Stay: true},
			&LeaveResp{RunID: "there", Granted: true, Serving: 3},
		} {
			require.NoError(t, rw.WriteMsg(in), wireProtocol)
			out, err := rw.ReadMsg()
			require.NoError(t, err, wireProtocol)
			require.Equal(t, in, out, wireProtocol)
		}
	}

	plain, err := json.Marshal(&LoginResp{Version: "v", RunID: "run"})
	require.NoError(t, err)
	require.JSONEq(t, `{"version":"v","run_id":"run"}`, string(plain))

	counted, err := json.Marshal(&LoginResp{Version: "v", RunID: "run", Peers: 3})
	require.NoError(t, err)
	var old struct {
		Version string `json:"version,omitempty"`
		RunID   string `json:"run_id,omitempty"`
		Error   string `json:"error,omitempty"`
	}
	require.NoError(t, json.Unmarshal(counted, &old))
	require.Equal(t, "run", old.RunID)
}
