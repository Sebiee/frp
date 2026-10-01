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

package group

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/fatedier/frp/pkg/util/vhost"
)

func TestHTTPGroupNextEndpoint(t *testing.T) {
	ctl := NewHTTPGroupController(vhost.NewRouters())
	rc := vhost.RouteConfig{Domain: "app.example.com", CreateConnFn: func(string) (net.Conn, error) { return nil, nil }}
	require.NoError(t, ctl.Register("a", "g", "k", rc))
	g, ok := ctl.get("g")
	require.True(t, ok)
	_, ok = g.nextEndpoint("a")
	require.False(t, ok, "alone: no other")

	require.NoError(t, ctl.Register("b", "g", "k", rc))
	require.NoError(t, ctl.Register("c", "g", "k", rc))
	for endpoint, want := range map[string]string{"a": "b", "b": "c", "c": "a", "gone": "a"} {
		next, ok := g.nextEndpoint(endpoint)
		require.True(t, ok)
		require.Equal(t, want, next, endpoint)
	}

}
