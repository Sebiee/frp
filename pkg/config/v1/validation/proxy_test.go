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

package validation

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	v1 "github.com/fatedier/frp/pkg/config/v1"
)

func TestValidateDomainConfigForServerRejectsSubdomainHostCaseInsensitively(t *testing.T) {
	tests := []struct {
		name          string
		subDomainHost string
		customDomain  string
		wantErr       bool
	}{
		{
			name:          "lowercase subdomain",
			subDomainHost: "frp.example.com",
			customDomain:  "victim.frp.example.com",
			wantErr:       true,
		},
		{
			name:          "mixed case custom domain",
			subDomainHost: "frp.example.com",
			customDomain:  "victim.FRP.example.com",
			wantErr:       true,
		},
		{
			name:          "mixed case wildcard domain",
			subDomainHost: "frp.example.com",
			customDomain:  "*.FRP.example.com",
			wantErr:       true,
		},
		{
			name:          "mixed case subdomain host",
			subDomainHost: "FRP.Example.Com",
			customDomain:  "victim.frp.example.com",
			wantErr:       true,
		},
		{
			name:          "external domain",
			subDomainHost: "frp.example.com",
			customDomain:  "victim.example.net",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDomainConfigForServer(
				&v1.DomainConfig{CustomDomains: []string{tt.customDomain}},
				&v1.ServerConfig{SubDomainHost: tt.subDomainHost},
			)
			if tt.wantErr {
				require.ErrorContains(t, err, "should not belong to subdomain host")
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestValidateHTTPProxyLocations(t *testing.T) {
	s := &v1.ServerConfig{VhostHTTPPort: 80}
	proxy := func(locations ...string) *v1.HTTPProxyConfig {
		c := &v1.HTTPProxyConfig{DomainConfig: v1.DomainConfig{CustomDomains: []string{"app.example.com"}}, Locations: locations}
		c.Name, c.Type, c.LocalPort = "web", "http", 8080
		c.Complete()
		return c
	}
	many := make([]string, 65)
	for i := range many {
		many[i] = fmt.Sprintf("/p%d", i)
	}
	for _, c := range []*v1.HTTPProxyConfig{
		proxy(many...),
		proxy("api"), proxy("//"), proxy("//api"), proxy("/api//v1"), proxy("/a/../api"), proxy("/a/./b"), proxy("/."), proxy("/api/.."),
	} {
		require.Error(t, ValidateProxyConfigurerForServer(c, s), c.Locations)
		require.Error(t, ValidateProxyConfigurerForClient(c), c.Locations)
	}
	for _, c := range []*v1.HTTPProxyConfig{
		proxy(), proxy(many[:64]...), proxy("", "/", "/api", "/api/", "/static/css", "/a%2fb", "/.well-known/x"),
	} {
		require.NoError(t, ValidateProxyConfigurerForServer(c, s), c.Locations)
		require.NoError(t, ValidateProxyConfigurerForClient(c), c.Locations)
	}
}
