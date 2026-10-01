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

package net

import "context"

type identityKey struct{}

// WithIdentity returns ctx carrying the identity a client's connection
// authenticated as outside frp, such as an embedder's mutual TLS.
func WithIdentity(ctx context.Context, identity string) context.Context {
	if identity == "" {
		return ctx
	}
	return context.WithValue(ctx, identityKey{}, identity)
}

// IdentityFromContext is the identity WithIdentity put in ctx, or "".
func IdentityFromContext(ctx context.Context) string {
	id, _ := ctx.Value(identityKey{}).(string)
	return id
}
