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

package vhost

import (
	"context"
	"time"
)

// Where a proxied request failed, in the order a request goes.
const (
	// StageRoute: no route matched the request's host and path.
	StageRoute = "route"
	// StageDial: no work connection to the client could be had.
	StageDial = "dial"
	// StageSend: writing the request to the work connection failed.
	StageSend = "send"
	// StageHeaders: the response headers did not come, or timed out.
	StageHeaders = "headers"
	// StageBody: the response body broke off after its headers were sent.
	StageBody = "body"
)

// ProxyError is an error of the HTTP proxy with the stage it happened in.
// HTTPReverseProxyOptions.OnError gets it.
type ProxyError struct {
	Stage string
	Err   error
}

func (e *ProxyError) Error() string { return e.Stage + ": " + e.Err.Error() }
func (e *ProxyError) Unwrap() error { return e.Err }

type headerTimeoutKey struct{}

// WithResponseHeaderTimeout sets how long the request routed with ctx
// waits for the origin's response headers, in place of the proxy's
// ResponseHeaderTimeoutS. d <= 0 keeps the proxy's.
func WithResponseHeaderTimeout(ctx context.Context, d time.Duration) context.Context {
	return context.WithValue(ctx, headerTimeoutKey{}, d)
}

func responseHeaderTimeout(ctx context.Context, def time.Duration) time.Duration {
	if d, ok := ctx.Value(headerTimeoutKey{}).(time.Duration); ok && d > 0 {
		return d
	}
	return def
}
