// Copyright 2026 The Alpaca Authors
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

package main

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureLog redirects the standard logger into a buffer for the duration of a
// test. log_test.go points the logger at io.Discard for the whole package, so a
// test that wants to assert on log output has to opt back in.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(io.Discard) })
	return &buf
}

// refusingProxy answers every CONNECT with the given status, the way a
// filtering proxy refuses a tunnel to a blocked destination.
func refusingProxy(status int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(status)
	})
}

// TestConnectFailureIsLogged pins the reason for a 502 landing in the log. A
// filtering upstream proxy refuses the tunnel, so the block page it would serve
// over plain HTTP never reaches the browser: alpaca's log is the only place the
// status is visible, and for a long time it wasn't logged at all.
func TestConnectFailureIsLogged(t *testing.T) {
	buf := captureLog(t)

	parent := httptest.NewServer(refusingProxy(http.StatusForbidden))
	defer parent.Close()
	child := httptest.NewServer(newChildProxy(parent))
	defer child.Close()

	client := http.Client{Transport: &http.Transport{Proxy: proxyServer(t, child)}}
	_, err := client.Get("https://blocked.test")
	require.Error(t, err, "the tunnel must not be established")

	logged := buf.String()
	assert.Contains(t, logged, "Error establishing CONNECT tunnel")
	assert.Contains(t, logged, "403", "the upstream status belongs in the log")
}

// TestConnectFailureToNonExistentHostIsLogged covers the direct path: no
// upstream proxy involved, the destination simply doesn't resolve.
func TestConnectFailureToNonExistentHostIsLogged(t *testing.T) {
	buf := captureLog(t)

	proxy := httptest.NewServer(newDirectProxy())
	defer proxy.Close()

	client := http.Client{Transport: &http.Transport{Proxy: proxyServer(t, proxy)}}
	_, err := client.Get("https://nonexistent.test")
	require.Error(t, err)

	assert.Contains(t, buf.String(), "Error establishing CONNECT tunnel")
}
