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
	"encoding/base64"
	"net/http"
	"net/url"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func basicHeader(credentials string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(credentials))
}

// TestPreemptiveBasicNotOfferedUnprompted is the central security
// property: until a proxy has actually asked for Basic and accepted it,
// alpaca volunteers nothing.
func TestPreemptiveBasicNotOfferedUnprompted(t *testing.T) {
	chain := newAuthChain(newBasicAuthenticator("user:pass"))
	_, ok := chain.preemptiveBasic("proxy.test")
	assert.False(t, ok, "credentials must not be offered before a challenge")
}

func TestPreemptiveBasicAfterSuccess(t *testing.T) {
	chain := newAuthChain(newBasicAuthenticator("user:pass"))
	chain.recordBasicSuccess("proxy.test")
	header, ok := chain.preemptiveBasic("proxy.test")
	require.True(t, ok)
	assert.Equal(t, basicHeader("user:pass"), header)
}

// TestPreemptiveBasicIsPerHost pins that learning one proxy says nothing
// about any other: a hostile PAC naming a different proxy must not
// receive credentials.
func TestPreemptiveBasicIsPerHost(t *testing.T) {
	chain := newAuthChain(newBasicAuthenticator("user:pass"))
	chain.recordBasicSuccess("proxy.test")
	_, ok := chain.preemptiveBasic("evil.test")
	assert.False(t, ok, "a different host must not inherit the cache entry")
}

func TestPreemptiveBasicHostNormalisation(t *testing.T) {
	chain := newAuthChain(newBasicAuthenticator("user:pass"))
	chain.recordBasicSuccess("Proxy.Test")
	for _, host := range []string{"proxy.test", "PROXY.TEST", "proxy.test."} {
		_, ok := chain.preemptiveBasic(host)
		assert.True(t, ok, "host %q should match the recorded entry", host)
	}
}

// TestPreemptiveBasicRespectsAllowlist checks the defence in depth: even
// with a cache entry, a host outside the allowlist gets nothing. The
// entry can only ever be created for an allowlisted host, so this guards
// against the allowlist being tightened while alpaca runs.
func TestPreemptiveBasicRespectsAllowlist(t *testing.T) {
	chain := newAuthChain(newBasicAuthenticator("user:pass"))
	chain.recordBasicSuccess("proxy.test")
	chain.hostAllowlist = parseAuthAllowlist("corp.example")
	_, ok := chain.preemptiveBasic("proxy.test")
	assert.False(t, ok, "allowlist must override the cache")
}

// TestPreemptiveBasicIgnoresOtherSchemes pins that only Basic is ever
// sent preemptively. NTLM and Negotiate are connection-bound and their
// handshakes are meaningless without a challenge.
func TestPreemptiveBasicIgnoresOtherSchemes(t *testing.T) {
	chain := newAuthChain(realisticFake("NTLM", "NTLM tok"))
	chain.recordBasicSuccess("proxy.test")
	_, ok := chain.preemptiveBasic("proxy.test")
	assert.False(t, ok, "a chain without Basic must not offer anything")
}

func TestForgetBasic(t *testing.T) {
	chain := newAuthChain(newBasicAuthenticator("user:pass"))
	chain.recordBasicSuccess("proxy.test")
	chain.forgetBasic("proxy.test")
	_, ok := chain.preemptiveBasic("proxy.test")
	assert.False(t, ok, "forgetBasic must clear the entry")
}

func TestPreemptiveBasicNilChainIsSafe(t *testing.T) {
	var chain *authChain
	assert.NotPanics(t, func() {
		_, ok := chain.preemptiveBasic("proxy.test")
		assert.False(t, ok)
		chain.recordBasicSuccess("proxy.test")
		chain.forgetBasic("proxy.test")
	})
}

// TestPreemptiveBasicConcurrent exercises the mutex; the chain is shared
// across request goroutines.
func TestPreemptiveBasicConcurrent(t *testing.T) {
	chain := newAuthChain(newBasicAuthenticator("user:pass"))
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			chain.recordBasicSuccess("proxy.test")
			_, _ = chain.preemptiveBasic("proxy.test")
			chain.forgetBasic("proxy.test")
		}()
	}
	wg.Wait()
}

// TestConnectViaProxy_PreemptiveBasicSavesRoundTrip is the end-to-end
// payoff: the first tunnel costs a probe plus an authenticated attempt,
// the second is authenticated straight away.
func TestConnectViaProxy_PreemptiveBasicSavesRoundTrip(t *testing.T) {
	accepted := basicHeader("user:pass")
	proxy := newConnectProxy(t, []string{`Basic realm="proxy"`}, accepted)
	defer proxy.Close()

	chain := newAuthChain(newBasicAuthenticator("user:pass"))

	for i := 0; i < 2; i++ {
		req, err := http.NewRequest(http.MethodConnect, "https://example.com:443", nil)
		require.NoError(t, err)
		req.Host = "example.com:443"
		conn, err := connectViaProxy(req, proxy.URL(), chain)
		require.NoError(t, err, "tunnel %d", i+1)
		_ = conn.Close()
	}

	requests := proxy.requests()
	require.Len(t, requests, 3, "expected probe + Basic, then Basic only")
	assert.Empty(t, requests[0], "first attempt is an unauthenticated probe")
	assert.Equal(t, accepted, requests[1], "challenge answered with Basic")
	assert.Equal(t, accepted, requests[2], "second tunnel authenticates up front")
}

// TestConnectViaProxy_PreemptiveBasicRecoversFromRejection covers a
// changed password: the cached credentials are refused, alpaca falls
// back to the challenge-driven flow and drops the cache entry.
func TestConnectViaProxy_PreemptiveBasicRecoversFromRejection(t *testing.T) {
	proxy := newConnectProxy(t, []string{`Basic realm="proxy"`}, "never-accepted")
	defer proxy.Close()

	chain := newAuthChain(newBasicAuthenticator("user:pass"))
	chain.recordBasicSuccess(proxy.URL().Hostname())

	req, err := http.NewRequest(http.MethodConnect, "https://example.com:443", nil)
	require.NoError(t, err)
	req.Host = "example.com:443"
	_, err = connectViaProxy(req, proxy.URL(), chain)
	require.Error(t, err, "proxy rejects every credential, so the tunnel fails")

	_, ok := chain.preemptiveBasic(proxy.URL().Hostname())
	assert.False(t, ok, "a rejected preemptive attempt must invalidate the cache")

	requests := proxy.requests()
	require.GreaterOrEqual(t, len(requests), 2)
	assert.Equal(t, basicHeader("user:pass"), requests[0],
		"first attempt carried the cached credentials")
}

// TestRetryProxyRequest_RecordsBasicSuccess pins that the plain-HTTP
// path populates the cache too, keyed by the proxy host from the request
// context.
func TestRetryProxyRequest_RecordsBasicSuccess(t *testing.T) {
	accepted := basicHeader("user:pass")
	proxy := newScriptedProxy([]string{`Basic realm="proxy"`}, accepted)
	defer proxy.Close()

	chain := newAuthChain(newBasicAuthenticator("user:pass"))
	resp, err := runProxyRequest(t, proxy, chain, nil)
	require.NoError(t, err)
	require.NotNil(t, resp)
	defer resp.Body.Close() //nolint:errcheck
	require.Equal(t, http.StatusOK, resp.StatusCode)

	proxyURL, err := url.Parse(proxy.URL)
	require.NoError(t, err)
	_, ok := chain.preemptiveBasic(proxyURL.Hostname())
	assert.True(t, ok, "a successful Basic attempt must be remembered")
}
