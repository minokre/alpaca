// Copyright 2019, 2021, 2022, 2025 The Alpaca Authors
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
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	// Set the retry delay to zero, so that it doesn't delay unit tests.
	delayAfterFailedDownload = 0
}

func pacjsHandler(pacjs string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(pacjs)) }
}

type pacServerWhichFailsOnFirstTry struct {
	t     *testing.T
	count int
}

func (s *pacServerWhichFailsOnFirstTry) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	s.count++
	if s.count == 1 {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	_, err := w.Write([]byte("test script"))
	require.NoError(s.t, err)
}

type fakeNetMonitor struct {
	changed bool
}

func (nm *fakeNetMonitor) addrsChanged() bool {
	tmp := nm.changed
	nm.changed = false
	return tmp
}

// pacServerWhichIsDown refuses to serve the PAC script until up is set, like a PAC server that
// can't be reached until a VPN connection has come up.
type pacServerWhichIsDown struct {
	up bool
}

func (s *pacServerWhichIsDown) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if !s.up {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	_, _ = w.Write([]byte("test script"))
}

// pinRetryDelays shortens the retry delays for the duration of a test.
func pinRetryDelays(t *testing.T, initial, max time.Duration) {
	t.Helper()
	oldInitial, oldMax := initialRetryDelay, maxRetryDelay
	t.Cleanup(func() { initialRetryDelay, maxRetryDelay = oldInitial, oldMax })
	initialRetryDelay, maxRetryDelay = initial, max
}

func TestDownload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(pacjsHandler("test script")))
	defer server.Close()
	pf := newPACFetcher(server.URL)
	assert.Equal(t, []byte("test script"), pf.download())
	assert.True(t, pf.isConnected())
}

func TestDownloadFailsOnFirstTry(t *testing.T) {
	s := &pacServerWhichFailsOnFirstTry{t: t, count: 0}
	server := httptest.NewServer(s)
	defer server.Close()
	pf := newPACFetcher(server.URL)
	require.Equal(t, 0, s.count)
	assert.Equal(t, []byte("test script"), pf.download())
	require.Equal(t, 2, s.count)
	assert.True(t, pf.isConnected())
}

func TestDownloadWithNetworkChanges(t *testing.T) {
	// Initially, the download succeeds and we are connected (to the PAC server).
	s1 := httptest.NewServer(http.HandlerFunc(pacjsHandler("test script 1")))
	nm := &fakeNetMonitor{true}
	pf := newPACFetcher(s1.URL)
	pf.monitor = nm
	assert.Equal(t, []byte("test script 1"), pf.download())
	assert.True(t, pf.isConnected())
	// Try again. Nothing changed, so we don't get a new script, but are still connected.
	assert.Nil(t, pf.download())
	assert.True(t, pf.isConnected())
	// Disconnect from the network.
	s1.Close()
	nm.changed = true
	assert.Nil(t, pf.download())
	assert.False(t, pf.isConnected())
	// Connect to a new network.
	s2 := httptest.NewServer(http.HandlerFunc(pacjsHandler("test script 2")))
	defer s2.Close()
	nm.changed = true
	pf.pacFinder = newPacFinder(s2.URL)
	assert.Equal(t, []byte("test script 2"), pf.download())
	assert.True(t, pf.isConnected())
}

// TestRetryAfterFailedDownload covers the case where the PAC server can't be reached when alpaca
// starts up, and becomes reachable later without the machine's addresses changing. Before the
// retry existed, this left every request on DIRECT indefinitely.
func TestRetryAfterFailedDownload(t *testing.T) {
	pinRetryDelays(t, time.Millisecond, time.Millisecond)
	s := &pacServerWhichIsDown{}
	server := httptest.NewServer(s)
	defer server.Close()
	// The monitor reports a change once, for the first attempt, and never again.
	nm := &fakeNetMonitor{true}
	pf := newPACFetcher(server.URL)
	pf.monitor = nm

	require.Nil(t, pf.download())
	require.False(t, pf.isConnected())
	require.False(t, nm.addrsChanged(), "the test relies on no further network changes")

	s.up = true
	time.Sleep(5 * time.Millisecond)
	assert.Equal(t, []byte("test script"), pf.download())
	assert.True(t, pf.isConnected())
	// A successful download clears the schedule, so we stop asking.
	assert.Zero(t, pf.retryDelay)
	assert.False(t, pf.retryDue())
}

func TestRetryDelayBacksOff(t *testing.T) {
	pinRetryDelays(t, time.Second, 4*time.Second)
	server := httptest.NewServer(&pacServerWhichIsDown{})
	defer server.Close()
	pf := newPACFetcher(server.URL)
	expected := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 4 * time.Second}
	for i, want := range expected {
		// Force an attempt rather than waiting for the delay to elapse.
		pf.monitor = &fakeNetMonitor{true}
		require.Nil(t, pf.download())
		assert.Equal(t, want, pf.retryDelay, "attempt %d", i+1)
	}
}

func TestNoRetryWithoutPACURL(t *testing.T) {
	pf := newPACFetcher("")
	pf.monitor = &fakeNetMonitor{true}
	assert.Nil(t, pf.download())
	assert.False(t, pf.isConnected())
	// There's nothing to retry, so we shouldn't be scheduling attempts.
	assert.Zero(t, pf.retryDelay)
	assert.False(t, pf.retryDue())
}

func TestResponseLimit(t *testing.T) {
	bigscript := strings.Repeat("x", 2*1024*1024) // 2 MB
	server := httptest.NewServer(http.HandlerFunc(pacjsHandler(bigscript)))
	defer server.Close()
	pf := newPACFetcher(server.URL)
	assert.Nil(t, pf.download())
	assert.False(t, pf.isConnected())
}

func TestPacFromFilesystem(t *testing.T) {
	// Set up a test PAC file
	content := []byte(`function FindProxyForURL(url, host) { return "DIRECT" }`)
	tempdir, err := os.MkdirTemp("", "alpaca")
	require.NoError(t, err)
	defer os.RemoveAll(tempdir) //nolint:errcheck
	pacPath := path.Join(tempdir, "test.pac")
	require.NoError(t, os.WriteFile(pacPath, content, 0644))
	pacURL := &url.URL{Scheme: "file", Path: filepath.ToSlash(pacPath)}
	pf := newPACFetcher(pacURL.String())
	pf.monitor = newNetMonitor()
	assert.Equal(t, content, pf.download())
	assert.True(t, pf.isConnected())
}

func TestFileURLPathOnWindows(t *testing.T) {
	tests := map[string]string{
		"file:///C:/Users/alice/proxy.pac": `C:\Users\alice\proxy.pac`,
		"file:///D:/Proxy/proxy.pac":      `D:\Proxy\proxy.pac`,
		"file://server/share/proxy.pac":   `\\server\share\proxy.pac`,
		"file://C:/Proxy/proxy.pac":       `C:\Proxy\proxy.pac`,
	}
	for uri, expected := range tests {
		t.Run(uri, func(t *testing.T) {
			actual, err := fileURLPath(uri, "windows")
			require.NoError(t, err)
			assert.Equal(t, expected, actual)
		})
	}
}

func TestDecodeDataURL(t *testing.T) {
	tests := []struct {
		name     string
		uri      string
		expected string
	}{
		{
			"Base64",
			"data:application/x-ns-proxy-autoconfig;base64,ZnVuY3Rpb24gRmluZFByb3h5Rm9yVVJMKHVybCwgaG" +
				"9zdCkgewogIHJldHVybiAiUFJPWFkgcHJveHk6ODA4MCI7Cn0K",
			"function FindProxyForURL(url, host) {\n  return \"PROXY proxy:8080\";\n}\n",
		},
		{
			"URLEncoded",
			"data:,function%20FindProxyForURL(url%2C%20host)%20%7B%0A%20%20return%20%22PROXY%20proxy%3A" +
				"8080%22%3B%0A%7D%0A",
			"function FindProxyForURL(url, host) {\n  return \"PROXY proxy:8080\";\n}\n",
		},
		{
			"URLEncodedWithPlus",
			"data:,foo+bar",
			"foo+bar",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pf := newPACFetcher(test.uri)
			assert.Equal(t, test.expected, string(pf.download()))
		})
	}
}

func TestDecodeDataURL_NonDataScheme(t *testing.T) {
	uri := "http://example.com"
	got, err := decodeDataURL(uri)
	assert.Nil(t, got)
	assert.NoError(t, err)
}
