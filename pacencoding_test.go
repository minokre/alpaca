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
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A comment with an umlaut, as found in PAC files written by German administrators.
const commentUTF8 = "// Variablen für die Proxys\n"

var (
	commentCP1252 = []byte{'/', '/', ' ', 'V', 'a', 'r', 'i', 'a', 'b', 'l', 'e', 'n', ' ',
		'f', 0xFC, 'r', ' ', 'd', 'i', 'e', ' ', 'P', 'r', 'o', 'x', 'y', 's', '\n'}
	commentUTF16LE = append([]byte{0xFF, 0xFE}, utf16le(commentUTF8)...)
	commentUTF16BE = append([]byte{0xFE, 0xFF}, utf16be(commentUTF8)...)
	commentUTF8BOM = append([]byte{0xEF, 0xBB, 0xBF}, []byte(commentUTF8)...)
)

func utf16le(s string) []byte {
	var out []byte
	for _, r := range s {
		out = append(out, byte(r), byte(r>>8))
	}
	return out
}

func utf16be(s string) []byte {
	var out []byte
	for _, r := range s {
		out = append(out, byte(r>>8), byte(r))
	}
	return out
}

func TestDecodePACtoUTF8(t *testing.T) {
	tests := []struct {
		name        string
		content     []byte
		contentType string
		expected    string
	}{
		{"Empty", []byte{}, "", ""},
		{"ASCII", []byte("// plain\n"), "", "// plain\n"},
		{"ValidUTF8Unlabelled", []byte(commentUTF8), "", commentUTF8},
		{"ValidUTF8Labelled", []byte(commentUTF8),
			"application/x-ns-proxy-autoconfig; charset=utf-8", commentUTF8},
		{"CP1252Unlabelled", commentCP1252, "", commentUTF8},
		{"CP1252Labelled", commentCP1252,
			"application/x-ns-proxy-autoconfig; charset=windows-1252", commentUTF8},
		{"Latin1Labelled", commentCP1252, "text/plain; charset=iso-8859-1", commentUTF8},
		// The server claims UTF-8 but sends CP1252. Browsers would produce replacement
		// characters; we prefer to recover the text.
		{"MislabelledAsUTF8", commentCP1252, "text/plain; charset=utf-8", commentUTF8},
		{"UnknownCharset", commentCP1252, "text/plain; charset=x-nonexistent", commentUTF8},
		{"MalformedContentType", commentCP1252, "text/plain; charset=", commentUTF8},
		{"UTF8BOMStripped", commentUTF8BOM, "", commentUTF8},
		{"UTF16LE", commentUTF16LE, "", commentUTF8},
		{"UTF16BE", commentUTF16BE, "", commentUTF8},
		// A BOM wins over a conflicting declared charset.
		{"BOMBeatsDeclaredCharset", commentUTF16LE, "text/plain; charset=windows-1252",
			commentUTF8},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := decodePACtoUTF8(test.content, test.contentType)
			assert.Equal(t, test.expected, string(actual))
			assert.True(t, utf8.Valid(actual), "result must be valid UTF-8")
		})
	}
}

// TestPACRunnerAcceptsCP1252 is the regression test for the actual failure: a PAC file with a
// single non-ASCII byte in a comment used to stop PACRunner.Update from loading the script.
func TestPACRunnerAcceptsCP1252(t *testing.T) {
	pacjs := append([]byte(nil), commentCP1252...)
	pacjs = append(pacjs, []byte(
		`function FindProxyForURL(url, host) { return "PROXY proxy.test:8080" }`)...)

	pr := new(PACRunner)
	require.Error(t, pr.Update(pacjs), "raw CP1252 should be rejected by the JS engine")

	require.NoError(t, pr.Update(decodePACtoUTF8(pacjs, "")))
	u, err := url.Parse("https://www.test/")
	require.NoError(t, err)
	proxy, err := pr.FindProxyForURL(*u)
	require.NoError(t, err)
	assert.Equal(t, "PROXY proxy.test:8080", proxy)
}

// TestFetchCP1252PAC checks the end-to-end path: a server that serves a CP1252 PAC file without
// a charset parameter, exactly like the one that motivated this change.
func TestFetchCP1252PAC(t *testing.T) {
	pacjs := append([]byte(nil), commentCP1252...)
	pacjs = append(pacjs, []byte(
		`function FindProxyForURL(url, host) { return "DIRECT" }`)...)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
		_, _ = w.Write(pacjs)
	}))
	defer server.Close()

	pf := newPACFetcher(server.URL)
	downloaded := pf.download()
	require.NotNil(t, downloaded)
	assert.True(t, utf8.Valid(downloaded), "downloaded PAC must be valid UTF-8")
	assert.True(t, pf.isConnected())
	assert.NoError(t, new(PACRunner).Update(downloaded))
}
