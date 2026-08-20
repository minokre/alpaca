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
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// The maximum size (in bytes) allowed for a PAC script. At 1 MB, this matches the limit in Chrome.
const maxResponseBytes = 1 * 1024 * 1024

// The maximum size (in bytes) allowed for a data URL.
// Chromium and Firefox limit data URLs to 512MB.
// See https://developer.mozilla.org/en-US/docs/Web/URI/Reference/Schemes/data#length_limitations
const maxDataURLLength = 512 * 1024 * 1024

// The time to wait before retrying a failed PAC download. This is similar to Chrome's delay:
// https://cs.chromium.org/chromium/src/net/proxy_resolution/proxy_resolution_service.cc?l=96&rcl=3db5f65968c3ecab3932c1ff7367ad28834f9502
var delayAfterFailedDownload = 2 * time.Second

// How long to wait before looking for the PAC file again after giving up on it, and the ceiling
// that this delay backs off to. Until a PAC script has been loaded, every request is sent
// DIRECT, so it's worth looking again eagerly: a common reason to be without one is that alpaca
// started before the machine's DNS or VPN connection was ready, and that resolves itself within
// a minute or two. The ceiling stays low for the same reason, since a failed lookup is cheap
// while sending a whole session's traffic DIRECT is not.
var (
	initialRetryDelay = 5 * time.Second
	maxRetryDelay     = 1 * time.Minute
)

type pacFetcher struct {
	pacFinder   *pacFinder
	monitor     netMonitor
	client      *http.Client
	connected   bool
	nextAttempt time.Time
	retryDelay  time.Duration
	//cache  []byte
	//modified time.Time
	//fetched time.Time
	//expiry   time.Time
	//etag     string
}

func newPACFetcher(pacurl string) *pacFetcher {
	client := &http.Client{Timeout: 30 * time.Second}
	if strings.HasPrefix(pacurl, "file:") {
		log.Print("Warning: When using a local PAC file, the online/offline status can't ",
			"be determined by the fact that the PAC file is downloaded. Make sure you ",
			"check for proxy connectivity in your PAC file!")
	} else {
		// The DefaultClient in net/http uses the proxy specified in the http(s)_proxy
		// environment variable, which could be pointing at this instance of alpaca. When
		// fetching the PAC file, we always use a client that goes directly to the server,
		// rather than via a proxy.
		client.Transport = &http.Transport{Proxy: nil}
	}
	return &pacFetcher{
		pacFinder: newPacFinder(pacurl),
		monitor:   newNetMonitor(),
		client:    client,
	}
}

func fileURLPath(uri, goos string) (string, error) {
	parsed, err := url.Parse(uri)
	if err != nil {
		return "", fmt.Errorf("error parsing local PAC URL: %w", err)
	}
	if parsed.Scheme != "file" {
		return "", fmt.Errorf("local PAC URL must use the file scheme")
	}

	if goos == "windows" {
		path := strings.ReplaceAll(parsed.Path, "/", `\`)
		if len(parsed.Host) == 2 && parsed.Host[1] == ':' {
			return parsed.Host + path, nil
		}
		if parsed.Host != "" && !strings.EqualFold(parsed.Host, "localhost") {
			return `\\` + parsed.Host + path, nil
		}
		if len(path) >= 3 && path[0] == '\\' && path[2] == ':' {
			path = path[1:]
		}
		return path, nil
	}

	if parsed.Host != "" && parsed.Host != "localhost" {
		return "", fmt.Errorf("local PAC URL with remote host %q is unsupported", parsed.Host)
	}
	return filepath.FromSlash(parsed.Path), nil
}

func readLocalPAC(uri string) ([]byte, error) {
	path, err := fileURLPath(uri, runtime.GOOS)
	if err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open local PAC file: %w", err)
	}
	defer file.Close() //nolint:errcheck

	content, err := io.ReadAll(io.LimitReader(file, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("cannot read local PAC file: %w", err)
	}
	if len(content) > maxResponseBytes {
		return nil, fmt.Errorf("PAC JS is too big (limit is %d bytes)", maxResponseBytes)
	}
	return content, nil
}

func requireOK(resp *http.Response, err error) (*http.Response, error) {
	if err != nil {
		return resp, err
	} else if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("expected status 200 OK, got %s", resp.Status)
	} else {
		return resp, nil
	}
}

// decodeDataURL decodes a data URL (e.g., data:text/plain;base64,SGVsbG8sIFdvcmxkIQ==).
// It supports both base64 and URL-encoded data, and enforces the maxResponseBytes size limit.
// See https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/Data_URLs for details.
func decodeDataURL(uri string) ([]byte, error) {
	parsedURL, err := url.Parse(uri)

	if err != nil {
		return nil, fmt.Errorf("error parsing pac url: %w", err)
	}

	if parsedURL.Scheme != "data" {
		return nil, nil
	}

	if len(uri) > maxDataURLLength {
		return nil, fmt.Errorf("error parsing data URL: PAC JS is too big (limit is %d bytes)",
			maxDataURLLength)
	}

	metadata, data, ok := strings.Cut(parsedURL.Opaque, ",")
	if !ok {
		return nil, fmt.Errorf("error parsing data URL: invalid format")
	}

	if strings.HasSuffix(metadata, ";base64") {
		bytes, err := base64.StdEncoding.DecodeString(data)
		if err != nil {
			return nil, fmt.Errorf("error decoding base64 data URL: %w", err)
		}
		return bytes, nil
	}

	decoded, err := url.PathUnescape(data)
	if err != nil {
		return nil, fmt.Errorf("error parsing data URL: %w", err)
	}
	return []byte(decoded), nil
}

func (pf *pacFetcher) download() []byte {
	// TODO: Combine pacChanged() and findPACURL() as described in
	// https://github.com/samuong/alpaca/pull/156#issuecomment-3125070335
	if !pf.monitor.addrsChanged() && !pf.pacFinder.pacChanged() && !pf.retryDue() {
		return nil
	}
	pacjs, configured := pf.downloadNow()
	pf.scheduleRetry(configured)
	return pacjs
}

// retryDue reports whether a scheduled retry has come due.
func (pf *pacFetcher) retryDue() bool {
	return !pf.nextAttempt.IsZero() && !time.Now().Before(pf.nextAttempt)
}

// scheduleRetry arranges for another attempt when this one didn't leave us with a usable PAC
// script. Without it, a PAC server that can't be reached at startup would keep every request on
// DIRECT until the machine's network addresses happen to change; alpaca starting before a VPN
// connection has finished coming up is a common way to end up in that state.
//
// The delay doubles with each consecutive failure, up to maxRetryDelay, so a server that comes
// back shortly is picked up quickly while one that stays away is polled rarely. If no PAC URL is
// configured at all there is nothing to retry, so don't schedule anything.
func (pf *pacFetcher) scheduleRetry(configured bool) {
	if pf.connected || !configured {
		pf.retryDelay = 0
		pf.nextAttempt = time.Time{}
		return
	}
	if pf.retryDelay == 0 {
		pf.retryDelay = initialRetryDelay
	} else if pf.retryDelay < maxRetryDelay {
		pf.retryDelay *= 2
		if pf.retryDelay > maxRetryDelay {
			pf.retryDelay = maxRetryDelay
		}
	}
	pf.nextAttempt = time.Now().Add(pf.retryDelay)
	log.Printf("No PAC script available, will try again in %v", pf.retryDelay)
}

// downloadNow fetches the PAC script from wherever it lives. The second result reports whether a
// PAC URL is configured at all, i.e. whether retrying could ever help.
func (pf *pacFetcher) downloadNow() ([]byte, bool) {
	pf.connected = false

	// The network state may have changed since the last attempt, so close any "idle"
	// connections from the previous network. This forces a fresh DNS lookup and TCP dial
	// during the next PAC download. For context, see
	// <https://github.com/samuong/alpaca/issues/165>.
	pf.client.CloseIdleConnections()

	pacurl, err := pf.pacFinder.findPACURL()
	if err != nil {
		log.Printf("Error while trying to detect PAC URL: %v", err)
		return nil, true
	} else if pacurl == "" {
		log.Println("No PAC URL specified or detected; all requests will be made directly")
		return nil, false
	}

	log.Printf("Attempting to download PAC from %s", pacurl)
	if strings.HasPrefix(pacurl, "file:") {
		pac, err := readLocalPAC(pacurl)
		if err != nil {
			log.Printf("Error reading local PAC file: %v", err)
			return nil, true
		}
		pf.connected = true
		return decodePACtoUTF8(pac, ""), true
	}

	pac, err := decodeDataURL(pacurl)
	if err != nil {
		log.Printf("Error downloading PAC file: %v", err)
		return nil, true
	}

	if pac != nil {
		pf.connected = true
		return decodePACtoUTF8(pac, ""), true
	}

	resp, err := requireOK(pf.client.Get(pacurl))
	if err != nil {
		// Sometimes, if we try to download too soon after a network change, the PAC
		// download can fail. See https://github.com/samuong/alpaca/issues/8 for details.
		log.Printf("Error downloading PAC file, will retry after %v: %q",
			delayAfterFailedDownload, err)
		time.Sleep(delayAfterFailedDownload)
		if resp, err = requireOK(pf.client.Get(pacurl)); err != nil {
			log.Printf("Error downloading PAC file, giving up: %q", err)
			return nil, true
		}
	}
	defer resp.Body.Close() //nolint:errcheck
	var buf bytes.Buffer
	_, err = io.CopyN(&buf, resp.Body, maxResponseBytes)
	if err == io.EOF {
		pf.connected = true
		return decodePACtoUTF8(buf.Bytes(), resp.Header.Get("Content-Type")), true
	} else if err != nil {
		log.Printf("Error reading PAC JS from response body: %q", err)
		return nil, true
	} else {
		log.Printf("PAC JS is too big (limit is %d bytes)", maxResponseBytes)
		return nil, true
	}
}

func (pf *pacFetcher) isConnected() bool {
	return pf.connected
}
