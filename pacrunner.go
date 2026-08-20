// Copyright 2019, 2021, 2023, 2024, 2025, 2026 The Alpaca Authors
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
	"encoding/binary"
	"errors"
	"math"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/dop251/goja"
	"github.com/gobwas/glob"
)

// https://developer.mozilla.org/en-US/docs/Web/HTTP/Proxy_servers_and_tunneling/Proxy_Auto-Configuration_(PAC)_file

// pacFunc is a PAC helper implemented in Go. It takes the runtime it belongs to, because goja
// values are bound to the runtime that created them.
type pacFunc func(vm *goja.Runtime, call goja.FunctionCall) goja.Value

// pacTimeFunc is a PAC helper whose result depends on the current time.
type pacTimeFunc func(vm *goja.Runtime, call goja.FunctionCall, now time.Time) goja.Value

type PACRunner struct {
	vm *goja.Runtime
	sync.Mutex
}

func (pr *PACRunner) Update(pacjs []byte) error {
	vm := goja.New()
	var err error
	set := func(name string, handler pacFunc) {
		if err != nil {
			return
		}
		err = vm.Set(name, func(call goja.FunctionCall) goja.Value {
			return handler(vm, call)
		})
	}
	setAt := func(name string, handler pacTimeFunc) {
		set(name, func(vm *goja.Runtime, call goja.FunctionCall) goja.Value {
			return handler(vm, call, time.Now())
		})
	}
	set("isPlainHostName", isPlainHostName)
	set("dnsDomainIs", dnsDomainIs)
	set("localHostOrDomainIs", localHostOrDomainIs)
	set("isResolvable", isResolvable)
	set("isInNet", isInNet)
	set("dnsResolve", dnsResolve)
	set("convert_addr", convertAddr)
	set("myIpAddress", myIpAddress)
	set("myIpAddressEx", myIpAddressEx)
	set("dnsDomainLevels", dnsDomainLevels)
	set("shExpMatch", shExpMatch)
	setAt("weekdayRange", weekdayRange)
	setAt("dateRange", dateRange)
	setAt("timeRange", timeRange)
	if err != nil {
		return err
	}
	if _, err = vm.RunScript("proxy.pac", string(pacjs)); err != nil {
		return err
	}
	pr.Lock()
	defer pr.Unlock()
	pr.vm = vm
	return nil
}

func (pr *PACRunner) FindProxyForURL(u url.URL) (string, error) {
	pr.Lock()
	defer pr.Unlock()
	if pr.vm == nil {
		return "", errors.New("no PAC JS has been loaded")
	}
	if u.Scheme == "" {
		// When a net/http Server parses a CONNECT request, the URL will
		// have no Scheme. In that case, assume the scheme is "https".
		u.Scheme = "https"
	}
	if u.Scheme == "https" || u.Scheme == "wss" {
		// Strip the path and query components of https:// URLs.
		// https://developer.mozilla.org/en-US/docs/Web/HTTP/Proxy_servers_and_tunneling/Proxy_Auto-Configuration_(PAC)_file#Parameters
		// Like Chrome, also strip the path and query for wss:// URLs (secure WebSockets).
		// https://cs.chromium.org/chromium/src/net/proxy_resolution/proxy_resolution_service.cc?rcl=fba6691ffca770dd0c916418601b9c9c019a2929&l=383
		// It also seems like a good idea to strip the fragment, so do that too.
		u.Path = "/"
		u.RawPath = "/"
		u.RawQuery = ""
		u.Fragment = ""
	}
	findProxyForURL, ok := goja.AssertFunction(pr.vm.Get("FindProxyForURL"))
	if !ok {
		return "", errors.New("PAC JS doesn't define a FindProxyForURL function")
	}
	val, err := findProxyForURL(goja.Undefined(),
		pr.vm.ToValue(u.String()), pr.vm.ToValue(u.Hostname()))
	if err != nil {
		return "", err
	}
	str, ok := val.Export().(string)
	if !ok {
		return "", errors.New("FindProxyForURL didn't return a string")
	}
	return str, nil
}

// lastArg returns the final argument of a call, or undefined if there are none. Unlike otto,
// goja's FunctionCall.Argument panics on a negative index, so the time-based helpers can't just
// ask for Argument(len(args)-1).
func lastArg(call goja.FunctionCall) goja.Value {
	if len(call.Arguments) == 0 {
		return goja.Undefined()
	}
	return call.Arguments[len(call.Arguments)-1]
}

// isNumber reports whether a value is a JavaScript number, as opposed to a string that merely
// looks like one. dateRange needs the distinction to tell "JAN" apart from 1.
func isNumber(v goja.Value) bool {
	switch v.Export().(type) {
	case int64, float64:
		return true
	default:
		return false
	}
}

func isPlainHostName(vm *goja.Runtime, call goja.FunctionCall) goja.Value {
	host := call.Argument(0).String()
	return vm.ToValue(!strings.ContainsRune(host, '.'))
}

func dnsDomainIs(vm *goja.Runtime, call goja.FunctionCall) goja.Value {
	host := call.Argument(0).String()
	domain := call.Argument(1).String()
	return vm.ToValue(strings.HasSuffix(host, domain))
}

func localHostOrDomainIs(vm *goja.Runtime, call goja.FunctionCall) goja.Value {
	host := call.Argument(0).String()
	hostdom := call.Argument(1).String()
	return vm.ToValue(host == hostdom || strings.HasPrefix(hostdom, host+"."))
}

func isResolvable(vm *goja.Runtime, call goja.FunctionCall) goja.Value {
	host := call.Argument(0).String()
	_, err := net.LookupHost(host)
	return vm.ToValue(err == nil)
}

func isInNet(vm *goja.Runtime, call goja.FunctionCall) goja.Value {
	host := call.Argument(0).String()
	pattern := call.Argument(1).String()
	mask := call.Argument(2).String()
	buf := net.ParseIP(mask).To4()
	if len(buf) != 4 {
		return vm.ToValue(false)
	}

	m := net.IPv4Mask(buf[0], buf[1], buf[2], buf[3])
	maskedIP := resolve(host).Mask(m)
	maskedPattern := net.ParseIP(pattern).To4().Mask(m)
	return vm.ToValue(maskedIP.Equal(maskedPattern))
}

func dnsResolve(vm *goja.Runtime, call goja.FunctionCall) goja.Value {
	host := call.Argument(0).String()
	return vm.ToValue(resolve(host).String())
}

func resolve(host string) net.IP {
	if ip := net.ParseIP(host); ip != nil {
		// The given host is already an IP(v4) address; just return it.
		return ip.To4()
	}
	addrs, err := net.LookupHost(host)
	if err != nil {
		return nil
	}
	for _, addr := range addrs {
		// There might be multiple IP addresses for this host. Return the first IPv4 address
		// that we can find.
		if ipv4 := net.ParseIP(addr).To4(); ipv4 != nil {
			return ipv4
		}
	}
	return nil
}

func convertAddr(vm *goja.Runtime, call goja.FunctionCall) goja.Value {
	ipaddr := call.Argument(0).String()
	ipv4 := net.ParseIP(ipaddr).To4()
	if ipv4 == nil {
		return vm.ToValue(0)
	}
	return vm.ToValue(binary.BigEndian.Uint32(ipv4))
}

func myIpAddress(vm *goja.Runtime, _ goja.FunctionCall) goja.Value {
	// https://chromium.googlesource.com/chromium/src/+/ee43fa5328856129f46566b2ea1be5811739681c/net/docs/proxy.md#Resolving-client_s-IP-address-within-a-PAC-script-using-myIpAddress
	if localAddr := probeRoute("8.8.8.8"); localAddr != "" {
		return vm.ToValue(localAddr)
	}
	if ips := resolveHostname(false); len(ips) > 0 {
		return vm.ToValue(ips[0].String())
	}
	private := []string{"10.0.0.0", "172.16.0.0", "192.168.0.0"}
	for _, remoteAddr := range private {
		if localAddr := probeRoute(remoteAddr); localAddr != "" {
			return vm.ToValue(localAddr)
		}
	}
	return vm.ToValue("127.0.0.1")
}

func myIpAddressEx(vm *goja.Runtime, _ goja.FunctionCall) goja.Value {
	// https://chromium.googlesource.com/chromium/src/+/ee43fa5328856129f46566b2ea1be5811739681c/net/docs/proxy.md#resolving-client_s-ip-address-within-a-pac-script-using-myipaddressex
	public := []string{"8.8.8.8", "2001:4860:4860::8888"}
	if ips := probeRoutes(public); ips != "" {
		return vm.ToValue(ips)
	}
	if ips := resolveHostname(true); len(ips) > 0 {
		var b strings.Builder
		b.WriteString(ips[0].String())
		for _, ip := range ips[1:] {
			b.WriteRune(';')
			b.WriteString(ip.String())
		}
		return vm.ToValue(b.String())
	}
	private := []string{"10.0.0.0", "172.16.0.0", "192.168.0.0", "FC00::"}
	ips := probeRoutes(private)
	return vm.ToValue(ips)
}

func probeRoutes(addresses []string) string {
	var slice []string
	set := map[string]struct{}{}
	for _, address := range addresses {
		localAddr := probeRoute(address)
		if localAddr == "" {
			continue
		}
		if _, ok := set[localAddr]; ok {
			continue
		}
		set[localAddr] = struct{}{}
		slice = append(slice, localAddr)
	}
	return strings.Join(slice, ";")
}

// probeRoute creates a UDP "connection" to the remote address, and returns the
// local interface address. This does involve a system call, but does not
// generate any network traffic since UDP is a connectionless protocol.
func probeRoute(address string) string {
	conn, err := net.Dial("udp", net.JoinHostPort(address, "80"))
	if err != nil {
		return ""
	}
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return ""
	}
	if local.IP.IsLoopback() ||
		local.IP.IsLinkLocalUnicast() ||
		local.IP.IsLinkLocalMulticast() {
		return ""
	}
	return local.IP.String()
}

// resolveHostname does a DNS resolve of the machine's hostname, and filters
// out any loopback and link-local addresses, as well as any IPv6 addresses if
// ipv6 is set to false.
func resolveHostname(ipv6 bool) []net.IP {
	host, err := os.Hostname()
	if err != nil {
		return nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil
	}
	var addrs []net.IP
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			continue
		}
		if ip.To4() != nil || ipv6 {
			addrs = append(addrs, ip)
		}
	}
	return addrs
}

func dnsDomainLevels(vm *goja.Runtime, call goja.FunctionCall) goja.Value {
	host := call.Argument(0).String()
	return vm.ToValue(strings.Count(host, "."))
}

func shExpMatch(vm *goja.Runtime, call goja.FunctionCall) goja.Value {
	str := call.Argument(0).String()
	shexp := call.Argument(1).String()
	g, err := glob.Compile(shexp)
	if err != nil {
		return goja.Undefined()
	}
	return vm.ToValue(g.Match(str))
}

func weekdayRange(vm *goja.Runtime, call goja.FunctionCall, now time.Time) goja.Value {
	if lastArg(call).String() == "GMT" {
		now = now.In(time.UTC)
	}
	weekdays := map[string]time.Weekday{
		"SUN": time.Sunday, "MON": time.Monday, "TUE": time.Tuesday, "WED": time.Wednesday,
		"THU": time.Thursday, "FRI": time.Friday, "SAT": time.Saturday,
	}
	wd1, ok := weekdays[call.Argument(0).String()]
	if !ok {
		return goja.Undefined()
	}
	wd2, ok := weekdays[call.Argument(1).String()]
	if !ok {
		return vm.ToValue(now.Weekday() == wd1)
	} else if wd1 <= wd2 {
		return vm.ToValue(wd1 <= now.Weekday() && now.Weekday() <= wd2)
	} else {
		return vm.ToValue(wd1 == now.Weekday() || wd2 == now.Weekday())
	}
}

func dateRange(vm *goja.Runtime, call goja.FunctionCall, now time.Time) goja.Value {
	argc := len(call.Arguments)
	if lastArg(call).String() == "GMT" {
		now = now.In(time.UTC)
		argc--
	}

	var days []int
	var months []time.Month
	var years []int

	monthmap := map[string]time.Month{
		"JAN": time.January, "FEB": time.February, "MAR": time.March,
		"APR": time.April, "MAY": time.May, "JUN": time.June,
		"JUL": time.July, "AUG": time.August, "SEP": time.September,
		"OCT": time.October, "NOV": time.November, "DEC": time.December,
	}

	for i := 0; i < argc; i++ {
		if isNumber(call.Argument(i)) {
			n := call.Argument(i).ToInteger()
			if 1 <= n && n <= 31 {
				days = append(days, int(n))
			} else {
				years = append(years, int(n))
			}
		} else if month, ok := monthmap[call.Argument(i).String()]; ok {
			months = append(months, month)
		} else {
			return goja.Undefined()
		}
	}

	switch max(len(days), len(months), len(years)) {
	case 1:
		// One (possibly partial) date provided; match it against the current date.
		if len(days) == 1 && days[0] != now.Day() {
			return vm.ToValue(false)
		} else if len(months) == 1 && months[0] != now.Month() {
			return vm.ToValue(false)
		} else if len(years) == 1 && years[0] != now.Year() {
			return vm.ToValue(false)
		} else {
			return vm.ToValue(true)
		}
	case 2:
		// Two dates provided; check that the current date is inside the range.
		y1, m1, d1 := now.Date()
		y2, m2, d2 := now.Date()
		if len(days) == 2 {
			d1, d2 = days[0], days[1]
		}
		if len(months) == 2 {
			m1, m2 = months[0], months[1]
		}
		if len(years) == 2 {
			y1, y2 = years[0], years[1]
		}
		h, m, s := now.Clock()
		ns, loc := now.Nanosecond(), now.Location()
		start := time.Date(y1, m1, d1, h, m, s, ns, loc)
		end := time.Date(y2, m2, d2, h, m, s, ns, loc)
		return vm.ToValue(!start.After(now) && !end.Before(now))
	default:
		// Zero, three or more dates provided. Something's wrong.
		return goja.Undefined()
	}
}

func max(a, b, c int) int {
	if a >= b && a >= c {
		return a
	} else if b >= c {
		return b
	} else {
		return c
	}
}

func timeRange(vm *goja.Runtime, call goja.FunctionCall, now time.Time) goja.Value {
	argc := len(call.Arguments)
	if lastArg(call).String() == "GMT" {
		now = now.In(time.UTC)
		argc--
	}
	h1, m1, s1, h2, m2, s2 := 0, 0, 0, 0, 0, 0
	invalid := false
	toInt := func(idx int) int {
		// goja's ToInteger turns anything non-numeric into 0, so check for NaN explicitly
		// rather than silently treating a bad argument as midnight.
		f := call.Argument(idx).ToFloat()
		if math.IsNaN(f) {
			invalid = true
		}
		return int(f)
	}
	switch argc {
	case 1:
		h1 = toInt(0)
		h2 = h1 + 1
	case 2:
		h1 = toInt(0)
		h2 = toInt(1)
	case 4:
		h1, m1 = toInt(0), toInt(1)
		h2, m2 = toInt(2), toInt(3)
	case 6:
		h1, m1, s1 = toInt(0), toInt(1), toInt(2)
		h2, m2, s2 = toInt(3), toInt(4), toInt(5)
	default:
		return goja.Undefined()
	}
	if invalid {
		return goja.Undefined()
	}
	start := time.Date(now.Year(), now.Month(), now.Day(), h1, m1, s1, 0, now.Location())
	end := time.Date(now.Year(), now.Month(), now.Day(), h2, m2, s2, 0, now.Location())
	return vm.ToValue(!start.After(now) && end.After(now))
}
