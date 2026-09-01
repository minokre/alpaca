// Copyright 2019 The Alpaca Authors
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
	"log"
	"net/http"
	"text/template"
)

// PACData contains program configuration to be made available to the pacWrapTmpl.
type PACData struct {
	Port int
}

type pacData struct {
	PACData
	UpstreamPAC string
}

type PACWrapper struct {
	data      pacData
	tmpl      *template.Template
	alpacaPAC string
}

// PACWrapper template for serving a PAC file to point at alpaca or DIRECT. If we have a valid
// PAC file, we wrap that PAC file with a wrapper function that only returns "DIRECT" or
// "127.0.0.1:port". If we do not have a PAC file, the PAC function we serve only returns
// "DIRECT", which should prevent all requests reaching us.
//
// The literal address is deliberate: naming "localhost" here makes every client resolve it
// before each proxied request. That is usually free, but not always. On Windows, a service
// resolving "localhost" early during logon was measured taking the full 60 second WinHTTP
// resolver timeout, and since nothing is listening on the proxy port at that stage either,
// the first logon of the day cost over two minutes. Alpaca listens on both loopback families
// by default, so clients reach it just as well through the literal address.
var pacWrapTmpl = `// Wrapped for and by alpaca
function FindProxyForURL(url, host) {
{{ if .UpstreamPAC }}
  return FindProxyForURL(url, host) === "DIRECT" ? "DIRECT" : "PROXY 127.0.0.1:{{.Port}}";
{{.UpstreamPAC}}
{{ else }}
  return "DIRECT";
{{ end }}
}
`

func NewPACWrapper(data PACData) *PACWrapper {
	t := template.Must(template.New("alpaca").Parse(pacWrapTmpl))
	return &PACWrapper{pacData{data, ""}, t, ""}
}

func (pw *PACWrapper) Wrap(pacjs []byte) {
	pac := string(pacjs)
	if pac == pw.data.UpstreamPAC && pw.alpacaPAC != "" {
		return
	}
	pw.data.UpstreamPAC = pac
	b := &bytes.Buffer{}
	if err := pw.tmpl.Execute(b, pw.data); err != nil {
		log.Printf("error executing PAC wrap template: %v", err)
		return
	}
	pw.alpacaPAC = b.String()
}

func (pw *PACWrapper) SetupHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/alpaca.pac", pw.handlePAC)
}

func (pw *PACWrapper) handlePAC(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
	if _, err := w.Write([]byte(pw.alpacaPAC)); err != nil {
		log.Printf("Error writing PAC to response: %v", err)
	}
}
