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
	"log"
	"mime"
	"unicode/utf8"

	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/encoding/htmlindex"
	"golang.org/x/text/encoding/unicode"
)

// decodePACtoUTF8 converts a PAC script to UTF-8.
//
// PAC files are frequently authored in a legacy single-byte encoding and served without a
// charset parameter. The JavaScript engine rejects invalid UTF-8 anywhere in the script,
// including inside comments, so a single umlaut in a comment is enough to stop the whole
// script from loading.
//
// The rules follow what browsers do: a byte order mark wins over everything else, then an
// explicitly declared charset, then UTF-8 if the bytes happen to be valid, and finally
// Windows-1252 as the legacy fallback. contentType may be empty, e.g. for local files.
func decodePACtoUTF8(content []byte, contentType string) []byte {
	if len(content) == 0 {
		return content
	}
	if dec, name, ok := bomDecoder(content); ok {
		return decodeWith(content, dec, name)
	}
	if declared, ok := charsetFromContentType(contentType); ok {
		enc, err := htmlindex.Get(declared)
		if err != nil {
			log.Printf("PAC file declares unknown charset %q, ignoring it", declared)
		} else if canonical, _ := htmlindex.Name(enc); canonical != "utf-8" {
			return decodeWith(content, enc.NewDecoder(), canonical)
		}
		// A declared UTF-8 charset is not trusted on its own; fall through to the check
		// below, so that mislabelled content still gets the Windows-1252 treatment.
	}
	if utf8.Valid(content) {
		return content
	}
	return decodeWith(content, charmap.Windows1252.NewDecoder(), "windows-1252")
}

// bomDecoder returns a decoder for the byte order mark at the start of content, if there is one.
func bomDecoder(content []byte) (*encoding.Decoder, string, bool) {
	switch {
	case bytes.HasPrefix(content, []byte{0xEF, 0xBB, 0xBF}):
		return unicode.UTF8BOM.NewDecoder(), "utf-8 (BOM)", true
	case bytes.HasPrefix(content, []byte{0xFF, 0xFE}):
		dec := unicode.UTF16(unicode.LittleEndian, unicode.ExpectBOM).NewDecoder()
		return dec, "utf-16le (BOM)", true
	case bytes.HasPrefix(content, []byte{0xFE, 0xFF}):
		dec := unicode.UTF16(unicode.BigEndian, unicode.ExpectBOM).NewDecoder()
		return dec, "utf-16be (BOM)", true
	}
	return nil, "", false
}

// charsetFromContentType extracts the charset parameter from a Content-Type header.
func charsetFromContentType(contentType string) (string, bool) {
	if contentType == "" {
		return "", false
	}
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return "", false
	}
	charset := params["charset"]
	return charset, charset != ""
}

// decodeWith transcodes content, returning it unchanged if the decoder fails.
func decodeWith(content []byte, dec *encoding.Decoder, name string) []byte {
	decoded, err := dec.Bytes(content)
	if err != nil {
		log.Printf("Error decoding PAC JS as %s, using it as-is: %v", name, err)
		return content
	}
	log.Printf("Decoded PAC JS from %s to UTF-8", name)
	return decoded
}
