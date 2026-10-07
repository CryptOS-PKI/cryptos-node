package console_test

/*
Copyright The CryptOS Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import (
	"regexp"
	"strings"
	"testing"

	"github.com/CryptOS-PKI/cryptos-node/internal/console"
)

// gateSizes are the sizes every state must render at: the 80x24 console a
// node falls back to, a large console, and the 38x11 compact view.
var gateSizes = []struct{ cols, rows int }{{80, 24}, {100, 37}, {38, 11}}

// gateStates names each console state and the words that say which state it
// is, so the state reads the same with colour turned off.
var gateStates = []struct {
	name   string
	labels []string
}{
	{"maintenance", []string{"MAINTENANCE", "Awaiting configuration"}},
	{"awaiting-ceremony", []string{"Awaiting ceremony"}},
	{"awaiting-parent", []string{"Awaiting parent certificate"}},
	{"ceremony-in-progress", []string{"Ceremony in progress"}},
	{"serving-root", []string{"ESTABLISHED", "not enrolled", "SEALED"}},
	{"serving-intermediate", []string{"ESTABLISHED", "connected", "UNAVAILABLE"}},
	{"serving-issuing", []string{"ESTABLISHED", "disconnected"}},
	{"degraded", []string{"degraded (reconnecting)"}},
	{"reset-confirm", []string{"RESET", "WARNING: this DESTROYS this CA."}},
	{"reset-mismatch", []string{"RESET", "Does not match. Nothing was erased."}},
	{"resetting", []string{"RESET", "Resetting. Erasing key material"}},
}

// hasWord reports whether label appears in text with no letter directly
// before or after it, so "connected" does not match inside "disconnected".
func hasWord(text, label string) bool {
	return regexp.MustCompile(`(^|[^A-Za-z])` + regexp.QuoteMeta(label) + `([^A-Za-z]|$)`).MatchString(text)
}

func TestEveryStateRendersAtTheGateSizes(t *testing.T) {
	cases := screenCases()
	for _, size := range gateSizes {
		seen := map[string]string{}
		for _, st := range gateStates {
			render, ok := cases[st.name]
			if !ok {
				t.Fatalf("no render for state %s", st.name)
			}
			lines := screenLines(render(size.cols, size.rows))
			plain := strings.Join(lines, "\n")
			framed := size.cols >= 40 && size.rows >= 12
			if framed && len(lines) != size.rows || !framed && len(lines) > size.rows {
				t.Fatalf("%s %dx%d: %d lines", st.name, size.cols, size.rows, len(lines))
			}
			for i, ln := range lines {
				if framed && len(ln) != size.cols || len(ln) > size.cols {
					t.Fatalf("%s %dx%d: line %d is %d wide: %q", st.name, size.cols, size.rows, i, len(ln), ln)
				}
			}
			for _, label := range st.labels {
				if !hasWord(plain, label) {
					t.Errorf("%s %dx%d: no %q in the text:\n%s", st.name, size.cols, size.rows, label, plain)
				}
			}
			footer := lines[len(lines)-1]
			if framed {
				footer = lines[size.rows-2]
			}
			if !strings.Contains(footer, " "+screenVer) || strings.Contains(plain, "v"+screenVer) {
				t.Errorf("%s %dx%d: footer %q, want %s once", st.name, size.cols, size.rows, footer, screenVer)
			}
			if other, dup := seen[plain]; dup {
				t.Errorf("%dx%d: %s and %s differ only in colour", size.cols, size.rows, st.name, other)
			}
			seen[plain] = st.name
		}
	}
}

// Boot steps are told apart by their marker text, not their colour, and the
// banner names the version once.
func TestBootStepsSayTheirState(t *testing.T) {
	ok := stripSGR(bootStream(console.StepOK))
	failed := stripSGR(bootStream(console.StepFail))
	if !strings.Contains(ok, "[ok]  network") || strings.Contains(ok, "[!!]") {
		t.Fatalf("boot stream:\n%s", ok)
	}
	if !strings.Contains(failed, "[!!]  network") {
		t.Fatalf("failed boot stream:\n%s", failed)
	}
	if !strings.Contains(ok, "CryptOS PKI "+screenVer+"\n") {
		t.Fatalf("boot banner has no %s line:\n%s", screenVer, ok)
	}
}
