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
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/CryptOS-PKI/cryptos-node/internal/console"
)

// The golden frames in testdata/screens are the console design's character
// grids: a .txt file holds the text and a .color file one colour key per
// character (spaces carry none). The keys are the design's: f frame cyan,
// b bright cyan, d dim, w default, W bright white, g green, y yellow, r red.

const (
	screenFP  = "3F2A 9C41 07BE D5A0 6E13 C8F7 2B94 E01D 5A6C 83F2 0D47 B9E5 1C08 7FA3 D26B 4E90"
	maintFP   = "8D1C 4F07 A2E9 3B56 C0F4 71DA 9E28 5B13 E64A 0C9F 27B1 D853 4FA6 1E0C 93B7 6D2F"
	screenVer = "v0.1.0"
	rootName  = "Example Root CA G1"
)

func servingRoot() console.View {
	return console.View{
		RootCN: rootName, Issuer: "self-signed", Role: "ROOT", NodeStatus: "ESTABLISHED",
		TPM: "SEALED", Uptime: 74*time.Hour + 14*time.Minute, Version: screenVer,
		Fleet: console.FleetNotEnrolled, MgmtFingerprint: screenFP, MgmtCASigned: true,
	}
}

// screenCases maps each golden frame to the render that must produce it. A
// name ending in "-64x24" is the same state at 64x24; the rest are 80x25,
// except the boot stream and the 38x11 compact views.
func screenCases() map[string]func(cols, rows int) string {
	dash := func(v console.View) func(cols, rows int) string {
		return func(cols, rows int) string { return console.RenderDashboard(v, cols, rows) }
	}
	intermediate := servingRoot()
	intermediate.RootCN, intermediate.Issuer, intermediate.Role = "Example Intermediate CA G1", rootName, "INTERMEDIATE"
	intermediate.Fleet, intermediate.TPM, intermediate.Uptime = console.FleetConnected, "UNAVAILABLE", 12*24*time.Hour+7*time.Hour+41*time.Minute
	issuing := servingRoot()
	issuing.RootCN, issuing.Issuer, issuing.Role = "Example Issuing CA G1", "Example Intermediate CA G1", "ISSUING"
	issuing.Fleet, issuing.Uptime = console.FleetDisconnected, 5*time.Minute
	compactRoot := servingRoot()
	compactRoot.MgmtCASigned = false

	maintenance := console.View{Maintenance: true, Version: screenVer, MgmtFingerprint: maintFP, MgmtAddrs: []string{"192.0.2.10", "198.51.100.24"}}
	awaitingCeremony := console.View{Role: "ROOT", NodeStatus: "maintenance", TPM: "SEALED", Version: screenVer, Maintenance: true, AwaitingCeremony: true, MgmtFingerprint: screenFP}
	awaitingParent := console.View{Role: "ISSUING", NodeStatus: "maintenance", TPM: "SEALED", Version: screenVer, Maintenance: true, AwaitingParentCert: true, MgmtFingerprint: screenFP, MgmtCASigned: true}
	inProgress := console.View{Role: "ROOT", NodeStatus: "establishing", TPM: "SEALED", Version: screenVer, Maintenance: true, CeremonyInProgress: true, MgmtFingerprint: screenFP}
	degraded := console.View{Degraded: true, Version: screenVer}

	framed := map[string]func(cols, rows int) string{
		"maintenance":          dash(maintenance),
		"awaiting-ceremony":    dash(awaitingCeremony),
		"awaiting-parent":      dash(awaitingParent),
		"ceremony-in-progress": dash(inProgress),
		"serving-root":         dash(servingRoot()),
		"serving-intermediate": dash(intermediate),
		"serving-issuing":      dash(issuing),
		"degraded":             dash(degraded),
		"reset-confirm": func(cols, rows int) string {
			return console.RenderResetConfirm(rootName, "Example Root CA G", screenVer, cols, rows)
		},
		"reset-mismatch": func(cols, rows int) string {
			return console.RenderResetMismatch(rootName, "Example Root CA G2", screenVer, cols, rows)
		},
		"resetting": func(cols, rows int) string { return console.RenderResetting(screenVer, cols, rows) },
	}
	cases := map[string]func(cols, rows int) string{}
	for name, f := range framed {
		cases[name] = f
		cases[name+"-64x24"] = f
	}
	for _, name := range []string{"maintenance", "awaiting-ceremony", "degraded", "reset-confirm", "reset-mismatch", "resetting"} {
		cases["compact-"+name] = framed[name]
	}
	cases["compact"] = dash(compactRoot)
	cases["boot"] = func(int, int) string { return bootStream(console.StepOK) }
	cases["boot-failed"] = func(int, int) string { return bootStream(console.StepFail) }
	return cases
}

// bootStream is the boot console after three steps, the last with state.
func bootStream(last console.StepState) string {
	var buf bytes.Buffer
	r := console.NewRenderer(&buf)
	_ = r.Banner(screenVer)
	_ = r.Step("state volume", console.StepOK)
	_ = r.Step("configuration", console.StepOK)
	_ = r.Step("network", last)
	return buf.String()
}

func screenSize(name string) (cols, rows int) {
	switch {
	case strings.HasPrefix(name, "compact"):
		return 38, 11
	case strings.HasSuffix(name, "-64x24"):
		return 64, 24
	default:
		return 80, 25
	}
}

func TestScreensMatchTheDesign(t *testing.T) {
	cases := screenCases()
	files, err := filepath.Glob(filepath.Join("testdata", "screens", "*.txt"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no golden screens: %v", err)
	}
	for _, file := range files {
		name := strings.TrimSuffix(filepath.Base(file), ".txt")
		t.Run(name, func(t *testing.T) {
			render, ok := cases[name]
			if !ok {
				t.Fatalf("no render for golden screen %s", name)
			}
			cols, rows := screenSize(name)
			raw := render(cols, rows)
			gotText, gotColor := grid(t, raw)
			wantText := readGolden(t, file)
			wantColor := readGolden(t, strings.TrimSuffix(file, ".txt")+".color")
			if gotText != wantText {
				t.Fatalf("%dx%d text differs from the design:\ngot:\n%s\nwant:\n%s", cols, rows, gotText, wantText)
			}
			if gotColor != wantColor {
				t.Fatalf("%dx%d colours differ from the design:\ngot:\n%s\nwant:\n%s", cols, rows, gotColor, wantColor)
			}
		})
	}
	for name := range cases {
		if _, err := os.Stat(filepath.Join("testdata", "screens", name+".txt")); err != nil {
			t.Errorf("render %s has no golden screen", name)
		}
	}
}

// Every framed screen fills the console exactly, at the sizes the design
// draws and at a larger and the smallest framed console.
func TestFramedScreensFillTheConsole(t *testing.T) {
	for name, render := range screenCases() {
		if strings.HasPrefix(name, "compact") || strings.HasPrefix(name, "boot") || strings.HasSuffix(name, "-64x24") {
			continue
		}
		for _, size := range []struct{ cols, rows int }{{80, 25}, {64, 24}, {100, 37}, {40, 12}} {
			lines := screenLines(render(size.cols, size.rows))
			if len(lines) != size.rows {
				t.Fatalf("%s %dx%d: %d lines", name, size.cols, size.rows, len(lines))
			}
			for i, ln := range lines {
				if len(ln) != size.cols {
					t.Fatalf("%s %dx%d: line %d is %d wide: %q", name, size.cols, size.rows, i, len(ln), ln)
				}
			}
			// From 64 columns up the footer has room for the version too.
			if size.cols >= 64 && !strings.HasSuffix(strings.TrimRight(lines[size.rows-2], " |"), screenVer) {
				t.Fatalf("%s %dx%d: footer has no version: %q", name, size.cols, size.rows, lines[size.rows-2])
			}
		}
	}
}

// A CN longer than the 39-character value column wraps onto a second value
// line instead of running into the frame.
func TestLongValuesWrapInTheValueColumn(t *testing.T) {
	v := servingRoot()
	v.RootCN = "Example Corporation Offline Root Certificate Authority G1"
	lines := screenLines(console.RenderDashboard(v, 64, 24))
	var got []string
	for i, ln := range lines {
		if strings.Contains(ln, "Root CA ") {
			got = []string{ln, lines[i+1]}
			break
		}
	}
	want := []string{
		"|    Root CA        Example Corporation Offline Root           |",
		"|                   Certificate Authority G1                   |",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("long CN:\ngot:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

var sgrCode = regexp.MustCompile("^\x1b\\[([0-9;]*)m")

// sgrKeys maps the renderer's SGR parameters to the design's colour keys.
var sgrKeys = map[string]byte{
	"0": 'w', "36": 'f', "1;36": 'b', "2": 'd', "1;37": 'W', "1;32": 'g', "1;33": 'y', "1;31": 'r',
}

// grid splits a rendered screen into its text and its colour mask, both with
// trailing spaces and trailing empty lines removed, the form of the goldens.
func grid(t *testing.T, raw string) (text, color string) {
	t.Helper()
	raw = strings.TrimPrefix(raw, "\x1b[2J\x1b[H")
	var tb, cb strings.Builder
	cur := byte('w')
	for i := 0; i < len(raw); {
		if m := sgrCode.FindStringSubmatch(raw[i:]); m != nil {
			k, ok := sgrKeys[m[1]]
			if !ok {
				t.Fatalf("unexpected SGR %q", m[1])
			}
			cur = k
			i += len(m[0])
			continue
		}
		c := raw[i]
		tb.WriteByte(c)
		switch c {
		case ' ', '\n':
			cb.WriteByte(c)
		default:
			cb.WriteByte(cur)
		}
		i++
	}
	return normalize(tb.String()), normalize(cb.String())
}

func normalize(s string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimRight(l, " ")
	}
	for len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return strings.Join(lines, "\n")
}

func readGolden(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return normalize(string(b))
}
