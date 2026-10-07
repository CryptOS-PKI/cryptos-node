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
	"strings"
	"testing"

	"github.com/CryptOS-PKI/cryptos-node/internal/console"
)

// A CA name too long for the compact view stops at the console edge and says
// it was cut, so the footer stays on the last row.
func TestCompactCANameStopsAtTheConsoleEdge(t *testing.T) {
	v := servingRoot()
	v.RootCN = "Example Corporation Offline Root Certificate Authority G1"
	lines := screenLines(console.RenderDashboard(v, 38, 11))
	if len(lines) != 11 {
		t.Fatalf("%d lines, want 11:\n%s", len(lines), strings.Join(lines, "\n"))
	}
	for i, ln := range lines {
		if len(ln) > 38 {
			t.Fatalf("line %d is %d wide: %q", i, len(ln), ln)
		}
	}
	if want := "CA    Example Corporation Offline R..."; lines[1] != want {
		t.Fatalf("CA line = %q, want %q", lines[1], want)
	}
}

// The reset screen shows the whole CN the operator must type, split over rows
// when it is wider than the console, at a framed and at the compact size.
func TestResetShowsTheWholeCN(t *testing.T) {
	cn := strings.Repeat("RootCA01", 8) // 64 characters, the X.509 limit
	for _, size := range []struct{ cols, rows int }{{64, 24}, {38, 11}} {
		lines := screenLines(console.RenderResetConfirm(cn, "", screenVer, size.cols, size.rows))
		var joined strings.Builder
		for i, ln := range lines {
			if len(ln) > size.cols {
				t.Fatalf("%dx%d: line %d is %d wide: %q", size.cols, size.rows, i, len(ln), ln)
			}
			joined.WriteString(strings.Trim(ln, "| "))
		}
		if !strings.Contains(joined.String(), cn) {
			t.Fatalf("%dx%d: the CN is not shown whole:\n%s", size.cols, size.rows, strings.Join(lines, "\n"))
		}
	}
}
