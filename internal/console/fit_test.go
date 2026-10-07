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
	"unicode/utf8"

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

// A multi-byte rune landing on the chunk boundary is kept whole: every line is
// valid UTF-8 and the lines rejoin to the exact CN, never a split rune.
func TestResetSplitsOnARuneBoundaryNotAByteOffset(t *testing.T) {
	// 61 ASCII bytes, then a 2-byte rune, then more ASCII: at 64x24 the framed
	// body chunks on 62 bytes (cols-2), so a naive byte slice at offset 62
	// would fall inside the 2-byte rune's encoding.
	cn := strings.Repeat("R", 61) + "ñ" + strings.Repeat("S", 5)
	lines := screenLines(console.RenderResetConfirm(cn, "", screenVer, 64, 24))
	var joined strings.Builder
	for i, ln := range lines {
		if !utf8.ValidString(ln) {
			t.Fatalf("line %d is not valid UTF-8: %q", i, ln)
		}
		joined.WriteString(strings.Trim(ln, "| "))
	}
	if !strings.Contains(joined.String(), cn) {
		t.Fatalf("the CN is not shown whole:\n%s", strings.Join(lines, "\n"))
	}
}

// A multi-byte rune landing on the compact dashboard's cut point is kept
// whole: the line is valid UTF-8 and still ends in "...". The rune is cut
// along with the rest, rather than split, since it would not fit under the
// byte budget together with the "...".
func TestCompactCANameWithMultibyteRuneCutsOnARuneBoundary(t *testing.T) {
	// 28 ASCII bytes, then a 2-byte rune, then more ASCII: at 38x11 the cut
	// point is byte 29 (width-3), which lands on the second byte of the
	// 2-byte rune's encoding, so a naive byte slice would split it.
	v := servingRoot()
	v.RootCN = strings.Repeat("A", 28) + "ü" + strings.Repeat("B", 10)
	lines := screenLines(console.RenderDashboard(v, 38, 11))
	for i, ln := range lines {
		if !utf8.ValidString(ln) {
			t.Fatalf("line %d is not valid UTF-8: %q", i, ln)
		}
	}
	want := "CA    " + strings.Repeat("A", 28) + "..."
	if lines[1] != want {
		t.Fatalf("CA line = %q, want %q", lines[1], want)
	}
}
