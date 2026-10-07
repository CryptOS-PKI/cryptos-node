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

func TestConfirmStateAccumulatesPrintable(t *testing.T) {
	var c console.ConfirmState
	for _, b := range []byte("Root CA G1") {
		if submit := c.Key(b); submit {
			t.Fatalf("printable byte %q must not submit", b)
		}
	}
	if c.Typed != "Root CA G1" {
		t.Fatalf("Typed = %q, want %q", c.Typed, "Root CA G1")
	}
}

func TestConfirmStateBackspaceTrims(t *testing.T) {
	var c console.ConfirmState
	for _, b := range []byte("abc") {
		c.Key(b)
	}
	c.Key(0x7f) // DEL
	c.Key(0x08) // BS
	if c.Typed != "a" {
		t.Fatalf("after two backspaces Typed = %q, want %q", c.Typed, "a")
	}
	// Backspace on empty is a no-op.
	c.Key(0x7f)
	c.Key(0x7f)
	if c.Typed != "" {
		t.Fatalf("backspace past empty Typed = %q, want empty", c.Typed)
	}
	c.Key(0x7f)
	if c.Typed != "" {
		t.Fatalf("backspace on empty must stay empty, got %q", c.Typed)
	}
}

func TestConfirmStateEnterSubmits(t *testing.T) {
	var c console.ConfirmState
	c.Key('x')
	if submit := c.Key('\r'); !submit {
		t.Fatal("CR must submit")
	}
	var d console.ConfirmState
	d.Key('y')
	if submit := d.Key('\n'); !submit {
		t.Fatal("LF must submit")
	}
}

func TestConfirmStateIgnoresControlBytes(t *testing.T) {
	var c console.ConfirmState
	c.Key('a')
	// A stray control byte other than BS/DEL/CR/LF is ignored, not appended.
	if submit := c.Key(0x01); submit {
		t.Fatal("control byte must not submit")
	}
	if c.Typed != "a" {
		t.Fatalf("control byte must not append, Typed = %q", c.Typed)
	}
	// An escape sequence byte (as ESC would start, were it not intercepted by
	// the caller before reaching Key) is likewise dropped, not appended.
	c2 := console.ConfirmState{}
	c2.Key(0x1b)
	if c2.Typed != "" {
		t.Fatalf("ESC must not append, Typed = %q", c2.Typed)
	}
}

// TestConfirmStateMatchesCNExactly drives ConfirmState through its public byte
// input (as the console's raw-tty reader would deliver it, one UTF-8 byte at a
// time) and checks the typed text against the CN exactly, for an ASCII CN, a
// Latin-accented CN, a non-Latin CN, and a mismatch.
func TestConfirmStateMatchesCNExactly(t *testing.T) {
	cases := []struct {
		name  string
		cn    string
		typed string
		want  bool
	}{
		{"ascii match", "Example Root CA", "Example Root CA", true},
		{"ascii mismatch", "Example Root CA", "Example Root CB", false},
		{"latin accented match", "Exämple Root CA", "Exämple Root CA", true},
		{"latin accented mismatch", "Exämple Root CA", "Example Root CA", false},
		{"non-latin match", "示例根 CA", "示例根 CA", true},
		{"non-latin mismatch", "示例根 CA", "示例跟 CA", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var c console.ConfirmState
			for _, b := range []byte(tc.typed) {
				if submit := c.Key(b); submit {
					t.Fatalf("byte %#x must not submit mid-string", b)
				}
			}
			if submit := c.Key('\r'); !submit {
				t.Fatal("CR must submit")
			}
			if got := c.Typed == tc.cn; got != tc.want {
				t.Fatalf("Typed %q == CN %q = %v, want %v", c.Typed, tc.cn, got, tc.want)
			}
		})
	}
}

// TestConfirmStateBackspaceRemovesWholeRune types a multi-byte rune and checks
// that one backspace removes the whole rune, not one byte of it.
func TestConfirmStateBackspaceRemovesWholeRune(t *testing.T) {
	var c console.ConfirmState
	for _, b := range []byte("ä") { // 2-byte UTF-8 rune (U+00E4)
		if submit := c.Key(b); submit {
			t.Fatal("rune byte must not submit")
		}
	}
	if c.Typed != "ä" {
		t.Fatalf("Typed = %q, want %q", c.Typed, "ä")
	}
	c.Key(0x7f) // one backspace
	if c.Typed != "" {
		t.Fatalf("one backspace must remove the whole rune, Typed = %q", c.Typed)
	}

	// Mixed ASCII + multi-byte: backspace trims the last rune only.
	var d console.ConfirmState
	for _, b := range []byte("a示") {
		d.Key(b)
	}
	if d.Typed != "a示" {
		t.Fatalf("Typed = %q, want %q", d.Typed, "a示")
	}
	d.Key(0x7f)
	if d.Typed != "a" {
		t.Fatalf("after backspace Typed = %q, want %q", d.Typed, "a")
	}
}

// TestConfirmStateAcceptsAnyPrintableRune checks that typing accepts Latin
// accented and non-Latin printable runes, not only ASCII, while a bare
// control byte is still rejected.
func TestConfirmStateAcceptsAnyPrintableRune(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"latin accented", "Exämple Root CA G1"},
		{"greek", "Παράδειγμα"},
		{"cjk", "示例根证书"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var c console.ConfirmState
			for _, b := range []byte(tc.input) {
				if submit := c.Key(b); submit {
					t.Fatalf("byte %#x must not submit", b)
				}
			}
			if c.Typed != tc.input {
				t.Fatalf("Typed = %q, want %q", c.Typed, tc.input)
			}
		})
	}
}

// TestConfirmStateDecodesSplitUTF8 feeds a multi-byte rune's bytes to Key one
// at a time, as a raw-tty reader delivers them across separate reads, and
// checks the rune is only appended once the full encoding has arrived.
func TestConfirmStateDecodesSplitUTF8(t *testing.T) {
	// "€" (U+20AC) is a 3-byte UTF-8 sequence: 0xE2 0x82 0xAC.
	raw := []byte("€")
	if len(raw) != 3 {
		t.Fatalf("test fixture: want a 3-byte rune, got %d bytes", len(raw))
	}
	var c console.ConfirmState
	if submit := c.Key(raw[0]); submit {
		t.Fatal("partial rune must not submit")
	}
	if c.Typed != "" {
		t.Fatalf("after 1 of 3 bytes Typed = %q, want empty (incomplete rune withheld)", c.Typed)
	}
	if submit := c.Key(raw[1]); submit {
		t.Fatal("partial rune must not submit")
	}
	if c.Typed != "" {
		t.Fatalf("after 2 of 3 bytes Typed = %q, want empty (incomplete rune withheld)", c.Typed)
	}
	if submit := c.Key(raw[2]); submit {
		t.Fatal("completed rune must not itself submit")
	}
	if c.Typed != "€" {
		t.Fatalf("after 3 of 3 bytes Typed = %q, want %q", c.Typed, "€")
	}

	// A stray invalid lead byte ahead of a valid ASCII byte drops only the
	// invalid byte and keeps the ASCII byte.
	var d console.ConfirmState
	d.Key(0xc3) // lead byte of a 2-byte sequence, never completed
	d.Key('a')  // not a valid continuation byte: the pending lead byte is dropped
	if d.Typed != "a" {
		t.Fatalf("Typed = %q, want %q (invalid lead byte dropped)", d.Typed, "a")
	}
}

func TestRenderResetConfirmContent(t *testing.T) {
	const cols, rows = 64, 24
	raw := console.RenderResetConfirm("ACME Root CA G1", "ACME Roo", "v0.1.0", cols, rows)
	out := stripSGR(raw)
	// Destructive warning is present and unmistakable.
	if !strings.Contains(strings.ToUpper(out), "DESTROY") && !strings.Contains(strings.ToUpper(out), "ERASE") {
		t.Fatalf("confirm screen lacks a destructive warning:\n%s", out)
	}
	// The Root CN the operator must type is shown.
	if !strings.Contains(out, "ACME Root CA G1") {
		t.Fatalf("confirm screen does not show the Root CN prompt:\n%s", out)
	}
	// The typed buffer is echoed.
	if !strings.Contains(out, "> ACME Roo") {
		t.Fatalf("confirm screen does not echo the typed text:\n%s", out)
	}
	// The confirm screen also fills the console: full-width lines, rows total.
	lines := screenLines(raw)
	if len(lines) != rows {
		t.Fatalf("confirm frame has %d lines, want %d", len(lines), rows)
	}
	for i, ln := range lines {
		if len(ln) != cols {
			t.Fatalf("confirm line %d is %d wide, want %d: %q", i, len(ln), cols, ln)
		}
	}
}
