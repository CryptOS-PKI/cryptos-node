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
