package console

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
	"unicode"
	"unicode/utf8"
)

// ConfirmState is the pure state machine behind the reset confirmation prompt.
// It accumulates the operator's typed Root CN and reports when a line is
// submitted. It holds no terminal or transport state, so it is fully
// unit-testable without a tty.
//
// The console delivers raw tty bytes one at a time, so a multi-byte UTF-8
// rune can arrive split across separate Key calls; pending holds the bytes of
// a rune still being assembled. Typed is compared against the CN with a plain
// Go string equality (exact rune-for-rune match, no Unicode normalization).
type ConfirmState struct {
	// Typed is the operator-entered text so far.
	Typed string

	// pending holds UTF-8 bytes of a rune not yet complete.
	pending []byte
}

// Key feeds one raw input byte into the state machine and reports whether the
// line was submitted (Enter). Any printable rune (unicode.IsPrint) is
// appended once its full UTF-8 encoding has arrived, including runes split
// across multiple Key calls; backspace/delete trims the last whole rune, not
// just its last byte; CR or LF submits. A control byte, an invalid UTF-8
// encoding, or a non-printable rune is dropped so a stray escape sequence
// cannot corrupt the buffer.
func (c *ConfirmState) Key(b byte) (submit bool) {
	switch b {
	case '\r', '\n':
		c.pending = nil
		return true
	case 0x7f, 0x08: // DEL or BS: drop any partial rune, trim one whole rune
		c.pending = nil
		if c.Typed != "" {
			r := []rune(c.Typed)
			c.Typed = string(r[:len(r)-1])
		}
		return false
	default:
		c.pending = append(c.pending, b)
		for len(c.pending) > 0 && utf8.FullRune(c.pending) {
			r, size := utf8.DecodeRune(c.pending)
			c.pending = c.pending[size:]
			if r != utf8.RuneError && unicode.IsPrint(r) {
				c.Typed += string(r)
			}
		}
		// A malformed stream should never accumulate unboundedly: a complete or
		// invalid rune is always resolved above within utf8.UTFMax bytes.
		if len(c.pending) > utf8.UTFMax {
			c.pending = nil
		}
		return false
	}
}

// Wording of the reset screens.
const (
	resetWarning   = "WARNING: this DESTROYS this CA."
	resetPrompt    = "Type the Root CA CN to confirm:"
	resetMismatch  = "Does not match. Nothing was erased."
	resetBack      = "Back to status in 5s"
	resettingLine1 = "Resetting. Erasing key material"
	resettingLine2 = "and rebooting into setup..."
)

// resetFooter is the confirm footer's key hints; gap separates the two.
func resetFooter(gap string) segLine {
	return segLine{{"Enter", sgrBoldWhite}, {" confirm" + gap, sgrDim}, {"Esc/^C", sgrBoldWhite}, {" cancel", sgrDim}}
}

// resetScreen is the confirmation screen, with the mismatch lines when
// mismatch is set. The typed line shows its tail when it is wider than the
// screen, so the operator always sees what they typed last.
func resetScreen(rootCN, typed, ver string, cols int, mismatch bool) screen {
	entry := "> " + typed
	if !mismatch {
		entry += "_"
	}
	if room := cols - 4; len(entry) > room && room > 2 {
		entry = "> " + entry[len(entry)-(room-2):]
	}
	body := []item{
		center(seg{resetWarning, sgrBoldRed}), blank(),
		center(seg{"The signing key material is erased", ""}),
		center(seg{"and the node reboots to be re-set up.", ""}), blank(),
		center(seg{resetPrompt, ""}),
	}
	for _, c := range chunks(rootCN, cols-2) {
		body = append(body, center(seg{c, sgrBoldYellow}))
	}
	body = append(body, blank(), center(seg{entry, sgrBoldWhite}))
	compact := []segLine{{{resetWarning, sgrBoldRed}}, {{resetPrompt, ""}}}
	for _, c := range chunks(rootCN, cols) {
		compact = append(compact, segLine{{c, sgrBoldYellow}})
	}
	compact = append(compact, segLine{{entry, sgrBoldWhite}})
	if mismatch {
		body = append(body, center(seg{resetMismatch, sgrBoldYellow}), center(seg{resetBack, sgrDim}))
		compact = append(compact, segLine{{resetMismatch, sgrBoldYellow}}, segLine{{resetBack, sgrDim}})
	}
	return screen{
		tag: "RESET", tagColor: sgrBoldRed, body: body, compact: compact,
		footL: resetFooter("    "), compactFoot: resetFooter("  "), footR: segLine{{versionTag(ver), sgrDim}},
	}
}

// RenderResetConfirm returns the full-screen destructive-reset confirmation,
// sized to cols x rows: an ANSI clear+home, a border frame, and a centered
// prominent warning that the reset erases the CA, the exact Root CN the operator
// must retype, and the buffer typed so far. Esc or ^C aborts back to the
// dashboard, so the footer names both. Sizes below the frame minimum fall back
// to a compact render.
func RenderResetConfirm(rootCN, typed, version string, cols, rows int) string {
	return resetScreen(rootCN, typed, version, cols, false).render(cols, rows)
}

// RenderResetMismatch returns the confirmation screen after the typed CN did
// not match: it shows what was typed and says that nothing was erased before
// the console returns to the dashboard.
func RenderResetMismatch(rootCN, typed, version string, cols, rows int) string {
	return resetScreen(rootCN, typed, version, cols, true).render(cols, rows)
}

// RenderResetting returns the full-screen shown once a Reset call succeeds. The
// node wipes and reboots, so the socket connection drops moments later.
func RenderResetting(version string, cols, rows int) string {
	return screen{
		tag: "RESET", tagColor: sgrBoldRed,
		body:    []item{center(seg{resettingLine1, sgrBoldYellow}), center(seg{resettingLine2, sgrBoldYellow})},
		compact: []segLine{{{resettingLine1, sgrBoldYellow}}, {{resettingLine2, sgrBoldYellow}}},
		footL:   segLine{{"RESET IN PROGRESS", sgrBoldYellow}}, footR: segLine{{versionTag(version), sgrDim}},
	}.render(cols, rows)
}
