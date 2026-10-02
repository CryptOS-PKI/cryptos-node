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
	"fmt"
	"strings"
)

// clearHome resets the screen: clear (2J) then move the cursor home (H).
const clearHome = "\x1b[2J\x1b[H"

// ANSI SGR codes. Only the 16 standard colors are used because the framebuffer
// console (fbcon) renders that palette; 256-color and truecolor are avoided.
// Bold is what makes a color bright on fbcon.
const (
	sgrReset      = "\x1b[0m"
	sgrDim        = "\x1b[2m"
	sgrCyan       = "\x1b[36m"
	sgrBoldCyan   = "\x1b[1;36m"
	sgrBoldWhite  = "\x1b[1;37m"
	sgrBoldGreen  = "\x1b[1;32m"
	sgrBoldYellow = "\x1b[1;33m"
	sgrBoldRed    = "\x1b[1;31m"
)

// sgr wraps s in an SGR color code and a reset. It is the single place color is
// applied, so all layout math elsewhere runs on plain (uncolored) text and the
// zero-width escapes never affect a computed width.
func sgr(code, s string) string {
	if code == "" {
		return s
	}
	return code + s + sgrReset
}

// seg is a piece of text paired with its color. A line is a sequence of segs;
// its plain width is the sum of the segs' plain lengths, so centering and
// padding math never counts the zero-width color escapes.
type seg struct {
	text  string
	color string
}

// segLine is one logical content line built from colored segments.
type segLine []seg

// plainLen returns the visible width of the line.
func (l segLine) plainLen() int {
	n := 0
	for _, s := range l {
		n += len(s.text)
	}
	return n
}

// colored renders the line with its color escapes.
func (l segLine) colored() string {
	var b strings.Builder
	for _, s := range l {
		b.WriteString(sgr(s.color, s.text))
	}
	return b.String()
}

// clipped returns the line cut to at most width visible bytes.
func (l segLine) clipped(width int) segLine {
	var out segLine
	for _, s := range l {
		if width <= 0 {
			break
		}
		if len(s.text) > width {
			s.text = s.text[:width]
		}
		out = append(out, s)
		width -= len(s.text)
	}
	return out
}

// spaces is an uncolored run of n spaces.
func spaces(n int) seg { return seg{strings.Repeat(" ", max(0, n)), ""} }

// Layout constants shared by every framed screen. Fields share one label
// column, and the label and value columns together form a block of fieldWidth
// that is centered as a whole, so the value column lines up on every screen.
const (
	labelWidth = 15
	fieldWidth = 54
	// designRows is the height of the tallest screen the design draws: the
	// mark, a gap and nine body rows. Centering on it rather than on each
	// screen's own height keeps the mark still when the screen changes.
	designRows = 19
)

// itemKind is how a body item is placed on a framed screen.
type itemKind int

const (
	itemBlank    itemKind = iota // an empty row
	itemCentered                 // a line centered across the frame
	itemField                    // a label and value in the field block
)

// item is one row, or one field that may wrap over several rows, of a
// screen's body.
type item struct {
	kind  itemKind
	line  segLine
	label string
	value string
	color string
}

func blank() item             { return item{kind: itemBlank} }
func center(segs ...seg) item { return item{kind: itemCentered, line: segs} }
func field(label, value, color string) item {
	return item{kind: itemField, label: label, value: value, color: color}
}

// screen is one console screen. Framed, it is drawn with the border, the mark,
// the body and the footer; compact, with a one-line header, the compact body
// and the footer on the last row.
type screen struct {
	tag      string
	tagColor string
	body     []item
	compact  []segLine
	footL    segLine
	footR    segLine
	// compactFoot replaces footL on the compact screen when set.
	compactFoot segLine
}

// render draws the screen at cols x rows: framed when the console is large
// enough, compact below that.
func (s screen) render(cols, rows int) string {
	if s.tagColor == "" {
		s.tagColor = sgrBoldWhite
	}
	if cols < minCols || rows < minRows {
		return s.renderCompact(cols, rows)
	}
	return s.renderFramed(cols, rows)
}

// Minimum size the framed screen needs before we fall back to a compact
// render. Below this the border and the field block cannot fit cleanly.
const (
	minCols = 40
	minRows = 12
)

// renderFramed draws the border with the wordmark and tag, the mark and body
// in the rows above the footer, and the footer just above the bottom border.
func (s screen) renderFramed(cols, rows int) string {
	inner := cols - 2
	off := max(1, (inner-fieldWidth)/2)
	room := min(fieldWidth-labelWidth, inner-off-labelWidth)

	var body []segLine
	for _, it := range s.body {
		body = append(body, it.lines(inner, off, room)...)
	}
	content := append(markLines(inner), segLine{})
	content = append(content, body...)

	interior := rows - 2
	footerRow := interior - 1
	if len(content) > footerRow {
		// A short console keeps the status and drops the mark.
		content = body
	}
	top := max(0, (footerRow-designRows-1)/2)
	top = max(0, min(top, footerRow-len(content)))

	lines := make([]string, 0, rows)
	lines = append(lines, topBorder(cols, s.tag, s.tagColor))
	for i := 0; i < interior; i++ {
		var l segLine
		switch {
		case i == footerRow:
			l = footerLine(inner, 2, s.footL, s.footR)
		case i >= top && i-top < len(content):
			l = content[i-top]
		}
		lines = append(lines, framedRow(l, inner))
	}
	lines = append(lines, sgr(sgrCyan, "'"+strings.Repeat("-", inner)+"'"))
	return clearHome + strings.Join(lines, "\n") + "\n"
}

// lines lays the item out as rows inside a frame inner columns wide, with the
// field block at column off and values wrapped to room columns.
func (it item) lines(inner, off, room int) []segLine {
	switch it.kind {
	case itemCentered:
		return []segLine{append(segLine{spaces((inner - it.line.plainLen()) / 2)}, it.line...)}
	case itemField:
		var out []segLine
		for i, chunk := range wrap(it.value, room) {
			label := ""
			if i == 0 {
				label = it.label
			}
			out = append(out, segLine{spaces(off), {fmt.Sprintf("%-*s", labelWidth, label), sgrDim}, {chunk, it.color}})
		}
		return out
	default:
		return []segLine{nil}
	}
}

// wrap splits s at spaces into lines of at most width bytes, cutting a word
// that is longer than width. An empty s is one empty line.
func wrap(s string, width int) []string {
	if len(s) <= width {
		return []string{s}
	}
	var out []string
	line := ""
	for _, w := range strings.Fields(s) {
		for len(w) > width {
			if line != "" {
				out = append(out, line)
				line = ""
			}
			out = append(out, w[:width])
			w = w[width:]
		}
		switch {
		case line == "":
			line = w
		case len(line)+1+len(w) <= width:
			line += " " + w
		default:
			out = append(out, line)
			line = w
		}
	}
	return append(out, line)
}

// framedRow renders an interior line between the side bars, padded to inner.
func framedRow(l segLine, inner int) string {
	l = l.clipped(inner)
	return sgr(sgrCyan, "|") + l.colored() + strings.Repeat(" ", inner-l.plainLen()) + sgr(sgrCyan, "|")
}

// footerLine puts the left hint and the right version tag pad columns in from
// each edge of width. When both do not fit, the hint is kept.
func footerLine(width, pad int, left, right segLine) segLine {
	gap := width - 2*pad - left.plainLen() - right.plainLen()
	if gap < 1 {
		return append(segLine{spaces(pad)}, left...)
	}
	l := append(segLine{spaces(pad)}, left...)
	l = append(l, spaces(gap))
	return append(l, right...)
}

// topBorder builds the top rule: ".- CryptOS PKI ---- TAG -." spanning cols.
func topBorder(cols int, tag, tagColor string) string {
	tg := " " + tag + " "
	dashes := cols - 2 - len(" CryptOS PKI ") - len(tg) - 2
	return sgr(sgrCyan, ".-") + sgr(sgrBoldWhite, " CryptOS PKI ") +
		sgr(sgrCyan, strings.Repeat("-", max(0, dashes))) + sgr(tagColor, tg) + sgr(sgrCyan, "-.")
}

// renderCompact is the small-console fallback: no frame, a one-line header,
// the compact body, and the footer on the last row. When the body does not
// fit, the gap under the header goes first; the status is never cut, so on a
// very small console the footer follows the body instead.
func (s screen) renderCompact(cols, rows int) string {
	lines := []segLine{{{"CryptOS PKI ", sgrBoldWhite}, {"[" + s.tag + "]", s.tagColor}}, nil}
	lines = append(lines, s.compact...)
	if len(lines)+1 > rows {
		lines = append(lines[:1], lines[2:]...)
	}
	for len(lines) < rows-1 {
		lines = append(lines, nil)
	}
	foot := s.footL
	if s.compactFoot != nil {
		foot = s.compactFoot
	}
	lines = append(lines, footerLine(cols, 0, foot, s.footR))
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = l.colored()
	}
	return clearHome + strings.Join(out, "\n") + "\n"
}
