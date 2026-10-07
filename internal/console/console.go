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
	"io"
	"strings"
)

// mark is the CryptOS mark drawn in ASCII: a frame with a keyhole that opens
// at the top. The framed screens color it; the boot stream prints it plain.
var mark = [...]string{
	".-----. | .-----.",
	"|       |       |",
	"|       |       |",
	"|    .--+--.    |",
	"|    |#####|    |",
	"|    |#####|    |",
	"|    '-----'    |",
	"|               |",
	"'---------------'",
}

// markWidth is the visible width of every mark line.
const markWidth = 17

// Banner returns the boot banner: the mark, then the wordmark and version.
func Banner(version string) string {
	return strings.Join(mark[:], "\n") + "\n\nCryptOS PKI " + versionTag(version) + "\n\n"
}

// markLines returns the mark centered in a frame inner columns wide, in frame
// cyan with the keyhole bright.
func markLines(inner int) []segLine {
	lines := make([]segLine, len(mark))
	for r, row := range mark {
		l := segLine{spaces((inner - markWidth) / 2)}
		for c := range row {
			color := sgrCyan
			if (c == 8 && r <= 3) || (r >= 3 && r <= 6 && c >= 5 && c <= 11) {
				color = sgrBoldCyan
			}
			if n := len(l) - 1; n > 0 && l[n].color == color {
				l[n].text += row[c : c+1]
				continue
			}
			l = append(l, seg{row[c : c+1], color})
		}
		lines[r] = l
	}
	return lines
}

// StepState is a bring-up step's outcome marker.
type StepState int

const (
	StepRunning StepState = iota // ".."
	StepOK                       // "ok"
	StepFail                     // "!!"
)

func (s StepState) marker() string {
	switch s {
	case StepOK:
		return "ok"
	case StepFail:
		return "!!"
	default:
		return ".."
	}
}

// Renderer writes the branded boot sequence to the node console.
type Renderer struct{ w io.Writer }

// NewRenderer returns a Renderer writing to w.
func NewRenderer(w io.Writer) *Renderer { return &Renderer{w: w} }

// Banner writes the boot banner once, at the start of boot.
func (r *Renderer) Banner(version string) error {
	_, err := io.WriteString(r.w, Banner(version))
	return err
}

// Step writes one bring-up status line, e.g. "[ok]  state volume".
func (r *Renderer) Step(name string, state StepState) error {
	_, err := fmt.Fprintf(r.w, "[%s]  %s\n", state.marker(), name)
	return err
}
