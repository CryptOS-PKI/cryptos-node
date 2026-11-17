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
	"errors"
	"strings"
	"testing"

	"github.com/CryptOS-PKI/cryptos-node/internal/console"
)

func TestBannerHasMarkAndVersion(t *testing.T) {
	b := console.Banner("v0.1.0")
	if !strings.Contains(b, "\nCryptOS PKI v0.1.0\n") {
		t.Fatalf("banner missing wordmark and version:\n%s", b)
	}
	if !strings.HasPrefix(b, ".-----. | .-----.\n") || !strings.Contains(b, "'---------------'\n") {
		t.Fatalf("banner missing the mark:\n%s", b)
	}
}

func TestRendererBanner(t *testing.T) {
	var buf bytes.Buffer
	if err := console.NewRenderer(&buf).Banner("v0.1.0"); err != nil {
		t.Fatal(err)
	}
	if buf.String() != console.Banner("v0.1.0") {
		t.Fatalf("Banner() writer output differs from Banner() string")
	}
}

func TestRendererShutdown(t *testing.T) {
	var buf bytes.Buffer
	if err := console.NewRenderer(&buf).Shutdown("v0.1.0", "Rebooting..."); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if !strings.HasPrefix(got, "\x1b[2J\x1b[H") {
		t.Fatalf("Shutdown did not clear the screen first:\n%q", got)
	}
	if !strings.Contains(got, console.Banner("v0.1.0")) {
		t.Fatalf("Shutdown missing the boot banner's mark and version:\n%s", got)
	}
	if !strings.HasSuffix(got, "Rebooting...\n") {
		t.Fatalf("Shutdown missing the message:\n%s", got)
	}
}

func TestRendererStep(t *testing.T) {
	cases := []struct {
		name  string
		state console.StepState
		want  string
	}{
		{"state volume", console.StepOK, "[ok]  state volume\n"},
		{"network", console.StepRunning, "[..]  network\n"},
		{"management API", console.StepFail, "[!!]  management API\n"},
	}
	for _, c := range cases {
		var buf bytes.Buffer
		if err := console.NewRenderer(&buf).Step(c.name, c.state); err != nil {
			t.Fatal(err)
		}
		if buf.String() != c.want {
			t.Fatalf("Step(%q,%v) = %q, want %q", c.name, c.state, buf.String(), c.want)
		}
	}
}

// A failed stage shows why it failed, not just where: the cause is drawn under
// the stage line, wrapped to the screen so it can be read on a VM console.
func TestRendererStepFailedShowsTheCause(t *testing.T) {
	cause := errors.New("init: ServerTLSConfig: the mTLS listener needs the full bootstrap admin certificate (PEM), not just a fingerprint")
	var buf bytes.Buffer
	if err := console.NewRenderer(&buf).StepFailed("management API", cause); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	if lines[0] != "[!!]  management API" {
		t.Fatalf("first line = %q, want the failed stage line", lines[0])
	}
	if len(lines) < 2 {
		t.Fatalf("no cause drawn under the stage:\n%s", buf.String())
	}
	var words []string
	for _, l := range lines[1:] {
		if len(l) > console.FailDetailWidth {
			t.Fatalf("cause line is %d columns, over the %d the screen shows: %q", len(l), console.FailDetailWidth, l)
		}
		if !strings.HasPrefix(l, "      ") {
			t.Fatalf("cause line %q is not indented under the stage", l)
		}
		words = append(words, strings.Fields(l)...)
	}
	if got := strings.Join(words, " "); got != cause.Error() {
		t.Fatalf("the cause was altered when wrapped:\n got %q\nwant %q", got, cause.Error())
	}
}

func TestRendererStepFailedWithNoCauseIsTheStageLine(t *testing.T) {
	var buf bytes.Buffer
	if err := console.NewRenderer(&buf).StepFailed("network", nil); err != nil {
		t.Fatal(err)
	}
	if buf.String() != "[!!]  network\n" {
		t.Fatalf("got %q, want only the stage line", buf.String())
	}
}

// A very long cause is cut to a few lines and says so, so it can't scroll the
// stage line off a 25-line console.
func TestRendererStepFailedTruncatesALongCause(t *testing.T) {
	cause := errors.New(strings.Repeat("word ", 400))
	var buf bytes.Buffer
	if err := console.NewRenderer(&buf).StepFailed("clock", cause); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	if len(lines) > 1+console.FailDetailMaxLines {
		t.Fatalf("%d lines drawn, want at most %d", len(lines), 1+console.FailDetailMaxLines)
	}
	if !strings.HasSuffix(lines[len(lines)-1], "...") {
		t.Fatalf("a cut cause must end with an ellipsis, last line %q", lines[len(lines)-1])
	}
}

// One word longer than the line (a long path or hash) is split, not dropped or
// left to run off the screen.
func TestRendererStepFailedSplitsAnOverlongWord(t *testing.T) {
	cause := errors.New("bad " + strings.Repeat("x", 200))
	var buf bytes.Buffer
	if err := console.NewRenderer(&buf).StepFailed("state volume", cause); err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")[1:] {
		if len(l) > console.FailDetailWidth {
			t.Fatalf("line of %d columns: %q", len(l), l)
		}
	}
	if strings.Count(buf.String(), "x") < 150 {
		t.Fatalf("most of the long word was dropped:\n%s", buf.String())
	}
}
