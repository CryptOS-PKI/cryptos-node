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
