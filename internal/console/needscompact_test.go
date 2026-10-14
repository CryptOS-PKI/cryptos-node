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
	"testing"

	"github.com/CryptOS-PKI/cryptos-node/internal/console"
)

// NeedsCompact must agree with the threshold screen.render already uses to
// fall back to its compact render, since a userspace caller outside the
// package (the console font fallback) needs the same floor without
// duplicating the numbers.
func TestNeedsCompactMatchesTheFramedFloor(t *testing.T) {
	cases := []struct {
		cols, rows int
		want       bool
	}{
		{40, 12, false},
		{80, 24, false},
		{39, 12, true},
		{40, 11, true},
		{38, 11, true},
	}
	for _, c := range cases {
		if got := console.NeedsCompact(c.cols, c.rows); got != c.want {
			t.Errorf("NeedsCompact(%d, %d) = %v, want %v", c.cols, c.rows, got, c.want)
		}
	}
}
