package isoimage

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

import "testing"

func TestBlockOffsetRefusesWhatWouldOverflow(t *testing.T) {
	const imageLen = 10 * blockSize
	cases := []struct {
		name string
		lba  uint64
		ok   bool
		want int
	}{
		{"first block", 0, true, 0},
		{"last block", 9, true, 9 * blockSize},
		{"one past the end", 10, true, 10 * blockSize},
		{"beyond the image", 11, false, 0},
		{"wraps a signed int", 1 << 63, false, 0},
		{"wraps after the multiply", 1<<63/blockSize + 1, false, 0},
		{"all ones", ^uint64(0), false, 0},
	}
	for _, c := range cases {
		got, ok := blockOffset(c.lba, imageLen)
		if ok != c.ok || got != c.want {
			t.Errorf("%s: blockOffset(%d) = %d, %v; want %d, %v", c.name, c.lba, got, ok, c.want, c.ok)
		}
	}
}
