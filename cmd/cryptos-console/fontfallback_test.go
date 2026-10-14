package main

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
	"errors"
	"testing"
)

// fakeFontSwitcher is a fontSwitcher fake so the fallback decision is tested
// without a real console tty.
type fakeFontSwitcher struct {
	calls int
	err   error
}

func (f *fakeFontSwitcher) setDefaultFont() error {
	f.calls++
	return f.err
}

func TestEnsureConsoleFitsRequestsTheFallbackBelowTheFloor(t *testing.T) {
	sw := &fakeFontSwitcher{}
	cols, rows := ensureConsoleFits(sw, func() (int, int) { return 80, 24 }, 38, 11)
	if sw.calls != 1 {
		t.Fatalf("setDefaultFont calls = %d, want 1", sw.calls)
	}
	if cols != 80 || rows != 24 {
		t.Fatalf("got %dx%d, want the re-read 80x24", cols, rows)
	}
}

func TestEnsureConsoleFitsSkipsTheFallbackAtOrAboveTheFloor(t *testing.T) {
	sw := &fakeFontSwitcher{}
	readSize := func() (int, int) {
		t.Fatal("readSize must not be called when the console already fits")
		return 0, 0
	}
	cols, rows := ensureConsoleFits(sw, readSize, 40, 12)
	if sw.calls != 0 {
		t.Fatalf("setDefaultFont calls = %d, want 0", sw.calls)
	}
	if cols != 40 || rows != 12 {
		t.Fatalf("got %dx%d, want the original 40x12 unchanged", cols, rows)
	}
}

func TestEnsureConsoleFitsKeepsTheOriginalSizeOnFallbackError(t *testing.T) {
	sw := &fakeFontSwitcher{err: errors.New("ioctl failed")}
	readSize := func() (int, int) {
		t.Fatal("readSize must not be called when the fallback failed")
		return 0, 0
	}
	cols, rows := ensureConsoleFits(sw, readSize, 38, 11)
	if sw.calls != 1 {
		t.Fatalf("setDefaultFont calls = %d, want 1", sw.calls)
	}
	if cols != 38 || rows != 11 {
		t.Fatalf("got %dx%d, want the original 38x11 kept", cols, rows)
	}
}
