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
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/CryptOS-PKI/cryptos-node/internal/console"
)

// servingSnap returns a snapshot func that always reports an established root
// node with the given Root CN, so the console is in the serving state where
// reset is offered.
func servingSnap(cn string) func(context.Context) (console.View, error) {
	return func(context.Context) (console.View, error) {
		return console.View{RootCN: cn, Role: "ROOT", NodeStatus: "ESTABLISHED"}, nil
	}
}

func TestResetOnMatchingCN(t *testing.T) {
	const cn = "ACME Root CA G1"
	var buf bytes.Buffer
	keys := make(chan byte, 64)
	var gotCN string
	called := 0
	resetFn := func(_ context.Context, confirm string) error {
		gotCN = confirm
		called++
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())

	// ^R opens the confirm screen, type the exact CN, Enter submits.
	keys <- 0x12 // ^R
	for _, b := range []byte(cn) {
		keys <- b
	}
	keys <- '\r'

	done := make(chan struct{})
	go func() { runConsole(ctx, servingSnap(cn), resetFn, &buf, nil, keys, 64, 24); close(done) }()
	waitFor(t, func() bool { return called == 1 })
	cancel()
	<-done

	if gotCN != cn {
		t.Fatalf("Reset called with %q, want %q", gotCN, cn)
	}
	if !strings.Contains(buf.String(), "Resetting") {
		t.Fatalf("resetting screen not rendered:\n%s", buf.String())
	}
}

func TestResetNotCalledOnMismatch(t *testing.T) {
	const cn = "ACME Root CA G1"
	var buf bytes.Buffer
	keys := make(chan byte, 64)
	called := 0
	resetFn := func(_ context.Context, _ string) error { called++; return nil }
	ctx, cancel := context.WithCancel(context.Background())

	keys <- 0x12 // ^R
	for _, b := range []byte("WRONG NAME") {
		keys <- b
	}
	keys <- '\r'

	done := make(chan struct{})
	go func() { runConsole(ctx, servingSnap(cn), resetFn, &buf, nil, keys, 64, 24); close(done) }()
	// Give the loop time to process the keys, then stop.
	time.Sleep(30 * time.Millisecond)
	cancel()
	<-done

	if called != 0 {
		t.Fatalf("Reset must not be called on a CN mismatch, called=%d", called)
	}
}

func TestEscCancelsConfirm(t *testing.T) {
	const cn = "ACME Root CA G1"
	var buf bytes.Buffer
	keys := make(chan byte, 64)
	called := 0
	resetFn := func(_ context.Context, _ string) error { called++; return nil }
	ctx, cancel := context.WithCancel(context.Background())

	keys <- 0x12 // ^R opens confirm
	keys <- 'a'  // type something
	keys <- 0x1b // Esc cancels back to dashboard
	// A subsequent Enter must NOT submit a reset (we are back on the dashboard).
	keys <- '\r'

	done := make(chan struct{})
	go func() { runConsole(ctx, servingSnap(cn), resetFn, &buf, nil, keys, 64, 24); close(done) }()
	time.Sleep(30 * time.Millisecond)
	cancel()
	<-done

	if called != 0 {
		t.Fatalf("Esc must abort the ceremony, Reset called=%d", called)
	}
}

// waitFor polls cond until true or a short deadline, failing the test on
// timeout so a hung loop does not stall the suite.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met before deadline")
}

// The maintenance screen now carries the address and fingerprint, but the node
// has no CA to erase, so Ctrl-R still does nothing there.
func TestResetNotOfferedInMaintenance(t *testing.T) {
	var buf bytes.Buffer
	keys := make(chan byte, 4)
	called := 0
	resetFn := func(_ context.Context, _ string) error { called++; return nil }
	snap := func(context.Context) (console.View, error) {
		return console.View{
			Maintenance: true, MgmtAddrs: []string{"192.0.2.10"},
			MgmtFingerprint: console.Fingerprint([]byte("maintenance cert")),
		}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())

	keys <- 0x12 // ^R
	done := make(chan struct{})
	go func() { runConsole(ctx, snap, resetFn, &buf, nil, keys, 64, 24); close(done) }()
	time.Sleep(30 * time.Millisecond)
	cancel()
	<-done

	if called != 0 || strings.Contains(buf.String(), "Type the Root CA CN") {
		t.Fatalf("Ctrl-R armed reset on the maintenance screen (called=%d):\n%s", called, buf.String())
	}
}

// A wrong CN says that nothing was erased, then the console goes back to the
// dashboard on its own.
func TestMismatchSaysNothingWasErasedThenReturns(t *testing.T) {
	const cn = "ACME Root CA G1"
	old := mismatchHold
	mismatchHold = 20 * time.Millisecond
	defer func() { mismatchHold = old }()

	var buf syncBuffer
	keys := make(chan byte, 64)
	resetFn := func(_ context.Context, _ string) error { return nil }
	ctx, cancel := context.WithCancel(context.Background())
	keys <- 0x12 // ^R
	for _, b := range []byte("WRONG NAME") {
		keys <- b
	}
	keys <- '\r'
	done := make(chan struct{})
	go func() { runConsole(ctx, servingSnap(cn), resetFn, &buf, nil, keys, 64, 24); close(done) }()
	waitFor(t, func() bool {
		out := buf.String()
		i := strings.LastIndex(out, "Does not match. Nothing was erased.")
		return i >= 0 && strings.Contains(out[i:], "^R  reset (destroys this CA)")
	})
	cancel()
	<-done
	if !strings.Contains(buf.String(), "> WRONG NAME") {
		t.Fatalf("mismatch screen does not show what was typed:\n%s", buf.String())
	}
}

// syncBuffer is a bytes.Buffer safe to read while the console loop writes.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
