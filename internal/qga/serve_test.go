package qga

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
	"errors"
	"io"
	"sync"
	"testing"
	"testing/fstest"
	"time"
)

// scriptedPort returns its reads in order (a nil entry reads as EOF, the way a
// virtio-serial port reads with no host connected), then cancels the context.
type scriptedPort struct {
	mu     sync.Mutex
	reads  [][]byte
	out    bytes.Buffer
	cancel context.CancelFunc
}

func (p *scriptedPort) Read(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.reads) == 0 {
		p.cancel()

		return 0, io.EOF
	}
	r := p.reads[0]
	p.reads = p.reads[1:]
	if r == nil {
		return 0, io.EOF
	}

	return copy(b, r), nil
}

func (p *scriptedPort) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.out.Write(b)
}

func TestServeDropsPartialInputWhenTheHostGoes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &scriptedPort{cancel: cancel, reads: [][]byte{
		[]byte(`{"execute":"guest-ping","id":1}{"execute":"guest-shutdown"`),
		nil,
		[]byte(`}{"execute":"guest-ping","id":2}`),
	}}
	h := newFakeHost()
	done := make(chan struct{})
	go func() {
		defer close(done)
		Serve(ctx, p, h, t.Logf, time.Millisecond)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after the context ended")
	}
	ls := lines(t, p.out.String())
	if len(ls) != 3 || ls[0] != `{"return":{},"id":1}` || ls[2] != `{"return":{},"id":2}` {
		t.Fatalf("responses = %q", ls)
	}
	wantError(t, decode(t, ls[1]), "GenericError", "JSON parse error")
	if len(h.shutdowns) != 0 {
		t.Fatalf("a half-sent request after a disconnect ran: %v", h.shutdowns)
	}
}

type failingWriter struct{ scriptedPort }

func (*failingWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

func TestServeSurvivesWriteErrors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &failingWriter{scriptedPort{cancel: cancel, reads: [][]byte{
		[]byte(`{"execute":"guest-ping"}`),
		[]byte(`{"execute":"guest-shutdown"}`),
	}}}
	h := newFakeHost()
	Serve(ctx, p, h, t.Logf, time.Millisecond)
	if len(h.shutdowns) != 1 {
		t.Fatalf("shutdowns = %v; a failed write must not stop later requests", h.shutdowns)
	}
}

func TestFindPortPrefersTheUdevLink(t *testing.T) {
	sys := fstest.MapFS{"vport1p1/name": {Data: []byte("org.qemu.guest_agent.0\n")}}
	got, err := findPort(func(p string) bool { return p == DevLink }, sys, "/dev")
	if err != nil || got != DevLink {
		t.Fatalf("findPort = %q, %v; want %s", got, err, DevLink)
	}
}

func TestFindPortFromSysfs(t *testing.T) {
	sys := fstest.MapFS{
		"vport0p0/name": {Data: []byte("org.qemu.console.0\n")},
		"vport1p2/name": {Data: []byte("org.qemu.guest_agent.0\n")},
		"vport1p3/name": {Data: []byte("\n")},
	}
	got, err := findPort(func(string) bool { return false }, sys, "/dev")
	if err != nil || got != "/dev/vport1p2" {
		t.Fatalf("findPort = %q, %v; want /dev/vport1p2", got, err)
	}
}

func TestFindPortNone(t *testing.T) {
	for _, sys := range []fstest.MapFS{
		{},
		{"vport0p1/name": {Data: []byte("com.example.other\n")}},
	} {
		if _, err := findPort(func(string) bool { return false }, sys, "/dev"); !errors.Is(err, ErrNoPort) {
			t.Fatalf("findPort err = %v, want ErrNoPort", err)
		}
	}
}
