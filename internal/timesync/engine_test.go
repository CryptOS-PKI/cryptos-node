package timesync

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
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
)

// fakeClock is the node clock under test: it starts at base, advances with
// real elapsed time, and records every adjustment instead of making it.
type fakeClock struct {
	mu      sync.Mutex
	base    time.Time
	start   time.Time
	steps   []time.Duration
	slews   []time.Duration
	synced  int
	failAll error
}

func newFakeClock(base time.Time) *fakeClock {
	return &fakeClock{base: base, start: time.Now()}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.base.Add(time.Since(c.start))
}

func (c *fakeClock) Step(d time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failAll != nil {
		return c.failAll
	}
	c.steps = append(c.steps, d)
	c.base = c.base.Add(d)
	return nil
}

func (c *fakeClock) Slew(d time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failAll != nil {
		return c.failAll
	}
	c.slews = append(c.slews, d)
	return nil
}

func (c *fakeClock) MarkSynced(time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.synced++
	return nil
}

func (c *fakeClock) adjustments() (steps, slews []time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Duration(nil), c.steps...), append([]time.Duration(nil), c.slews...)
}

// fakeServer is an SNTP server on loopback. Its time is the fake clock plus
// offset, so the offset the client measures is known.
type fakeServer struct {
	conn     *net.UDPConn
	clock    *fakeClock
	requests atomic.Int32

	mu      sync.Mutex
	offset  time.Duration
	stratum uint8
	leap    uint8
	kiss    string
	drop    bool
}

func newFakeServer(t *testing.T, clock *fakeClock, offset time.Duration) *fakeServer {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &fakeServer{conn: conn, clock: clock, offset: offset, stratum: 2}
	t.Cleanup(func() { _ = conn.Close() })
	go s.serve()
	return s
}

func (s *fakeServer) set(fn func(*fakeServer)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(s)
}

func (s *fakeServer) serve() {
	buf := make([]byte, 512)
	for {
		n, from, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		s.requests.Add(1)
		req, err := ParseHeader(buf[:n])
		if err != nil {
			continue
		}
		s.mu.Lock()
		drop, off, stratum, leap, kiss := s.drop, s.offset, s.stratum, s.leap, s.kiss
		s.mu.Unlock()
		if drop {
			continue
		}
		now := TimestampFromTime(s.clock.Now().Add(off))
		reply := Header{
			Leap: leap, Version: 4, Mode: ModeServer, Stratum: stratum,
			RootDelay: 0x00000100, RootDispersion: 0x00000100,
			Origin: req.Transmit, Receive: now, Transmit: now,
		}
		if kiss != "" {
			reply.Stratum = 0
			reply.Leap = 3
			copy(reply.ReferenceID[:], kiss)
		}
		_, _ = s.conn.WriteToUDP(reply.Marshal(), from)
	}
}

func (s *fakeServer) addr() netip.AddrPort {
	return s.conn.LocalAddr().(*net.UDPAddr).AddrPort()
}

// harness wires an Engine to fake servers. Each server is reached under a
// documentation address (192.0.2.0/24), which Dial maps to the loopback port.
type harness struct {
	t       *testing.T
	clock   *fakeClock
	floor   *Floor
	servers map[netip.Addr]*fakeServer
	names   map[string]netip.Addr
	logs    *bytes.Buffer
	cfg     Config
}

var testNow = time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)

func newHarness(t *testing.T) *harness {
	t.Helper()
	floor, err := OpenFloor(filepath.Join(t.TempDir(), "clock-floor"), testNow.Add(-30*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{
		t: t, clock: newFakeClock(testNow), floor: floor,
		servers: map[netip.Addr]*fakeServer{}, names: map[string]netip.Addr{},
		logs: &bytes.Buffer{},
	}
	h.cfg = Config{
		Source:       nodev1.TimeSource_TIME_SOURCE_MACHINE_CONFIG,
		Clock:        h.clock,
		Floor:        floor,
		Logger:       slog.New(slog.NewTextHandler(&syncWriter{b: h.logs}, &slog.HandlerOptions{Level: LevelTrace})),
		QueryTimeout: 200 * time.Millisecond,
		RetryGap:     20 * time.Millisecond,
		BootBudget:   2 * time.Second,
		Resolve: func(_ context.Context, host string) ([]netip.Addr, error) {
			if a, ok := h.names[host]; ok {
				return []netip.Addr{a}, nil
			}
			return nil, errors.New("no such host")
		},
		Dial: func(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
			s, ok := h.servers[addr.Addr()]
			if !ok || addr.Port() != Port {
				return nil, errors.New("unexpected dial to " + addr.String())
			}
			var d net.Dialer
			return d.DialContext(ctx, "udp4", s.addr().String())
		},
	}
	return h
}

// add registers a fake server as name (a literal in 192.0.2.0/24 or a
// hostname) and returns it.
func (h *harness) add(name string, offset time.Duration) *fakeServer {
	s := newFakeServer(h.t, h.clock, offset)
	a, err := netip.ParseAddr(name)
	if err != nil {
		a = netip.AddrFrom4([4]byte{192, 0, 2, byte(100 + len(h.names))})
		h.names[name] = a
	}
	h.servers[a] = s
	h.cfg.Servers = append(h.cfg.Servers, name)
	return s
}

func (h *harness) engine() *Engine {
	h.t.Helper()
	e, err := New(h.cfg)
	if err != nil {
		h.t.Fatalf("New: %v", err)
	}
	return e
}

type syncWriter struct {
	mu sync.Mutex
	b  *bytes.Buffer
}

func (w *syncWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

func approx(got, want time.Duration) bool {
	d := got - want
	return d > -50*time.Millisecond && d < 50*time.Millisecond
}

func TestBootSyncStepsALargeOffset(t *testing.T) {
	h := newHarness(t)
	h.add("192.0.2.1", 5*time.Second)
	e := h.engine()
	if e.SignAllowed() {
		t.Fatal("SignAllowed before the first sync with a configured source")
	}
	if got := e.Status().GetState(); got != nodev1.TimeSyncState_TIME_SYNC_STATE_PENDING {
		t.Fatalf("state before sync = %v, want PENDING", got)
	}
	e.BootSync(context.Background())

	steps, slews := h.clock.adjustments()
	if len(steps) != 1 || !approx(steps[0], 5*time.Second) || len(slews) != 0 {
		t.Fatalf("steps = %v, slews = %v; want one step of about 5s", steps, slews)
	}
	st := e.Status()
	if st.GetState() != nodev1.TimeSyncState_TIME_SYNC_STATE_SYNCED || !st.GetSteppedAtBoot() {
		t.Fatalf("status = %v", st)
	}
	if st.GetLastServer() != "192.0.2.1" || st.GetStratum() != 2 || st.GetLastSync() == nil {
		t.Fatalf("status = %v", st)
	}
	if !approx(st.GetLastOffset().AsDuration(), 5*time.Second) {
		t.Fatalf("last offset = %v", st.GetLastOffset().AsDuration())
	}
	if !e.SignAllowed() {
		t.Fatal("SignAllowed = false after a good sync")
	}
	if h.clock.synced != 1 {
		t.Fatalf("MarkSynced called %d times, want 1", h.clock.synced)
	}
	if !h.floor.Get().After(testNow.Add(4 * time.Second)) {
		t.Fatalf("floor = %v, want it advanced to the synced time", h.floor.Get())
	}
	if !strings.Contains(h.logs.String(), "stepped") {
		t.Fatalf("no info log for the boot step:\n%s", h.logs)
	}
}

func TestBootSyncSlewsASmallOffset(t *testing.T) {
	h := newHarness(t)
	h.add("192.0.2.1", 60*time.Millisecond)
	e := h.engine()
	e.BootSync(context.Background())
	steps, slews := h.clock.adjustments()
	if len(steps) != 0 || len(slews) != 1 {
		t.Fatalf("steps = %v, slews = %v; want one slew", steps, slews)
	}
	if e.Status().GetSteppedAtBoot() {
		t.Fatal("stepped_at_boot set for a slew")
	}
}

// A node with no time source runs on its hardware clock and is never gated.
func TestNoSourceIsNotConfiguredAndNeverGated(t *testing.T) {
	h := newHarness(t)
	h.cfg.Source = nodev1.TimeSource_TIME_SOURCE_NONE
	e := h.engine()
	e.BootSync(context.Background())
	st := e.Status()
	if st.GetState() != nodev1.TimeSyncState_TIME_SYNC_STATE_NOT_CONFIGURED || st.GetSource() != nodev1.TimeSource_TIME_SOURCE_NONE {
		t.Fatalf("status = %v", st)
	}
	if !e.SignAllowed() {
		t.Fatal("SignAllowed = false with no time source")
	}
}

func TestBootSyncUnreachableServerIsBoundedAndGated(t *testing.T) {
	h := newHarness(t)
	s := h.add("192.0.2.1", 0)
	s.set(func(s *fakeServer) { s.drop = true })
	h.cfg.BootBudget = 500 * time.Millisecond
	e := h.engine()
	start := time.Now()
	e.BootSync(context.Background())
	if el := time.Since(start); el > time.Second {
		t.Fatalf("BootSync took %v, want it bounded by the boot budget", el)
	}
	if got := s.requests.Load(); got < 2 || got > 4 {
		t.Fatalf("server saw %d requests, want the first try plus retries, at most 4", got)
	}
	st := e.Status()
	if st.GetState() != nodev1.TimeSyncState_TIME_SYNC_STATE_UNSYNCED || st.GetLastError() == "" {
		t.Fatalf("status = %v", st)
	}
	if e.SignAllowed() {
		t.Fatal("SignAllowed with a configured source that never synced")
	}
}

func TestDisagreeingSourcesAreNotApplied(t *testing.T) {
	h := newHarness(t)
	h.add("192.0.2.1", 0)
	h.add("192.0.2.2", 5*time.Second)
	e := h.engine()
	e.BootSync(context.Background())
	steps, slews := h.clock.adjustments()
	if len(steps)+len(slews) != 0 {
		t.Fatalf("clock adjusted (steps %v, slews %v) although the sources disagree", steps, slews)
	}
	st := e.Status()
	if st.GetState() != nodev1.TimeSyncState_TIME_SYNC_STATE_UNSYNCED || !strings.Contains(st.GetLastError(), "disagree") {
		t.Fatalf("status = %v", st)
	}
	if !strings.Contains(h.logs.String(), "level=WARN") {
		t.Fatalf("no warn log for the disagreement:\n%s", h.logs)
	}
}

func TestMedianOfThreeIsApplied(t *testing.T) {
	h := newHarness(t)
	h.add("192.0.2.1", 2300*time.Millisecond)
	h.add("192.0.2.2", 2000*time.Millisecond)
	h.add("192.0.2.3", 2100*time.Millisecond)
	e := h.engine()
	e.BootSync(context.Background())
	steps, _ := h.clock.adjustments()
	if len(steps) != 1 || !approx(steps[0], 2100*time.Millisecond) {
		t.Fatalf("steps = %v, want the median 2.1s", steps)
	}
	if got := e.Status().GetLastServer(); got != "192.0.2.3" {
		t.Fatalf("last server = %q, want the median's server", got)
	}
}

// A server's time behind the floor (a notBefore already issued) is never
// applied.
func TestTimeBehindTheFloorIsRefused(t *testing.T) {
	h := newHarness(t)
	if err := h.floor.Advance(testNow.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	h.add("192.0.2.1", 10*time.Second)
	e := h.engine()
	e.BootSync(context.Background())
	steps, slews := h.clock.adjustments()
	if len(steps)+len(slews) != 0 {
		t.Fatalf("clock adjusted behind the floor: steps %v, slews %v", steps, slews)
	}
	st := e.Status()
	if st.GetState() != nodev1.TimeSyncState_TIME_SYNC_STATE_UNSYNCED || !strings.Contains(st.GetLastError(), "behind") {
		t.Fatalf("status = %v", st)
	}
	if e.SignAllowed() {
		t.Fatal("SignAllowed after the only sync was refused")
	}
	if !strings.Contains(h.logs.String(), "level=ERROR") {
		t.Fatalf("no error log for the floor violation:\n%s", h.logs)
	}
}

func TestPeriodicSyncSlewsStepsForwardAndRefusesBackwards(t *testing.T) {
	h := newHarness(t)
	s := h.add("192.0.2.1", 10*time.Millisecond)
	e := h.engine()
	e.BootSync(context.Background())
	if !e.SignAllowed() {
		t.Fatal("boot sync failed")
	}

	s.set(func(s *fakeServer) { s.offset = 40 * time.Millisecond })
	e.sync(context.Background(), true)
	_, slews := h.clock.adjustments()
	if len(slews) != 2 {
		t.Fatalf("slews = %v, want a second slew", slews)
	}

	s.set(func(s *fakeServer) { s.offset = 2 * time.Second })
	e.sync(context.Background(), true)
	steps, _ := h.clock.adjustments()
	if len(steps) != 1 || !approx(steps[0], 2*time.Second) {
		t.Fatalf("steps = %v, want one forward step of 2s", steps)
	}

	s.set(func(s *fakeServer) { s.offset = -2 * time.Second })
	e.sync(context.Background(), true)
	steps, _ = h.clock.adjustments()
	if len(steps) != 1 {
		t.Fatalf("steps = %v, want the backwards step refused", steps)
	}
	st := e.Status()
	if st.GetState() != nodev1.TimeSyncState_TIME_SYNC_STATE_UNSYNCED || !strings.Contains(st.GetLastError(), "backwards") {
		t.Fatalf("status = %v", st)
	}
	// The gate is "never synced this boot": a later refusal does not stop
	// signing on a clock that was already corrected.
	if !e.SignAllowed() {
		t.Fatal("SignAllowed = false after a later round failed")
	}
}

func TestKissDenyStopsQueryingThatServer(t *testing.T) {
	for _, code := range []string{KissDeny, KissRstr} {
		t.Run(code, func(t *testing.T) {
			h := newHarness(t)
			s := h.add("192.0.2.1", 0)
			s.set(func(s *fakeServer) { s.kiss = code })
			e := h.engine()
			e.BootSync(context.Background())
			if got := s.requests.Load(); got != 1 {
				t.Fatalf("server saw %d requests at boot, want 1 (no retry after %s)", got, code)
			}
			e.sync(context.Background(), true)
			if got := s.requests.Load(); got != 1 {
				t.Fatalf("server saw %d requests, want none after %s", got, code)
			}
			if !strings.Contains(e.Status().GetLastError(), code) {
				t.Fatalf("last error = %q, want it to name %s", e.Status().GetLastError(), code)
			}
		})
	}
}

func TestKissRateDoublesThePollInterval(t *testing.T) {
	h := newHarness(t)
	s := h.add("192.0.2.1", 0)
	e := h.engine()
	e.BootSync(context.Background())
	if got := e.interval("192.0.2.1"); got != MinPoll {
		t.Fatalf("interval after a good sync = %v, want %v", got, MinPoll)
	}
	s.set(func(s *fakeServer) { s.kiss = KissRate })
	e.sync(context.Background(), true)
	if got := e.interval("192.0.2.1"); got != 2*MinPoll {
		t.Fatalf("interval after RATE = %v, want %v", got, 2*MinPoll)
	}
}

func TestUnreachableServerBacksOffToMaxPoll(t *testing.T) {
	h := newHarness(t)
	s := h.add("192.0.2.1", 0)
	s.set(func(s *fakeServer) { s.drop = true })
	h.cfg.BootBudget = 100 * time.Millisecond
	h.cfg.QueryTimeout = 20 * time.Millisecond
	e := h.engine()
	e.BootSync(context.Background())
	var seen []time.Duration
	for range 8 {
		e.sync(context.Background(), true)
		seen = append(seen, e.interval("192.0.2.1"))
	}
	for i, d := range seen {
		if d < PollFloor {
			t.Fatalf("interval %d = %v, below the RFC 4330 floor of %v", i, d, PollFloor)
		}
		if d > MaxPoll {
			t.Fatalf("interval %d = %v, above MaxPoll", i, d)
		}
	}
	if seen[len(seen)-1] != MaxPoll {
		t.Fatalf("intervals = %v, want the back-off to reach %v", seen, MaxPoll)
	}
}

// Only servers whose poll interval has elapsed are queried in a round.
func TestPeriodicSyncHonoursThePollInterval(t *testing.T) {
	h := newHarness(t)
	s := h.add("192.0.2.1", 0)
	e := h.engine()
	e.BootSync(context.Background())
	before := s.requests.Load()
	e.sync(context.Background(), false)
	if got := s.requests.Load(); got != before {
		t.Fatalf("server queried again %d times before its poll interval elapsed", got-before)
	}
}

func TestHostnameServerIsResolvedAndReportedByName(t *testing.T) {
	h := newHarness(t)
	h.add("time.example.org", 3*time.Second)
	e := h.engine()
	e.BootSync(context.Background())
	st := e.Status()
	if st.GetState() != nodev1.TimeSyncState_TIME_SYNC_STATE_SYNCED || st.GetLastServer() != "time.example.org" {
		t.Fatalf("status = %v", st)
	}
}

func TestUnresolvableHostnameIsReported(t *testing.T) {
	h := newHarness(t)
	h.cfg.Servers = []string{"missing.example.org"}
	e := h.engine()
	e.BootSync(context.Background())
	st := e.Status()
	if st.GetState() != nodev1.TimeSyncState_TIME_SYNC_STATE_UNSYNCED || !strings.Contains(st.GetLastError(), "missing.example.org") {
		t.Fatalf("status = %v", st)
	}
}

func TestClockSyscallFailureIsReported(t *testing.T) {
	h := newHarness(t)
	h.add("192.0.2.1", 5*time.Second)
	h.clock.failAll = errors.New("operation not permitted")
	e := h.engine()
	e.BootSync(context.Background())
	st := e.Status()
	if st.GetState() != nodev1.TimeSyncState_TIME_SYNC_STATE_UNSYNCED || !strings.Contains(st.GetLastError(), "not permitted") {
		t.Fatalf("status = %v", st)
	}
	if e.SignAllowed() {
		t.Fatal("SignAllowed although the clock could not be set")
	}
}

// A reply from the wrong peer never reaches the client: the socket is
// connected, so the kernel drops it, and the query times out.
func TestReplyFromAnotherAddressIsIgnored(t *testing.T) {
	h := newHarness(t)
	target, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = target.Close() }()
	spoof, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = spoof.Close() }()
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := target.ReadFromUDP(buf)
			if err != nil {
				return
			}
			req, err := ParseHeader(buf[:n])
			if err != nil {
				continue
			}
			now := TimestampFromTime(h.clock.Now().Add(time.Hour))
			reply := Header{Version: 4, Mode: ModeServer, Stratum: 1, Origin: req.Transmit, Receive: now, Transmit: now}
			_, _ = spoof.WriteToUDP(reply.Marshal(), from)
		}
	}()
	h.cfg.Servers = []string{"192.0.2.1"}
	h.cfg.BootBudget = 300 * time.Millisecond
	h.cfg.Dial = func(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "udp4", target.LocalAddr().String())
	}
	e := h.engine()
	e.BootSync(context.Background())
	if steps, _ := h.clock.adjustments(); len(steps) != 0 {
		t.Fatalf("clock stepped by a spoofed reply: %v", steps)
	}
	if e.SignAllowed() {
		t.Fatal("SignAllowed after only a spoofed reply")
	}
}

func TestNewRejectsTooManyServers(t *testing.T) {
	h := newHarness(t)
	h.cfg.Servers = []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"}
	if _, err := New(h.cfg); err == nil {
		t.Fatal("New accepted four servers")
	}
}

func TestRunStopsWithTheContext(t *testing.T) {
	h := newHarness(t)
	h.add("192.0.2.1", 0)
	e := h.engine()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.Run(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after the context was cancelled")
	}
}

func TestNoteIssuedRaisesTheFloor(t *testing.T) {
	h := newHarness(t)
	e := h.engine()
	nb := testNow.Add(2 * time.Hour)
	e.NoteIssued(nb)
	if got := h.floor.Get(); !got.Equal(nb) {
		t.Fatalf("floor = %v, want the issued notBefore %v", got, nb)
	}
}

// At shutdown the floor records the clock only if it was synced this boot; an
// unsynced clock may be fast, and baking it into the floor would block the
// correction on the next boot.
func TestShutdownRecordsOnlyASyncedClock(t *testing.T) {
	h := newHarness(t)
	s := h.add("192.0.2.1", 0)
	s.set(func(s *fakeServer) { s.drop = true })
	h.cfg.BootBudget = 100 * time.Millisecond
	e := h.engine()
	e.BootSync(context.Background())
	before := h.floor.Get()
	e.Shutdown()
	if !h.floor.Get().Equal(before) {
		t.Fatal("Shutdown advanced the floor on an unsynced clock")
	}

	s.set(func(s *fakeServer) { s.drop = false })
	e.sync(context.Background(), true)
	if !e.SignAllowed() {
		t.Fatal("sync failed")
	}
	mark := h.floor.Get()
	time.Sleep(5 * time.Millisecond)
	e.Shutdown()
	if !h.floor.Get().After(mark) {
		t.Fatal("Shutdown did not advance the floor on a synced clock")
	}
}

func TestStatusListsServersAndSource(t *testing.T) {
	h := newHarness(t)
	h.add("192.0.2.1", 0)
	h.add("time.example.org", 0)
	h.cfg.Source = nodev1.TimeSource_TIME_SOURCE_DHCP_LEASE
	e := h.engine()
	st := e.Status()
	if st.GetSource() != nodev1.TimeSource_TIME_SOURCE_DHCP_LEASE || strings.Join(st.GetServers(), ",") != "192.0.2.1,time.example.org" {
		t.Fatalf("status = %v", st)
	}
}

// A slew only slows the clock, so it never reorders issued times: a small
// negative offset measured just after an issuance is slewed, not refused by
// the floor.
func TestSmallNegativeSlewIsNotBlockedByTheFloor(t *testing.T) {
	h := newHarness(t)
	s := h.add("192.0.2.1", 0)
	e := h.engine()
	e.BootSync(context.Background())
	e.NoteIssued(h.clock.Now())
	s.set(func(s *fakeServer) { s.offset = -80 * time.Millisecond })
	e.sync(context.Background(), true)
	_, slews := h.clock.adjustments()
	if len(slews) != 2 || !approx(slews[1], -80*time.Millisecond) {
		t.Fatalf("slews = %v, want a second slew of about -80ms", slews)
	}
	if st := e.Status(); st.GetState() != nodev1.TimeSyncState_TIME_SYNC_STATE_SYNCED {
		t.Fatalf("status = %v", st)
	}
}

func TestAdjustmentRefusedHoldsUntilTheNextGoodSync(t *testing.T) {
	h := newHarness(t)
	s := h.add("192.0.2.1", 10*time.Millisecond)
	h.cfg.QueryTimeout = 20 * time.Millisecond
	e := h.engine()
	e.BootSync(context.Background())
	if e.Status().GetAdjustmentRefused() {
		t.Fatal("adjustment_refused after a good boot sync")
	}

	s.set(func(s *fakeServer) { s.drop = true })
	e.sync(context.Background(), true)
	if st := e.Status(); st.GetState() != nodev1.TimeSyncState_TIME_SYNC_STATE_UNSYNCED || st.GetAdjustmentRefused() {
		t.Fatalf("after an unanswered poll: status = %v, want UNSYNCED without adjustment_refused", st)
	}

	s.set(func(s *fakeServer) { s.drop = false; s.offset = -2 * time.Second })
	e.sync(context.Background(), true)
	if !e.Status().GetAdjustmentRefused() {
		t.Fatalf("status = %v, want adjustment_refused after a refused backwards step", e.Status())
	}

	s.set(func(s *fakeServer) { s.drop = true })
	e.sync(context.Background(), true)
	if !e.Status().GetAdjustmentRefused() {
		t.Fatal("an unanswered poll cleared adjustment_refused")
	}

	s.set(func(s *fakeServer) { s.drop = false; s.offset = 20 * time.Millisecond })
	e.sync(context.Background(), true)
	if st := e.Status(); st.GetState() != nodev1.TimeSyncState_TIME_SYNC_STATE_SYNCED || st.GetAdjustmentRefused() {
		t.Fatalf("after a good sync: status = %v, want SYNCED without adjustment_refused", st)
	}
}

func TestDisagreeingSourcesSetAdjustmentRefused(t *testing.T) {
	h := newHarness(t)
	h.add("192.0.2.1", 0)
	h.add("192.0.2.2", 5*time.Second)
	e := h.engine()
	e.BootSync(context.Background())
	if !e.Status().GetAdjustmentRefused() {
		t.Fatalf("status = %v, want adjustment_refused", e.Status())
	}
}
