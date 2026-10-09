package init

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
	"encoding/binary"
	"errors"
	"os"
	"slices"
	"syscall"
	"testing"
	"testing/fstest"
	"time"

	"github.com/CryptOS-PKI/cryptos-node/internal/reset"
)

// testShutdownRequests is newShutdownRequests with the teardown watchdog and
// the console announcement replaced: a real watchdog would reboot the test
// host after a minute, and a real announcement would write to the test
// host's actual console. armed, when non-nil, records every action the
// watchdog was armed for.
func testShutdownRequests(armed *[]ShutdownAction) *shutdownRequests {
	sd := newShutdownRequests()
	sd.watchdog = func(a ShutdownAction) {
		if armed != nil {
			*armed = append(*armed, a)
		}
	}
	sd.announce = func(ShutdownAction) {}

	return sd
}

// The watchdog is armed for the chosen action as soon as Wait returns, so a
// teardown that hangs still ends in the reboot or power-off asked for.
func TestShutdownRequests_WaitArmsTheWatchdog(t *testing.T) {
	var armed []ShutdownAction
	sd := testShutdownRequests(&armed)
	sd.Request(ShutdownPowerOff)

	sd.Wait(context.Background())
	if !slices.Equal(armed, []ShutdownAction{ShutdownPowerOff}) {
		t.Fatalf("watchdog armed for %v, want [%v]", armed, ShutdownPowerOff)
	}
}

// Nothing arms the watchdog until a shutdown has been chosen.
func TestShutdownRequests_RequestAloneDoesNotArmTheWatchdog(t *testing.T) {
	var armed []ShutdownAction
	sd := testShutdownRequests(&armed)
	sd.Request(ShutdownReboot)

	if len(armed) != 0 {
		t.Fatalf("watchdog armed before Wait: %v", armed)
	}
}

func TestShutdownRequests_FirstRequestWins(t *testing.T) {
	sd := testShutdownRequests(nil)
	sd.Request(ShutdownPowerOff)
	sd.Request(ShutdownReboot)

	if got := sd.Wait(context.Background()); got != ShutdownPowerOff {
		t.Fatalf("Wait = %v, want %v", got, ShutdownPowerOff)
	}
	if got := sd.Action(); got != ShutdownPowerOff {
		t.Errorf("Action = %v, want %v", got, ShutdownPowerOff)
	}
}

// A boot that fails before anything asked for a shutdown must still reboot:
// that is the fail-closed behaviour PID 1 has always had.
func TestShutdownRequests_DefaultsToReboot(t *testing.T) {
	if got := testShutdownRequests(nil).Action(); got != ShutdownReboot {
		t.Fatalf("Action = %v, want %v", got, ShutdownReboot)
	}
}

// Wait announces the chosen action to the console as soon as it is chosen,
// before arming the watchdog, so an admin watching the screen is told what
// is about to happen even if the teardown that follows hangs.
func TestShutdownRequests_WaitAnnouncesTheAction(t *testing.T) {
	sd := testShutdownRequests(nil)
	var announced []ShutdownAction
	sd.announce = func(a ShutdownAction) { announced = append(announced, a) }
	sd.Request(ShutdownPowerOff)

	sd.Wait(context.Background())
	if !slices.Equal(announced, []ShutdownAction{ShutdownPowerOff}) {
		t.Fatalf("announced = %v, want [%v]", announced, ShutdownPowerOff)
	}
}

// The console message names the action in the same words an admin sees
// elsewhere in the UI, not the log's terse "reboot"/"power-off".
func TestShutdownAction_ConsoleMessage(t *testing.T) {
	if got, want := ShutdownReboot.consoleMessage(), "Rebooting..."; got != want {
		t.Fatalf("ShutdownReboot.consoleMessage() = %q, want %q", got, want)
	}
	if got, want := ShutdownPowerOff.consoleMessage(), "Shutting down..."; got != want {
		t.Fatalf("ShutdownPowerOff.consoleMessage() = %q, want %q", got, want)
	}
}

func TestShutdownRequests_WaitReturnsWhenTheContextEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if got := testShutdownRequests(nil).Wait(ctx); got != ShutdownReboot {
		t.Fatalf("Wait = %v, want %v", got, ShutdownReboot)
	}
}

// rebooterFor builds a nodeRebooter whose scheduled request runs inline.
func rebooterFor(caCN string, got *[]ShutdownAction) nodeRebooter {
	return nodeRebooter{
		caCN:     func() string { return caCN },
		request:  func(a ShutdownAction) { *got = append(*got, a) },
		schedule: func(f func()) { f() },
	}
}

func TestNodeRebooter_RefusesAMismatchedOrEmptyConfirmation(t *testing.T) {
	cases := []struct{ name, caCN, confirm string }{
		{"wrong", testCACN, "Some Other CA"},
		{"empty confirmation", testCACN, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got []ShutdownAction
			err := rebooterFor(tc.caCN, &got).Reboot(context.Background(), tc.confirm, false)
			if !errors.Is(err, reset.ErrConfirmMismatch) {
				t.Fatalf("err = %v, want ErrConfirmMismatch", err)
			}
			if len(got) != 0 {
				t.Errorf("a refused confirmation still asked for a shutdown: %v", got)
			}
		})
	}
}

func TestNodeRebooter_RefusesWithNoCAIdentity(t *testing.T) {
	for _, confirm := range []string{"", testCACN} {
		var got []ShutdownAction
		err := rebooterFor("", &got).Reboot(context.Background(), confirm, false)
		if !errors.Is(err, reset.ErrNoCAIdentity) {
			t.Fatalf("confirm %q: err = %v, want ErrNoCAIdentity", confirm, err)
		}
		if len(got) != 0 {
			t.Errorf("a node with no CA identity still asked for a shutdown: %v", got)
		}
	}
}

func TestNodeRebooter_RequestsTheOrderlyShutdown(t *testing.T) {
	for _, tc := range []struct {
		powerOff bool
		want     ShutdownAction
	}{{false, ShutdownReboot}, {true, ShutdownPowerOff}} {
		var got []ShutdownAction
		if err := rebooterFor(testCACN, &got).Reboot(context.Background(), testCACN, tc.powerOff); err != nil {
			t.Fatalf("Reboot: %v", err)
		}
		if !slices.Equal(got, []ShutdownAction{tc.want}) {
			t.Errorf("powerOff=%t: requested %v, want [%v]", tc.powerOff, got, tc.want)
		}
	}
}

// The CA CN is read per call: a node whose identity is committed after boot
// (the ceremony, or a subordinate's certificate install) must accept the
// confirmation without first needing the reboot it is asking for.
func TestNodeRebooter_ReadsTheCACNPerCall(t *testing.T) {
	cn := ""
	var got []ShutdownAction
	rb := nodeRebooter{
		caCN:     func() string { return cn },
		request:  func(a ShutdownAction) { got = append(got, a) },
		schedule: func(f func()) { f() },
	}
	if err := rb.Reboot(context.Background(), testCACN, false); !errors.Is(err, reset.ErrNoCAIdentity) {
		t.Fatalf("before the identity exists: err = %v, want ErrNoCAIdentity", err)
	}
	cn = testCACN
	if err := rb.Reboot(context.Background(), testCACN, false); err != nil {
		t.Fatalf("after the identity is committed: %v", err)
	}
	if !slices.Equal(got, []ShutdownAction{ShutdownReboot}) {
		t.Errorf("requested %v, want [%v]", got, ShutdownReboot)
	}
}

// The RPC reply has to leave the node before the listeners stop, so the
// request is deferred rather than made on the handler goroutine.
func TestNodeRebooter_DefersTheRequest(t *testing.T) {
	var got []ShutdownAction
	var scheduled func()
	rb := nodeRebooter{
		caCN:     func() string { return testCACN },
		request:  func(a ShutdownAction) { got = append(got, a) },
		schedule: func(f func()) { scheduled = f },
	}
	if err := rb.Reboot(context.Background(), testCACN, false); err != nil {
		t.Fatalf("Reboot: %v", err)
	}
	if len(got) != 0 {
		t.Fatal("the shutdown fired before the reply could be sent")
	}
	scheduled()
	if !slices.Equal(got, []ShutdownAction{ShutdownReboot}) {
		t.Errorf("requested %v, want [%v]", got, ShutdownReboot)
	}
}

func TestSignalAction(t *testing.T) {
	for _, tc := range []struct {
		sig  os.Signal
		want ShutdownAction
		ok   bool
	}{
		{syscall.SIGTERM, ShutdownReboot, true},
		// The kernel sends SIGINT to PID 1 for Ctrl-Alt-Del once it is told
		// not to restart on its own.
		{syscall.SIGINT, ShutdownReboot, true},
		{syscall.SIGHUP, ShutdownReboot, false},
	} {
		got, ok := signalAction(tc.sig)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Errorf("signalAction(%v) = %v, %t; want %v, %t", tc.sig, got, ok, tc.want, tc.ok)
		}
	}
}

func TestSignalSource_RequestsOnAShutdownSignal(t *testing.T) {
	sigs := make(chan os.Signal, 2)
	sigs <- syscall.SIGHUP
	sigs <- syscall.SIGINT
	sd := testShutdownRequests(nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go signalSource{signals: sigs}.Watch(ctx, sd.Request)

	if got := sd.Wait(ctx); got != ShutdownReboot || ctx.Err() != nil {
		t.Fatalf("Wait = %v (ctx err %v), want %v", got, ctx.Err(), ShutdownReboot)
	}
}

// inputEvent encodes one struct input_event the way a 64-bit kernel writes it.
func inputEvent(typ, code uint16, value int32) []byte {
	b := make([]byte, inputEventSize)
	binary.LittleEndian.PutUint16(b[16:], typ)
	binary.LittleEndian.PutUint16(b[18:], code)
	binary.LittleEndian.PutUint32(b[20:], uint32(value))

	return b
}

func TestReadPowerButton_PowersOffOnAPress(t *testing.T) {
	var stream bytes.Buffer
	stream.Write(inputEvent(evKey, keyPower, 1)) // press
	stream.Write(inputEvent(evSyn, 0, 0))
	stream.Write(inputEvent(evKey, keyPower, 0)) // release

	var got []ShutdownAction
	err := readPowerButton(&stream, func(a ShutdownAction) { got = append(got, a) })
	if err == nil {
		t.Fatal("readPowerButton returned nil at the end of the stream")
	}
	if !slices.Equal(got, []ShutdownAction{ShutdownPowerOff}) {
		t.Errorf("requested %v, want one power-off for one press", got)
	}
}

func TestReadPowerButton_IgnoresOtherKeys(t *testing.T) {
	var stream bytes.Buffer
	stream.Write(inputEvent(evKey, 142, 1)) // KEY_SLEEP
	stream.Write(inputEvent(evSyn, keyPower, 1))

	var got []ShutdownAction
	_ = readPowerButton(&stream, func(a ShutdownAction) { got = append(got, a) })
	if len(got) != 0 {
		t.Errorf("requested %v for events that are not a power-button press", got)
	}
}

func TestPowerButtonDevices_FindsTheACPIPowerButtons(t *testing.T) {
	sys := fstest.MapFS{
		"event0/device/name": {Data: []byte("Power Button\n")},
		"event1/device/name": {Data: []byte("AT Translated Set 2 keyboard\n")},
		"event2/device/name": {Data: []byte("Power Button\n")},
		"event3/device/name": {Data: []byte("Sleep Button\n")},
		"input0/name":        {Data: []byte("Power Button\n")},
		"mice":               {Data: []byte{}},
	}

	got := powerButtonDevices(sys)
	want := []string{"/dev/input/event0", "/dev/input/event2"}
	if !slices.Equal(got, want) {
		t.Fatalf("powerButtonDevices = %v, want %v", got, want)
	}
}

type fakeVolume struct {
	closed bool
	err    error
}

func (v *fakeVolume) Close(context.Context) error {
	v.closed = true

	return v.err
}

func TestCloseStateVolume_UnmountsThenLocks(t *testing.T) {
	var unmounted string
	vol := &fakeVolume{}

	err := closeStateVolume(context.Background(), "/var/lib/cryptos", func(p string) error {
		unmounted = p

		return nil
	}, vol)
	if err != nil {
		t.Fatalf("closeStateVolume: %v", err)
	}
	if unmounted != "/var/lib/cryptos" || !vol.closed {
		t.Errorf("unmounted=%q closed=%t", unmounted, vol.closed)
	}
}

// Locking a volume whose filesystem is still mounted would fail anyway, and
// trying is noise in the only log an operator has.
func TestCloseStateVolume_LeavesTheVolumeOpenIfUnmountFails(t *testing.T) {
	vol := &fakeVolume{}

	err := closeStateVolume(context.Background(), "/var/lib/cryptos", func(string) error {
		return errors.New("device or resource busy")
	}, vol)
	if err == nil {
		t.Fatal("closeStateVolume reported success on a failed unmount")
	}
	if vol.closed {
		t.Error("the volume was closed under a mounted filesystem")
	}
}
