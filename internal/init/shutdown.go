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

// Orderly shutdown of a running node (#231).
//
// A running node stops for one of three reasons: an admin calls the Reboot
// RPC, PID 1 receives SIGTERM or SIGINT (the kernel delivers SIGINT for
// Ctrl-Alt-Del once it is told not to restart on its own), or the platform
// presses the ACPI power button (a hypervisor's guest shutdown request on a
// guest without tools). Every one of them lands in shutdownRequests, so they
// all take the same path: Boot returns, its deferred teardown stops the
// listeners, closes the audit log and etcd, unmounts and locks the state
// volume, and only then does PID 1 ask the kernel to restart or power off.
// A hypervisor hard reset skips all of that.

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/CryptOS-PKI/cryptos-node/internal/buildinfo"
	"github.com/CryptOS-PKI/cryptos-node/internal/console"
	"github.com/CryptOS-PKI/cryptos-node/internal/reset"
)

// ShutdownAction is what PID 1 asks the kernel for once Boot has returned.
type ShutdownAction int

const (
	// ShutdownReboot restarts the node. It is the zero value, so a boot that
	// fails before anything asked for a shutdown still reboots (fail-closed).
	ShutdownReboot ShutdownAction = iota
	// ShutdownPowerOff halts the node and powers it off.
	ShutdownPowerOff
)

// String names the action for the log.
func (a ShutdownAction) String() string {
	if a == ShutdownPowerOff {
		return "power-off"
	}

	return "reboot"
}

// consoleMessage is the branded line shown on the console while the action
// runs, matching the boot banner's style.
func (a ShutdownAction) consoleMessage() string {
	if a == ShutdownPowerOff {
		return "Shutting down..."
	}

	return "Rebooting..."
}

// rebootRPCDelay lets the RebootResponse flush before the listeners stop,
// the same grace the reset and image-activate paths give their replies.
const rebootRPCDelay = 2 * time.Second

// shutdownTeardownTimeout bounds the orderly teardown. Once a shutdown is
// chosen the watchdog is armed; if Boot's deferred teardown (listeners, audit
// log, etcd, unmount, LUKS close) and PID 1's own sync have not handed the
// node to the kernel by then, the watchdog restarts or powers it off directly.
// A remote CA with no console must never sit half shut down.
const shutdownTeardownTimeout = 60 * time.Second

// shutdownRequests collects shutdown requests from every source. The first
// request wins; later ones are dropped because the node is already going
// down.
type shutdownRequests struct {
	ch chan ShutdownAction

	// watchdog arms the teardown watchdog for the chosen action.
	watchdog func(ShutdownAction)

	// announce tells the console the chosen action, so the screen says what
	// is happening instead of freezing on its last frame.
	announce func(ShutdownAction)

	mu     sync.Mutex
	chosen ShutdownAction
}

func newShutdownRequests() *shutdownRequests {
	return &shutdownRequests{
		ch: make(chan ShutdownAction, 1),
		watchdog: func(a ShutdownAction) {
			time.AfterFunc(shutdownTeardownTimeout, func() {
				log.Printf("shutdown: teardown still running after %s; forcing %s", shutdownTeardownTimeout, a)
				forceHalt(a)
			})
		},
		announce: announceShutdown,
	}
}

// announceShutdown writes a branded status line to the console saying the
// node is rebooting or shutting down. Best-effort: a console that cannot be
// opened (a dev host, or one that is already gone) does not block shutdown.
func announceShutdown(a ShutdownAction) {
	cons, err := openConsole()
	if err != nil {
		return
	}
	if c, ok := cons.(io.Closer); ok {
		defer func() { _ = c.Close() }()
	}
	_ = console.NewRenderer(cons).Shutdown(buildinfo.Get().Version, a.consoleMessage())
}

// Request asks for a shutdown. It never blocks.
func (r *shutdownRequests) Request(a ShutdownAction) {
	select {
	case r.ch <- a:
	default:
	}
}

// Wait blocks until a shutdown is requested or ctx ends, records the outcome
// for Action, and arms the teardown watchdog before returning, so the
// teardown that follows cannot hang the node. An ended context counts as a
// reboot.
func (r *shutdownRequests) Wait(ctx context.Context) ShutdownAction {
	a := ShutdownReboot
	select {
	case a = <-r.ch:
	case <-ctx.Done():
	}
	r.mu.Lock()
	r.chosen = a
	r.mu.Unlock()
	if r.announce != nil {
		r.announce(a)
	}
	if r.watchdog != nil {
		r.watchdog(a)
	}

	return a
}

// Action is the action Wait returned, or ShutdownReboot if Wait never ran.
func (r *shutdownRequests) Action() ShutdownAction {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.chosen
}

// nodeRebooter implements grpc.Rebooter over shutdownRequests.
type nodeRebooter struct {
	// caCN returns the node's current CA CN, or "" before one exists.
	caCN     func() string
	request  func(ShutdownAction)
	schedule func(func())
}

// newNodeRebooter wires a rebooter whose request fires after rebootRPCDelay,
// off the RPC goroutine, so the reply reaches the caller first.
func newNodeRebooter(caCN func() string, sd *shutdownRequests) nodeRebooter {
	return nodeRebooter{
		caCN:     caCN,
		request:  sd.Request,
		schedule: func(f func()) { time.AfterFunc(rebootRPCDelay, f) },
	}
}

// Reboot implements grpc.Rebooter. The confirmation is checked with
// reset.CheckConfirm, as the resetter and the image upgrader check theirs:
// fail closed on an empty CA CN (reset.ErrNoCAIdentity) or an empty or
// different confirmation (reset.ErrConfirmMismatch), with a constant-time
// compare.
func (r nodeRebooter) Reboot(_ context.Context, confirmCommonName string, powerOff bool) error {
	if err := reset.CheckConfirm(r.caCN(), confirmCommonName); err != nil {
		return err
	}

	action := ShutdownReboot
	if powerOff {
		action = ShutdownPowerOff
	}
	log.Printf("shutdown: %s requested over the API", action)
	r.schedule(func() { r.request(action) })

	return nil
}

// shutdownSource is something outside the API that can ask a running node to
// stop. Watch blocks until ctx ends, calling request for every shutdown the
// source observes.
type shutdownSource interface {
	Watch(ctx context.Context, request func(ShutdownAction))
}

// watchShutdownSources runs every source in the background.
func watchShutdownSources(ctx context.Context, request func(ShutdownAction), sources ...shutdownSource) {
	for _, s := range sources {
		go s.Watch(ctx, request)
	}
}

// signalAction maps a signal delivered to PID 1 to the shutdown it asks for.
func signalAction(sig os.Signal) (ShutdownAction, bool) {
	switch sig {
	case syscall.SIGTERM, syscall.SIGINT:
		return ShutdownReboot, true
	}

	return ShutdownReboot, false
}

// signalSource turns the signals delivered on signals into shutdown requests.
type signalSource struct {
	signals <-chan os.Signal
}

// Watch implements shutdownSource.
func (s signalSource) Watch(ctx context.Context, request func(ShutdownAction)) {
	for {
		select {
		case <-ctx.Done():
			return
		case sig := <-s.signals:
			if a, ok := signalAction(sig); ok {
				log.Printf("shutdown: %s requested by %v", a, sig)
				request(a)
			}
		}
	}
}

// Linux input event constants (linux/input-event-codes.h) and the size of
// struct input_event on a 64-bit kernel: a 16-byte timeval, then u16 type,
// u16 code, s32 value. CryptOS builds only for 64-bit little-endian targets
// (amd64, arm64).
const (
	inputEventSize = 24
	evSyn          = 0x00
	evKey          = 0x01
	keyPower       = 116
)

// readPowerButton reads input events from r and requests a power-off for
// every power-key press. It returns the read error that ends the stream.
func readPowerButton(r io.Reader, request func(ShutdownAction)) error {
	br := bufio.NewReaderSize(r, inputEventSize*8)
	buf := make([]byte, inputEventSize)
	for {
		if _, err := io.ReadFull(br, buf); err != nil {
			return err
		}
		typ := binary.LittleEndian.Uint16(buf[16:])
		code := binary.LittleEndian.Uint16(buf[18:])
		value := int32(binary.LittleEndian.Uint32(buf[20:])) //nolint:gosec // the kernel field is an s32
		if typ == evKey && code == keyPower && value == 1 {
			log.Printf("shutdown: %s requested by the ACPI power button", ShutdownPowerOff)
			request(ShutdownPowerOff)
		}
	}
}

// acpiPowerButtonName is the input device name the kernel's ACPI button
// driver gives the power button (both the fixed-feature and the PNP0C0C
// device).
const acpiPowerButtonName = "Power Button"

// powerButtonDevices lists the /dev/input event nodes whose input device is
// an ACPI power button. sysInput is /sys/class/input.
func powerButtonDevices(sysInput fs.FS) []string {
	entries, err := fs.ReadDir(sysInput, ".")
	if err != nil {
		return nil
	}
	var devs []string
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "event") {
			continue
		}
		name, err := fs.ReadFile(sysInput, path.Join(e.Name(), "device", "name"))
		if err != nil || strings.TrimSpace(string(name)) != acpiPowerButtonName {
			continue
		}
		devs = append(devs, "/dev/input/"+e.Name())
	}

	return devs
}

// powerButtonSource watches one ACPI power button event node.
type powerButtonSource struct {
	device string
}

// Watch implements shutdownSource. A device that cannot be opened or read
// only logs: the API and signal paths still work without it.
func (p powerButtonSource) Watch(ctx context.Context, request func(ShutdownAction)) {
	f, err := os.Open(p.device)
	if err != nil {
		log.Printf("shutdown: power button %s: %v", p.device, err)

		return
	}
	go func() {
		<-ctx.Done()
		_ = f.Close()
	}()
	if err := readPowerButton(f, request); err != nil && ctx.Err() == nil {
		log.Printf("shutdown: power button %s: %v", p.device, err)
	}
}

// powerButtonSources discovers the ACPI power buttons under /sys/class/input.
func powerButtonSources() []shutdownSource {
	var out []shutdownSource
	for _, d := range powerButtonDevices(os.DirFS("/sys/class/input")) {
		out = append(out, powerButtonSource{device: d})
	}
	if len(out) == 0 {
		log.Printf("shutdown: no ACPI power button found; a guest shutdown request from the platform will be ignored")
	}

	return out
}

// volumeCloser is the part of luks.Volume closeStateVolume needs.
type volumeCloser interface {
	Close(ctx context.Context) error
}

// closeStateVolume unmounts the state filesystem and locks the LUKS volume
// under it, so a clean shutdown leaves nothing of the state partition
// mapped. If the unmount fails the volume is left open: locking it under a
// mounted filesystem would fail anyway.
func closeStateVolume(ctx context.Context, mount string, unmount func(string) error, vol volumeCloser) error {
	if err := unmount(mount); err != nil {
		return fmt.Errorf("init: unmount %s: %w", mount, err)
	}
	log.Printf("shutdown: state filesystem %s unmounted", mount)
	if err := vol.Close(ctx); err != nil {
		return fmt.Errorf("init: lock the state volume: %w", err)
	}
	log.Printf("shutdown: state volume locked (LUKS closed)")

	return nil
}
