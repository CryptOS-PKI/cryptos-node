// Command cryptos-console renders the CryptOS node dashboard on the local
// console. It is a gRPC client of the on-box UNIX socket: it polls the node
// status and identity roughly every two seconds and redraws the Talos-style
// dashboard frame. PID 1 supervises it and restarts it on exit, so a console
// crash never affects a serving CA.
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
	"context"
	"flag"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/CryptOS-PKI/cryptos-node/internal/buildinfo"
	"github.com/CryptOS-PKI/cryptos-node/internal/console"
)

func main() {
	socket := flag.String("socket", "/run/cryptos.sock", "path to the node's local gRPC socket")
	mgmtCert := flag.String("mgmt-cert", console.ManagementCertPath, "path to the management certificate the node publishes for fingerprint display")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Query the console size once at startup; the kernel sets a large font so
	// the frame fills the whole screen. On any failure this falls back to 80x24.
	cols, rows := consoleSize(int(os.Stdout.Fd()))
	ver := buildinfo.Get().Version

	// Dial the local socket, retrying on failure so the console comes up even
	// if it launches before the node has finished exposing the socket. While no
	// connection exists we still render a degraded frame each tick so the screen
	// is never blank.
	var c *console.Client
	for c == nil {
		conn, err := console.Dial(*socket)
		if err == nil {
			c = conn
			break
		}
		renderDegraded(os.Stdout, ver, cols, rows)
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
	defer func() { _ = c.Close() }()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	// Put the console into raw mode so Ctrl-R and the typed confirmation reach
	// us a byte at a time. If stdin is not a terminal makeRaw returns a no-op
	// restore and an error, which we ignore: the dashboard still renders and
	// key input is simply unavailable.
	restore, _ := makeRaw(int(os.Stdin.Fd()))
	defer restore()
	keys := readKeys(ctx, os.Stdin)

	snap := withVersion(withMgmtAddrs(withMgmtFingerprint(c.Snapshot, *mgmtCert), console.LocalManagementAddrs), ver)
	runConsole(ctx, snap, c.Reset, os.Stdout, ticker.C, keys, cols, rows)
}

// renderDegraded draws a degraded frame, used while the socket is unreachable,
// with the console's own version in the footer.
func renderDegraded(out io.Writer, ver string, cols, rows int) {
	_, _ = io.WriteString(out, console.RenderDashboard(console.View{Degraded: true, Version: ver}, cols, rows))
}
