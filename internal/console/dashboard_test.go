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
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/CryptOS-PKI/cryptos-node/internal/console"
)

// sgrRE matches ANSI SGR color escapes; color codes are zero-width, so tests
// strip them before any width or length assertion.
var sgrRE = regexp.MustCompile("\x1b\\[[0-9;]*m")

// stripSGR removes ANSI SGR escapes so a visible width can be measured.
func stripSGR(s string) string { return sgrRE.ReplaceAllString(s, "") }

// screenLines returns the frame's rendered lines with the leading clear+home
// prefix removed and ANSI color escapes stripped, for width/length assertions.
func screenLines(out string) []string {
	out = strings.TrimPrefix(out, "\x1b[2J\x1b[H")
	out = stripSGR(out)
	out = strings.TrimRight(out, "\n")
	return strings.Split(out, "\n")
}

func TestHumanUptime(t *testing.T) {
	got := console.HumanUptime(74*time.Hour + 14*time.Minute + 9*time.Second)
	if got != "3d 02h 14m" {
		t.Fatalf("HumanUptime = %q, want %q", got, "3d 02h 14m")
	}
}

func TestRenderDashboardServing(t *testing.T) {
	v := console.View{
		RootCN: "ACME Root CA G1", Role: "ROOT", NodeStatus: "ESTABLISHED",
		TPM: "SEALED", Uptime: 74 * time.Hour, Version: "phase-1-dev", Fleet: console.FleetConnected,
	}
	out := console.RenderDashboard(v, 64, 24)
	plain := stripSGR(out)
	for _, want := range []string{"CryptOS PKI", "ROOT", "ACME Root CA G1", "ESTABLISHED", "SEALED", "connected", "^R"} {
		if !strings.Contains(plain, want) {
			t.Fatalf("serving dashboard missing %q:\n%s", want, plain)
		}
	}
	// No network/crypto identifiers on screen.
	for _, banned := range []string{"10.0.0", "sha256", "SHA256", "serial"} {
		if strings.Contains(plain, banned) {
			t.Fatalf("dashboard leaked identifier %q:\n%s", banned, plain)
		}
	}
}

func TestRenderDashboardIssuer(t *testing.T) {
	v := console.View{
		RootCN: "ACME Issuing CA G1", Role: "INTERMEDIATE", Issuer: "ACME Root CA G1",
		NodeStatus: "ESTABLISHED", TPM: "SEALED", Uptime: 74 * time.Hour, Version: "phase-1-dev",
		Fleet: console.FleetConnected,
	}
	plain := stripSGR(console.RenderDashboard(v, 64, 24))
	for _, want := range []string{"Intermediate   ACME Issuing CA G1", "Issuer", "ACME Root CA G1"} {
		if !strings.Contains(plain, want) {
			t.Fatalf("serving dashboard missing %q:\n%s", want, plain)
		}
	}
}

// TestRenderDashboardFillsScreen checks the frame spans the full console: every
// rendered line is exactly cols wide (on plain text) and there are exactly rows
// lines.
func TestRenderDashboardFillsScreen(t *testing.T) {
	const cols, rows = 64, 24
	out := console.RenderDashboard(console.View{
		RootCN: "ACME Root CA G1", Role: "ROOT", NodeStatus: "ESTABLISHED",
		TPM: "SEALED", Fleet: console.FleetConnected, Version: "1.0",
	}, cols, rows)
	lines := screenLines(out)
	if len(lines) != rows {
		t.Fatalf("frame has %d lines, want %d:\n%s", len(lines), rows, strings.Join(lines, "\n"))
	}
	for i, ln := range lines {
		if len(ln) != cols {
			t.Fatalf("line %d is %d wide, want %d: %q", i, len(ln), cols, ln)
		}
	}
	// The top border must carry the wordmark and span the full width.
	if !strings.Contains(lines[0], "CryptOS PKI") || len(lines[0]) != cols {
		t.Fatalf("top border wrong: %q", lines[0])
	}
}

func TestRenderDashboardMaintenanceAndDegraded(t *testing.T) {
	m := stripSGR(console.RenderDashboard(console.View{Maintenance: true, Version: "phase-1-dev"}, 64, 24))
	if !strings.Contains(m, "MAINTENANCE") || !strings.Contains(m, "config apply") {
		t.Fatalf("maintenance screen wrong:\n%s", m)
	}
	if strings.Contains(m, "^R") {
		t.Fatalf("maintenance must not offer reset:\n%s", m)
	}
	d := stripSGR(console.RenderDashboard(console.View{Degraded: true, RootCN: "ACME Root CA G1", Role: "ROOT"}, 64, 24))
	if !strings.Contains(d, "degraded") {
		t.Fatalf("degraded screen missing marker:\n%s", d)
	}
	// A degraded node is still serving, so it keeps the reset affordance.
	if !strings.Contains(d, "^R") {
		t.Fatalf("degraded screen must keep reset:\n%s", d)
	}
}

func TestFleetLabel(t *testing.T) {
	cases := map[console.FleetState]string{
		console.FleetNotEnrolled: "not enrolled", console.FleetConnected: "connected", console.FleetDisconnected: "disconnected",
	}
	for st, want := range cases {
		out := stripSGR(console.RenderDashboard(console.View{Fleet: st, RootCN: "x", Role: "ROOT", NodeStatus: "ESTABLISHED", TPM: "SEALED"}, 64, 24))
		if !strings.Contains(out, want) {
			t.Fatalf("fleet %v missing %q", st, want)
		}
	}
}
