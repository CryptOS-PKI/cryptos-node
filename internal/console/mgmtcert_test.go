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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CryptOS-PKI/cryptos-node/internal/console"
)

func TestFingerprintGroupsUppercaseHex(t *testing.T) {
	der := []byte("any certificate bytes")
	sum := sha256.Sum256(der)
	got := console.Fingerprint(der)

	groups := strings.Split(got, " ")
	if len(groups) != 16 {
		t.Fatalf("Fingerprint = %q, want 16 space-separated groups", got)
	}
	if want := strings.ToUpper(hex.EncodeToString(sum[:])); strings.Join(groups, "") != want {
		t.Fatalf("Fingerprint = %q, want the SHA-256 %s", got, want)
	}
}

func TestManagementFingerprintReadsTheCertFile(t *testing.T) {
	certPEM := leafPEM(t, "192.0.2.10")
	block, _ := pem.Decode([]byte(certPEM))
	path := filepath.Join(t.TempDir(), "mgmt.crt")
	if err := os.WriteFile(path, []byte(certPEM), 0o644); err != nil {
		t.Fatal(err)
	}

	if got, want := console.ManagementFingerprint(path), console.Fingerprint(block.Bytes); got != want {
		t.Fatalf("ManagementFingerprint = %q, want %q", got, want)
	}
}

// A missing or unreadable file means the node has not published its
// certificate yet; the dashboard shows nothing rather than a wrong value.
func TestManagementFingerprintEmptyWithoutAValidCert(t *testing.T) {
	dir := t.TempDir()
	if got := console.ManagementFingerprint(filepath.Join(dir, "absent.crt")); got != "" {
		t.Fatalf("missing file: got %q, want empty", got)
	}
	junk := filepath.Join(dir, "junk.crt")
	if err := os.WriteFile(junk, []byte("not a certificate"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := console.ManagementFingerprint(junk); got != "" {
		t.Fatalf("junk file: got %q, want empty", got)
	}
}

func servingView(fp string) console.View {
	return console.View{
		RootCN: "ACME Root CA G1", Role: "ROOT", NodeStatus: "ESTABLISHED",
		TPM: "SEALED", Uptime: time.Hour, Version: "1.0", Fleet: console.FleetConnected,
		MgmtFingerprint: fp,
	}
}

func TestRenderDashboardShowsTheManagementFingerprint(t *testing.T) {
	fp := console.Fingerprint([]byte("mgmt cert"))
	groups := strings.Split(fp, " ")

	for _, size := range []struct{ cols, rows int }{{64, 24}, {40, 24}, {80, 30}} {
		lines := screenLines(console.RenderDashboard(servingView(fp), size.cols, size.rows))
		plain := strings.Join(lines, "\n")
		if !strings.Contains(plain, "Mgmt SHA-256") {
			t.Fatalf("%dx%d: no management cert label:\n%s", size.cols, size.rows, plain)
		}
		// The fingerprint wraps across lines, but every group is shown in order.
		var seen []string
		for _, f := range strings.Fields(plain) {
			if len(seen) < len(groups) && f == groups[len(seen)] {
				seen = append(seen, f)
			}
		}
		if len(seen) != len(groups) {
			t.Fatalf("%dx%d: fingerprint groups missing (saw %d of %d):\n%s", size.cols, size.rows, len(seen), len(groups), plain)
		}
		if len(lines) != size.rows {
			t.Fatalf("%dx%d: frame has %d lines", size.cols, size.rows, len(lines))
		}
		for i, ln := range lines {
			if len(ln) != size.cols {
				t.Fatalf("%dx%d: line %d is %d wide: %q", size.cols, size.rows, i, len(ln), ln)
			}
		}
	}
}

func TestRenderCompactShowsTheManagementFingerprint(t *testing.T) {
	fp := console.Fingerprint([]byte("mgmt cert"))
	plain := stripSGR(console.RenderDashboard(servingView(fp), 30, 10))
	if !strings.Contains(plain, "SHA   "+strings.Split(fp, " ")[0]) || !strings.Contains(plain, strings.Split(fp, " ")[15]) {
		t.Fatalf("compact render missing the fingerprint:\n%s", plain)
	}
}

func TestRenderDashboardOmitsFingerprintWhenUnknownOrDegraded(t *testing.T) {
	if plain := stripSGR(console.RenderDashboard(servingView(""), 64, 24)); strings.Contains(plain, "Mgmt SHA-256") {
		t.Fatalf("label shown with no fingerprint:\n%s", plain)
	}
	fp := console.Fingerprint([]byte("mgmt cert"))
	v := console.View{Degraded: true, RootCN: "ACME Root CA G1", Role: "ROOT", MgmtFingerprint: fp}
	if plain := stripSGR(console.RenderDashboard(v, 64, 24)); strings.Contains(plain, "Mgmt SHA-256") {
		t.Fatalf("fingerprint shown on the degraded frame:\n%s", plain)
	}
}

// maintenanceView is a node booted from the ISO, or back in maintenance after
// a reset, with no config yet.
func maintenanceView(fp string, addrs ...string) console.View {
	return console.View{Maintenance: true, Version: "1.0", MgmtFingerprint: fp, MgmtAddrs: addrs}
}

// The adoption preview asks the operator to compare the fingerprint with the
// node console, and the operator needs the DHCP address to reach the node, so
// the maintenance screen shows both.
func TestRenderDashboardMaintenanceShowsAddressAndFingerprint(t *testing.T) {
	fp := console.Fingerprint([]byte("maintenance cert"))
	groups := strings.Split(fp, " ")
	last := groups[len(groups)-1]

	for _, size := range []struct{ cols, rows int }{{64, 24}, {40, 24}, {80, 30}} {
		lines := screenLines(console.RenderDashboard(maintenanceView(fp, "192.0.2.10", "198.51.100.7"), size.cols, size.rows))
		plain := strings.Join(lines, "\n")

		got := fingerprintBlock(lines, last)
		want := fingerprintBlock(screenLines(console.RenderDashboard(servingView(fp), size.cols, size.rows)), last)
		if len(got) == 0 || strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Fatalf("%dx%d: fingerprint not shown as on the serving dashboard:\ngot:\n%s\nwant:\n%s\nscreen:\n%s",
				size.cols, size.rows, strings.Join(got, "\n"), strings.Join(want, "\n"), plain)
		}
		var addrLines []string
		for _, ln := range lines {
			ln = strings.Trim(ln, "| ")
			if strings.HasSuffix(ln, "192.0.2.10") || strings.HasSuffix(ln, "198.51.100.7") {
				addrLines = append(addrLines, strings.Join(strings.Fields(ln), " "))
			}
		}
		if len(addrLines) != 2 || addrLines[0] != "Address 192.0.2.10" || addrLines[1] != "198.51.100.7" {
			t.Fatalf("%dx%d: address lines = %q, want the label then each address on its own line:\n%s", size.cols, size.rows, addrLines, plain)
		}
		for _, s := range []string{"Awaiting configuration", "Run: cryptosctl config apply", "MAINTENANCE MODE"} {
			if !strings.Contains(plain, s) {
				t.Fatalf("%dx%d: missing %q:\n%s", size.cols, size.rows, s, plain)
			}
		}
		if strings.Contains(plain, "^R") {
			t.Fatalf("%dx%d: maintenance must not offer reset:\n%s", size.cols, size.rows, plain)
		}
		if len(lines) != size.rows {
			t.Fatalf("%dx%d: frame has %d lines", size.cols, size.rows, len(lines))
		}
		for i, ln := range lines {
			if len(ln) != size.cols {
				t.Fatalf("%dx%d: line %d is %d wide: %q", size.cols, size.rows, i, len(ln), ln)
			}
		}
	}
}

func TestRenderCompactMaintenanceShowsAddressAndFingerprint(t *testing.T) {
	fp := console.Fingerprint([]byte("maintenance cert"))
	plain := stripSGR(console.RenderDashboard(maintenanceView(fp, "192.0.2.10"), 30, 10))
	for _, want := range []string{"Awaiting configuration", "IP    192.0.2.10", "SHA   " + strings.Split(fp, " ")[0], strings.Split(fp, " ")[15]} {
		if !strings.Contains(plain, want) {
			t.Fatalf("compact render missing %q:\n%s", want, plain)
		}
	}
	if strings.Contains(plain, "^R") {
		t.Fatalf("compact maintenance render offers reset:\n%s", plain)
	}
}

// Until the listener has published its certificate and DHCP has answered, the
// maintenance screen keeps its plain form rather than showing empty lines.
func TestRenderDashboardMaintenanceWithoutAddressOrFingerprint(t *testing.T) {
	for _, size := range []struct{ cols, rows int }{{64, 24}, {30, 10}} {
		plain := stripSGR(console.RenderDashboard(maintenanceView(""), size.cols, size.rows))
		if strings.Contains(plain, "Address") || strings.Contains(plain, "Mgmt SHA-256") {
			t.Fatalf("%dx%d: empty address or fingerprint lines shown:\n%s", size.cols, size.rows, plain)
		}
		if !strings.Contains(plain, "Awaiting configuration") {
			t.Fatalf("%dx%d: maintenance title missing:\n%s", size.cols, size.rows, plain)
		}
	}
}

// Installed nodes have a configured address, so only maintenance shows one.
func TestRenderDashboardShowsAddressOnlyInMaintenance(t *testing.T) {
	fp := console.Fingerprint([]byte("mgmt cert"))
	serving := servingView(fp)
	serving.MgmtAddrs = []string{"192.0.2.10"}
	pending := awaitingCeremonyView(fp)
	pending.MgmtAddrs = []string{"192.0.2.10"}
	for _, v := range []console.View{serving, pending} {
		if plain := stripSGR(console.RenderDashboard(v, 64, 24)); strings.Contains(plain, "192.0.2.10") {
			t.Fatalf("address shown on an installed node's screen:\n%s", plain)
		}
	}
}

func TestManagementAddrsKeepsReachableIPv4(t *testing.T) {
	addrs := []net.Addr{
		&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)},
		&net.IPNet{IP: net.ParseIP("192.0.2.10"), Mask: net.CIDRMask(24, 32)},
		&net.IPNet{IP: net.ParseIP("169.254.10.1"), Mask: net.CIDRMask(16, 32)},
		&net.IPNet{IP: net.ParseIP("2001:db8::10"), Mask: net.CIDRMask(64, 128)},
		&net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)},
		&net.IPAddr{IP: net.ParseIP("198.51.100.7")},
	}
	got := console.ManagementAddrs(addrs)
	if strings.Join(got, ",") != "192.0.2.10,198.51.100.7" {
		t.Fatalf("ManagementAddrs = %q, want the two routable IPv4 addresses in order", got)
	}
}

// awaitingCeremonyView is an installed Root node that has not run its
// ceremony yet.
func awaitingCeremonyView(fp string) console.View {
	return console.View{
		Role: "ROOT", NodeStatus: "maintenance", TPM: "SEALED", Version: "1.0",
		Maintenance: true, AwaitingCeremony: true, MgmtFingerprint: fp,
	}
}

// fingerprintBlock returns the rendered lines from the "Mgmt SHA-256" label
// through the last fingerprint group, trimmed of the frame and centering.
func fingerprintBlock(lines []string, lastGroup string) []string {
	var block []string
	for _, ln := range lines {
		ln = strings.Trim(ln, "| ")
		if len(block) == 0 && !strings.HasPrefix(ln, "Mgmt SHA-256") {
			continue
		}
		block = append(block, ln)
		if strings.HasSuffix(ln, lastGroup) {
			break
		}
	}
	return block
}

func TestRenderDashboardAwaitingCeremonyShowsTheFingerprint(t *testing.T) {
	fp := console.Fingerprint([]byte("mgmt cert"))
	groups := strings.Split(fp, " ")
	last := groups[len(groups)-1]

	for _, size := range []struct{ cols, rows int }{{64, 24}, {40, 24}, {80, 30}} {
		lines := screenLines(console.RenderDashboard(awaitingCeremonyView(fp), size.cols, size.rows))
		plain := strings.Join(lines, "\n")

		got := fingerprintBlock(lines, last)
		want := fingerprintBlock(screenLines(console.RenderDashboard(servingView(fp), size.cols, size.rows)), last)
		if len(got) == 0 || strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Fatalf("%dx%d: fingerprint not shown as after the ceremony:\ngot:\n%s\nwant:\n%s\nscreen:\n%s",
				size.cols, size.rows, strings.Join(got, "\n"), strings.Join(want, "\n"), plain)
		}
		if !strings.Contains(plain, "Fetch trust, then start the ceremony") {
			t.Fatalf("%dx%d: no next-step hint:\n%s", size.cols, size.rows, plain)
		}
		if strings.Contains(plain, "config apply") {
			t.Fatalf("%dx%d: installed node told to apply a config:\n%s", size.cols, size.rows, plain)
		}
		if strings.Contains(plain, "^R") {
			t.Fatalf("%dx%d: a node with no CA must not offer reset:\n%s", size.cols, size.rows, plain)
		}
		if len(lines) != size.rows {
			t.Fatalf("%dx%d: frame has %d lines", size.cols, size.rows, len(lines))
		}
		for i, ln := range lines {
			if len(ln) != size.cols {
				t.Fatalf("%dx%d: line %d is %d wide: %q", size.cols, size.rows, i, len(ln), ln)
			}
		}
	}
}

func TestRenderCompactAwaitingCeremonyShowsTheFingerprint(t *testing.T) {
	fp := console.Fingerprint([]byte("mgmt cert"))
	plain := stripSGR(console.RenderDashboard(awaitingCeremonyView(fp), 30, 10))
	for _, want := range []string{"SHA   " + strings.Split(fp, " ")[0], strings.Split(fp, " ")[15], "Fetch trust, then start the ceremony"} {
		if !strings.Contains(plain, want) {
			t.Fatalf("compact render missing %q:\n%s", want, plain)
		}
	}
	if strings.Contains(plain, "config apply") || strings.Contains(plain, "^R") {
		t.Fatalf("compact render shows the wrong hint:\n%s", plain)
	}
}

// pendingIdentityScreens are the installed states past the start of the
// ceremony that still have no committed CA, with the title and next-step hint
// each one must show.
var pendingIdentityScreens = []struct {
	name        string
	view        func(fp string) console.View
	title, hint string
}{
	{
		name: "awaiting parent",
		view: func(fp string) console.View {
			return console.View{
				Role: "INTERMEDIATE", NodeStatus: "maintenance", TPM: "SEALED", Version: "1.0",
				Maintenance: true, AwaitingParentCert: true, MgmtFingerprint: fp,
			}
		},
		title: "Awaiting parent certificate",
		hint:  "Fetch trust, then get the CSR signed",
	},
	{
		name: "ceremony in progress",
		view: func(fp string) console.View {
			return console.View{
				Role: "ROOT", NodeStatus: "establishing", TPM: "SEALED", Version: "1.0",
				Maintenance: true, CeremonyInProgress: true, MgmtFingerprint: fp,
			}
		},
		title: "Ceremony in progress",
		hint:  "Wait, or start it again if it failed",
	},
}

func TestRenderDashboardPendingIdentityScreens(t *testing.T) {
	fp := console.Fingerprint([]byte("mgmt cert"))
	groups := strings.Split(fp, " ")
	last := groups[len(groups)-1]

	for _, tc := range pendingIdentityScreens {
		for _, size := range []struct{ cols, rows int }{{64, 24}, {40, 24}, {80, 30}} {
			lines := screenLines(console.RenderDashboard(tc.view(fp), size.cols, size.rows))
			plain := strings.Join(lines, "\n")

			got := fingerprintBlock(lines, last)
			want := fingerprintBlock(screenLines(console.RenderDashboard(servingView(fp), size.cols, size.rows)), last)
			if len(got) == 0 || strings.Join(got, "\n") != strings.Join(want, "\n") {
				t.Fatalf("%s %dx%d: fingerprint not shown as on the serving dashboard:\ngot:\n%s\nwant:\n%s\nscreen:\n%s",
					tc.name, size.cols, size.rows, strings.Join(got, "\n"), strings.Join(want, "\n"), plain)
			}
			for _, s := range []string{tc.title, tc.hint, strings.ToUpper(tc.title)} {
				if !strings.Contains(plain, s) {
					t.Fatalf("%s %dx%d: missing %q:\n%s", tc.name, size.cols, size.rows, s, plain)
				}
			}
			if strings.Contains(plain, "config apply") || strings.Contains(plain, "Awaiting configuration") {
				t.Fatalf("%s %dx%d: installed node shown the maintenance screen:\n%s", tc.name, size.cols, size.rows, plain)
			}
			if strings.Contains(plain, "^R") {
				t.Fatalf("%s %dx%d: a node with no CA must not offer reset:\n%s", tc.name, size.cols, size.rows, plain)
			}
			if len(lines) != size.rows {
				t.Fatalf("%s %dx%d: frame has %d lines", tc.name, size.cols, size.rows, len(lines))
			}
			for i, ln := range lines {
				if len(ln) != size.cols {
					t.Fatalf("%s %dx%d: line %d is %d wide: %q", tc.name, size.cols, size.rows, i, len(ln), ln)
				}
			}
		}
	}
}

func TestRenderCompactPendingIdentityScreens(t *testing.T) {
	fp := console.Fingerprint([]byte("mgmt cert"))
	for _, tc := range pendingIdentityScreens {
		plain := stripSGR(console.RenderDashboard(tc.view(fp), 30, 10))
		for _, want := range []string{"SHA   " + strings.Split(fp, " ")[0], strings.Split(fp, " ")[15], tc.title, tc.hint} {
			if !strings.Contains(plain, want) {
				t.Fatalf("%s: compact render missing %q:\n%s", tc.name, want, plain)
			}
		}
		if strings.Contains(plain, "config apply") || strings.Contains(plain, "^R") {
			t.Fatalf("%s: compact render shows the wrong hint:\n%s", tc.name, plain)
		}
	}
}

// caSignedLeafPEM returns a leaf issued by a separate CA, the shape the
// management certificate takes once the node has its CA.
func caSignedLeafPEM(t *testing.T) string {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Example Root CA G1"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "192.0.2.10"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestManagementCASignedTellsTheTwoKindsApart(t *testing.T) {
	dir := t.TempDir()
	self := filepath.Join(dir, "self.crt")
	signed := filepath.Join(dir, "signed.crt")
	if err := os.WriteFile(self, []byte(leafPEM(t, "192.0.2.10")), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(signed, []byte(caSignedLeafPEM(t)), 0o644); err != nil {
		t.Fatal(err)
	}
	if console.ManagementCASigned(self) {
		t.Error("a self-signed certificate reads as CA-signed")
	}
	if !console.ManagementCASigned(signed) {
		t.Error("a CA-signed certificate reads as self-signed")
	}
	if console.ManagementCASigned(filepath.Join(dir, "absent.crt")) {
		t.Error("a missing file reads as CA-signed")
	}
}

// Once the node presents a CA-signed certificate, the dashboard says so, so
// an operator trusts the CA rather than pinning a fingerprint that changes
// every boot.
func TestRenderDashboardMarksACASignedManagementCert(t *testing.T) {
	fp := console.Fingerprint([]byte("mgmt cert"))
	signed := servingView(fp)
	signed.MgmtCASigned = true

	for _, size := range []struct{ cols, rows int }{{64, 24}, {40, 24}, {80, 30}} {
		lines := screenLines(console.RenderDashboard(signed, size.cols, size.rows))
		plain := strings.Join(lines, "\n")
		if !strings.Contains(plain, "CA-signed") {
			t.Fatalf("%dx%d: no CA-signed marker:\n%s", size.cols, size.rows, plain)
		}
		for i, ln := range lines {
			if len(ln) != size.cols {
				t.Fatalf("%dx%d: line %d is %d wide: %q", size.cols, size.rows, i, len(ln), ln)
			}
		}
		if unsigned := stripSGR(console.RenderDashboard(servingView(fp), size.cols, size.rows)); strings.Contains(unsigned, "CA-signed") {
			t.Fatalf("%dx%d: CA-signed marker on a self-signed certificate:\n%s", size.cols, size.rows, unsigned)
		}
	}
	if plain := stripSGR(console.RenderDashboard(signed, 30, 10)); !strings.Contains(plain, "CA-signed") {
		t.Fatalf("compact render has no CA-signed marker:\n%s", plain)
	}
}
