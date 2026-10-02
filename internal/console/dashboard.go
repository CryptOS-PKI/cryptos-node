package console

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
	"fmt"
	"strings"
	"time"
)

// FleetState is the node's Fleet Manager relationship, shown on the dashboard.
type FleetState int

const (
	// FleetNotEnrolled means no Fleet Manager endpoint is configured.
	FleetNotEnrolled FleetState = iota
	// FleetConnected means the node is reaching its Fleet Manager.
	FleetConnected
	// FleetDisconnected means an endpoint is configured but unreachable.
	FleetDisconnected
)

// fleetLabel maps a FleetState to its short display string.
func fleetLabel(s FleetState) string {
	switch s {
	case FleetConnected:
		return "connected"
	case FleetDisconnected:
		return "disconnected"
	default:
		return "not enrolled"
	}
}

// View is the rendered dashboard's data. It carries operational status and no
// network or crypto identifiers, with two exceptions: MgmtFingerprint, the
// SHA-256 of the public management certificate, which exists so an operator
// can verify a pin against the node's own screen, and MgmtAddrs, which only
// the maintenance screen shows, because a node with no config has a DHCP
// address the operator cannot know in advance.
type View struct {
	RootCN      string
	Issuer      string
	Role        string
	NodeStatus  string
	TPM         string
	Uptime      time.Duration
	Version     string
	Fleet       FleetState
	Maintenance bool
	Degraded    bool

	// AwaitingCeremony marks an installed node that has no CA identity yet
	// and is waiting for its first ceremony. It is set with Maintenance, and
	// its screen shows the management fingerprint so the operator can verify
	// it before pinning.
	AwaitingCeremony bool

	// AwaitingParentCert marks a subordinate that has staged its CSR and is
	// waiting for its parent-signed chain. CeremonyInProgress marks a node
	// whose ceremony started and has not committed; a failed ceremony leaves
	// it set until one succeeds. Both are set with Maintenance and share the
	// awaiting-ceremony layout.
	AwaitingParentCert bool
	CeremonyInProgress bool

	// MgmtFingerprint is the management certificate fingerprint in the
	// grouped form Fingerprint returns. Empty hides the line.
	MgmtFingerprint string

	// MgmtCASigned marks a management certificate issued by the node's CA.
	// The screen then says to trust the CA instead of pinning the
	// fingerprint.
	MgmtCASigned bool

	// MgmtAddrs are the IPv4 addresses the management listener is reachable
	// on. Only the maintenance screen shows them; empty hides the line.
	MgmtAddrs []string
}

// HumanUptime renders a duration in "3d 02h 14m" form.
func HumanUptime(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	days := int(d / (24 * time.Hour))
	rem := d % (24 * time.Hour)
	hours := int(rem / time.Hour)
	rem %= time.Hour
	mins := int(rem / time.Minute)
	return fmt.Sprintf("%dd %02dh %02dm", days, hours, mins)
}

// statusColor picks the value color for a health string: green for the healthy
// markers, yellow for the ones that need attention, and no color for normal
// states such as "not enrolled" or a TPM-less key tier.
func statusColor(s string) string {
	switch strings.ToUpper(s) {
	case "ESTABLISHED", "CONNECTED", "SEALED", "OK":
		return sgrBoldGreen
	case "DISCONNECTED", "DEGRADED":
		return sgrBoldYellow
	default:
		return ""
	}
}

// Wording shared by more than one screen.
const (
	resetHint        = "^R  reset (destroys this CA)"
	compactResetHint = "^R reset"
	degradedStatus   = "degraded (reconnecting)"
	mgmtCASignedHint = "CA-signed, trust the CA"
	mgmtSelfHint     = "self-signed, compare the fingerprint"
	fingerprintLabel = "Mgmt SHA-256"
	// The adoption flow asks the operator to compare the fingerprint twice:
	// once in maintenance before the install, once after the installed
	// node's first boot.
	checkBeforeInstall = "check 1/2: compare with the web console"
	checkAfterInstall  = "check 2/2: compare with the web console"
)

// RenderDashboard returns the full-screen dashboard sized to cols x rows: an
// ANSI clear + home prefix, then the framed screen for the view's state, or the
// compact fallback when the console is smaller than the frame needs. Color is
// applied over zero-width SGR escapes, so all layout math runs on plain text.
func RenderDashboard(v View, cols, rows int) string {
	return dashboardScreen(v).render(cols, rows)
}

// dashboardScreen builds the screen for the view's state: a pending identity,
// maintenance, degraded, or serving.
func dashboardScreen(v View) screen {
	ver := segLine{{version(v), sgrDim}}
	reset := segLine{{resetHint, sgrBoldRed}}
	compactReset := segLine{{compactResetHint, sgrBoldRed}}
	switch p := v.pendingIdentity(); {
	case p != nil:
		body := []item{center(seg{p.title, sgrBoldYellow}), center(seg{p.hint, ""})}
		if v.MgmtFingerprint != "" {
			body = append(append(body, blank()), fingerprintItems(v.MgmtFingerprint)...)
			body = append(body, p.extra(v)...)
		}
		compact := []segLine{{{p.title, sgrBoldYellow}}, {{p.hint, ""}}}
		compact = append(compact, compactFingerprint(v)...)
		foot := segLine{{strings.ToUpper(p.title), sgrBoldYellow}}
		return screen{tag: roleTag(v), body: body, compact: compact, footL: foot, footR: ver}
	case v.Maintenance:
		run := []seg{{"Run: ", sgrDim}, {"cryptosctl config apply", sgrBoldWhite}}
		body := []item{center(seg{"Awaiting configuration", sgrBoldYellow}), center(run...)}
		if len(v.MgmtAddrs) > 0 {
			body = append(body, blank())
			for i, a := range v.MgmtAddrs {
				body = append(body, field(firstLabel(i, "Address"), a, sgrBoldWhite))
			}
		}
		if v.MgmtFingerprint != "" {
			body = append(append(body, blank()), fingerprintItems(v.MgmtFingerprint)...)
			body = append(body, field("", checkBeforeInstall, sgrBoldYellow))
		}
		compact := []segLine{{{"Awaiting configuration", sgrBoldYellow}}, run}
		for i, a := range v.MgmtAddrs {
			compact = append(compact, compactField(firstLabel(i, "IP"), a, sgrBoldWhite))
		}
		compact = append(compact, compactFingerprint(v)...)
		foot := segLine{{"MAINTENANCE MODE", sgrBoldYellow}}
		return screen{tag: "MAINTENANCE", tagColor: sgrBoldYellow, body: body, compact: compact, footL: foot, footR: ver}
	case v.Degraded:
		body := []item{
			field(caLabelFromRole(v.Role), v.RootCN, sgrBoldWhite),
			field("Node", degradedStatus, sgrBoldYellow),
		}
		compact := []segLine{
			compactField("CA", v.RootCN, sgrBoldWhite),
			compactField("Node", degradedStatus, sgrBoldYellow),
		}
		return screen{tag: roleTag(v), body: body, compact: compact, footL: reset, compactFoot: compactReset, footR: ver}
	default:
		fleet := fleetLabel(v.Fleet)
		body := []item{
			field(caLabelFromRole(v.Role), v.RootCN, sgrBoldWhite),
			field("Issuer", v.Issuer, ""),
			field("Node", v.NodeStatus, statusColor(v.NodeStatus)),
			field("Fleet Manager", fleet, statusColor(fleet)),
			field("TPM", v.TPM, statusColor(v.TPM)),
			field("Uptime", HumanUptime(v.Uptime), ""),
		}
		if v.MgmtFingerprint != "" {
			body = append(append(body, fingerprintItems(v.MgmtFingerprint)...), mgmtCertItem(v))
		}
		compact := []segLine{
			compactField("CA", v.RootCN, sgrBoldWhite),
			compactField("Node", v.NodeStatus, statusColor(v.NodeStatus)),
			compactField("FM", fleet, statusColor(fleet)),
			compactField("TPM", v.TPM, statusColor(v.TPM)),
		}
		compact = append(compact, compactFingerprint(v)...)
		return screen{tag: roleTag(v), body: body, compact: compact, footL: reset, compactFoot: compactReset, footR: ver}
	}
}

// firstLabel labels only the first of a stacked list of values.
func firstLabel(i int, label string) string {
	if i == 0 {
		return label
	}
	return ""
}

// pendingScreen is the title and next-step hint for an installed node that has
// no committed CA identity yet. Every such state shares one layout: the title,
// the hint, and the management fingerprint the operator verifies before
// pinning.
type pendingScreen struct {
	title, hint string
	// check is the fingerprint check line shown while the certificate is
	// self-signed; mgmtCert says whether the "Mgmt cert" line follows.
	check    string
	mgmtCert bool
}

var (
	// awaitingCeremonyScreen: pin the management certificate, checked against
	// this screen, then run the ceremony against it.
	awaitingCeremonyScreen = pendingScreen{"Awaiting ceremony", "Fetch trust, then start the ceremony", checkAfterInstall, true}
	// awaitingParentScreen: pin the node, then fetch its CSR, have the parent
	// sign it, and submit the chain back.
	awaitingParentScreen = pendingScreen{"Awaiting parent certificate", "Fetch trust, then get the CSR signed", "", true}
	// ceremonyInProgressScreen: the phase is not rolled back when a ceremony
	// fails, so the hint also covers starting it again.
	ceremonyInProgressScreen = pendingScreen{"Ceremony in progress", "Wait, or start it again if it failed", "", false}
)

// pendingIdentity returns the screen for the view's pre-identity state, or nil
// when the node is not in one.
func (v View) pendingIdentity() *pendingScreen {
	switch {
	case v.AwaitingCeremony:
		return &awaitingCeremonyScreen
	case v.AwaitingParentCert:
		return &awaitingParentScreen
	case v.CeremonyInProgress:
		return &ceremonyInProgressScreen
	default:
		return nil
	}
}

// extra returns the lines under the fingerprint: the check line while the
// certificate is self-signed, then the "Mgmt cert" line.
func (p *pendingScreen) extra(v View) []item {
	var out []item
	if p.check != "" && !v.MgmtCASigned {
		out = append(out, field("", p.check, sgrBoldYellow))
	}
	if p.mgmtCert {
		out = append(out, mgmtCertItem(v))
	}
	return out
}

// mgmtCertItem says how to trust the management certificate: trust the CA
// that signed it, or compare the fingerprint of a self-signed one.
func mgmtCertItem(v View) item {
	if v.MgmtCASigned {
		return field("Mgmt cert", mgmtCASignedHint, "")
	}
	return field("Mgmt cert", mgmtSelfHint, "")
}

// fingerprintItems lays a grouped fingerprint out under the "Mgmt SHA-256"
// label, eight groups per line. A narrow frame wraps the value column, which
// splits each line into two of four groups.
func fingerprintItems(fp string) []item {
	groups := strings.Fields(fp)
	var out []item
	for i := 0; i < len(groups); i += 8 {
		chunk := strings.Join(groups[i:min(i+8, len(groups))], " ")
		out = append(out, field(firstLabel(i, fingerprintLabel), chunk, sgrBoldWhite))
	}
	return out
}

// compactLabelWidth is the label column of the compact screen.
const compactLabelWidth = 6

// compactField is a compact "label value" line.
func compactField(label, value, color string) segLine {
	return segLine{{fmt.Sprintf("%-*s", compactLabelWidth, label), sgrDim}, {value, color}}
}

// compactFingerprint is the fingerprint on the compact screen, four groups per
// line under a short label, then the CA-signed marker when it applies.
func compactFingerprint(v View) []segLine {
	groups := strings.Fields(v.MgmtFingerprint)
	var out []segLine
	for i := 0; i < len(groups); i += 4 {
		chunk := strings.Join(groups[i:min(i+4, len(groups))], " ")
		if i == 0 {
			out = append(out, compactField("SHA", chunk, sgrBoldWhite))
			continue
		}
		out = append(out, segLine{spaces(compactLabelWidth), {chunk, sgrBoldWhite}})
	}
	if len(out) > 0 && v.MgmtCASigned {
		out = append(out, segLine{{mgmtCASignedHint, ""}})
	}
	return out
}

// version renders the footer version tag. The build stamps a git-describe
// version that already starts with "v", so the prefix is added only to a bare
// number such as "0.1.0".
func version(v View) string { return versionTag(v.Version) }

// versionTag is version for a bare version string.
func versionTag(ver string) string {
	switch {
	case ver == "":
		return "v?"
	case ver[0] >= '0' && ver[0] <= '9':
		return "v" + ver
	default:
		return ver
	}
}

// roleTag returns the header role tag, defaulting to NODE.
func roleTag(v View) string {
	if v.Role == "" {
		return "NODE"
	}
	return v.Role
}
