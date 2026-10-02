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

// clearHome resets the screen: clear (2J) then move the cursor home (H).
const clearHome = "\x1b[2J\x1b[H"

// ANSI SGR codes. Only the 16 standard colors are used because the framebuffer
// console (fbcon) renders that palette; 256-color and truecolor are avoided.
const (
	sgrReset     = "\x1b[0m"
	sgrDim       = "\x1b[2m"
	sgrBoldCyan  = "\x1b[1;36m"
	sgrBoldGreen = "\x1b[1;32m"
	sgrYellow    = "\x1b[33m"
	sgrBoldRed   = "\x1b[1;31m"
)

// sgr wraps s in an SGR color code and a reset. It is the single place color is
// applied, so all layout math elsewhere runs on plain (uncolored) text and the
// zero-width escapes never affect a computed width.
func sgr(code, s string) string {
	if code == "" {
		return s
	}
	return code + s + sgrReset
}

// Minimum size the full-screen frame needs before we fall back to a compact
// render. Below this the border and centered content cannot fit cleanly.
const (
	minCols = 40
	minRows = 12
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
// markers, yellow for the not-healthy ones, and no color otherwise.
func statusColor(s string) string {
	switch strings.ToUpper(s) {
	case "ESTABLISHED", "CONNECTED", "SEALED", "OK":
		return sgrBoldGreen
	case "DISCONNECTED", "NOT ENROLLED", "UNAVAILABLE", "DEGRADED":
		return sgrYellow
	default:
		return ""
	}
}

// seg is a piece of text paired with its color. A line is a sequence of segs;
// its plain width is the sum of the segs' plain lengths, so centering and
// padding math never counts the zero-width color escapes.
type seg struct {
	text  string
	color string
}

// segLine is one logical content line built from colored segments.
type segLine []seg

// plainLen returns the visible width of the line.
func (l segLine) plainLen() int {
	n := 0
	for _, s := range l {
		n += len(s.text)
	}
	return n
}

// colored renders the line with its color escapes.
func (l segLine) colored() string {
	var b strings.Builder
	for _, s := range l {
		b.WriteString(sgr(s.color, s.text))
	}
	return b.String()
}

// text builds a single-segment line with no color.
func text(s string) segLine { return segLine{{s, ""}} }

// labelValue builds a "label  value" line with a dim, fixed-width label column
// and a colored value.
func labelValue(label, value, valColor string) segLine {
	return segLine{{fmt.Sprintf("%-14s ", label), sgrDim}, {value, valColor}}
}

// footerSpec is the footer's left hint and whether it is a destructive (red)
// action; the right side is always the dim version tag.
type footerSpec struct {
	left   string
	danger bool
}

// RenderDashboard returns a full-screen framed dashboard sized to cols x rows:
// an ANSI clear + home prefix, a border spanning the whole console, and the
// status content centered both horizontally and vertically inside the frame.
// The maintenance and degraded variants are keyed off v.Maintenance and
// v.Degraded; otherwise the serving frame is drawn. Sizes below the minimum
// fall back to a compact render so the output never overflows or panics. Color
// is applied over zero-width SGR escapes, so all layout math runs on plain text.
func RenderDashboard(v View, cols, rows int) string {
	if cols < minCols || rows < minRows {
		return renderCompact(v)
	}
	body, foot, right, tag := dashboardParts(v, cols)
	return frame(cols, rows, tag, body, foot, right)
}

// dashboardParts returns the centered body lines, footer, version tag, and
// header tag for the current view variant.
func dashboardParts(v View, cols int) (body []segLine, foot footerSpec, right, headerTag string) {
	p := v.pendingIdentity()
	switch {
	case p != nil:
		body = append(p.lines(), mgmtLines(v, cols-2)...)
		return body, footerSpec{left: p.footer()}, version(v), roleTag(v)
	case v.Maintenance:
		body = []segLine{
			{{"Awaiting configuration", sgrYellow}},
			text(""),
			text("Run: cryptosctl config apply"),
		}
		if more := maintenanceLines(v, cols-2); len(more) > 0 {
			body = append(append(body, text("")), alignLeft(more)...)
		}
		return body, footerSpec{left: "MAINTENANCE MODE"}, version(v), "MAINTENANCE"
	case v.Degraded:
		body = []segLine{
			labelValue("Root CA", v.RootCN, ""),
			text(""),
			{{"degraded (reconnecting)", sgrYellow}},
		}
		return body, footerSpec{left: "^R  reset (destroys this CA)", danger: true}, version(v), roleTag(v)
	default:
		return fieldLines(v, cols-2), footerSpec{left: "^R  reset (destroys this CA)", danger: true}, version(v), roleTag(v)
	}
}

// pendingScreen is the title and next-step hint for an installed node that has
// no committed CA identity yet. Every such state shares one layout: the title,
// the hint, and the management fingerprint the operator verifies before
// pinning.
type pendingScreen struct {
	title, hint string
}

var (
	// awaitingCeremonyScreen: pin the management certificate, checked against
	// this screen, then run the ceremony against it.
	awaitingCeremonyScreen = pendingScreen{"Awaiting ceremony", "Fetch trust, then start the ceremony"}
	// awaitingParentScreen: pin the node, then fetch its CSR, have the parent
	// sign it, and submit the chain back.
	awaitingParentScreen = pendingScreen{"Awaiting parent certificate", "Fetch trust, then get the CSR signed"}
	// ceremonyInProgressScreen: the phase is not rolled back when a ceremony
	// fails, so the hint also covers starting it again.
	ceremonyInProgressScreen = pendingScreen{"Ceremony in progress", "Wait, or start it again if it failed"}
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

// lines returns the status and hint lines shown above the management
// fingerprint.
func (p *pendingScreen) lines() []segLine {
	return []segLine{
		{{p.title, sgrYellow}},
		text(""),
		text(p.hint),
		text(""),
	}
}

// footer is the footer's left label: the title in capitals.
func (p *pendingScreen) footer() string { return strings.ToUpper(p.title) }

// fieldLines returns the centered serving status lines. The CA identity line is
// labeled by role (Root CA / Intermediate CA / Issuing CA) and is followed by an
// Issuer line naming the parent CA. width is the room each line has; it only
// decides how the management fingerprint wraps.
func fieldLines(v View, width int) []segLine {
	lines := []segLine{
		labelValue(caLabelFromRole(v.Role), v.RootCN, ""),
		labelValue("Issuer", v.Issuer, ""),
		labelValue("Node", v.NodeStatus, statusColor(v.NodeStatus)),
		labelValue("Fleet Manager", fleetLabel(v.Fleet), statusColor(fleetLabel(v.Fleet))),
		labelValue("TPM", v.TPM, statusColor(v.TPM)),
		labelValue("Uptime", HumanUptime(v.Uptime), ""),
	}
	return append(lines, mgmtLines(v, width)...)
}

// labelWidth is the visible width of labelValue's label column.
const labelWidth = 15

// mgmtCASignedHint follows the fingerprint when the management certificate is
// CA-signed.
const mgmtCASignedHint = "CA-signed, trust the CA"

// mgmtLines returns the management certificate lines: the fingerprint, then
// the CA-signed marker when it applies.
func mgmtLines(v View, width int) []segLine {
	lines := fingerprintLines(v.MgmtFingerprint, width)
	if len(lines) > 0 && v.MgmtCASigned {
		lines = append(lines, labelValue("Mgmt cert", mgmtCASignedHint, ""))
	}
	return lines
}

// maintenanceLines returns the address and management certificate lines of
// the maintenance screen: what an operator needs to reach the node and to
// check the certificate it presents before trusting it.
func maintenanceLines(v View, width int) []segLine {
	return append(addressLines(v.MgmtAddrs), mgmtLines(v, width)...)
}

// alignLeft pads every line to the width of the widest so that, centered
// one by one, the lines share a left edge and their label columns line up.
func alignLeft(lines []segLine) []segLine {
	w := 0
	for _, l := range lines {
		w = max(w, l.plainLen())
	}
	out := make([]segLine, len(lines))
	for i, l := range lines {
		out[i] = append(append(segLine{}, l...), seg{strings.Repeat(" ", w-l.plainLen()), ""})
	}
	return out
}

// addressLines puts the first address beside the "Address" label and each
// further one on its own line under it. IPv4 addresses always fit beside the
// label at the minimum frame width.
func addressLines(addrs []string) []segLine {
	var lines []segLine
	for i, a := range addrs {
		if i == 0 {
			lines = append(lines, labelValue("Address", a, ""))
			continue
		}
		lines = append(lines, segLine{{strings.Repeat(" ", labelWidth) + a, ""}})
	}
	return lines
}

// fingerprintLines wraps a grouped fingerprint under the "Mgmt SHA-256" label.
// Eight groups per line when they fit beside the label, otherwise four; when
// even four do not fit, the label takes its own line and the groups start at
// the left edge.
func fingerprintLines(fp string, width int) []segLine {
	if fp == "" {
		return nil
	}
	const label = "Mgmt SHA-256"
	groups := strings.Fields(fp)
	per := 8
	if labelWidth+groupsWidth(per) > width {
		per = 4
	}
	var lines []segLine
	indent := strings.Repeat(" ", labelWidth)
	if labelWidth+groupsWidth(per) > width {
		lines = append(lines, segLine{{label, sgrDim}})
		indent = ""
	}
	for i := 0; i < len(groups); i += per {
		chunk := strings.Join(groups[i:min(i+per, len(groups))], " ")
		if i == 0 && indent != "" {
			lines = append(lines, labelValue(label, chunk, ""))
			continue
		}
		lines = append(lines, segLine{{indent + chunk, ""}})
	}
	return lines
}

// groupsWidth is the visible width of n space-separated 4-digit groups.
func groupsWidth(n int) int { return n*5 - 1 }

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

// frame assembles the full cols x rows screen: a top border with the wordmark
// and a right-aligned tag, the shield banner and body centered vertically, a
// footer row just above the bottom border, and cyan side bars on every interior
// row. All widths are computed on plain text; color rides along per segment.
func frame(cols, rows int, tag string, body []segLine, foot footerSpec, right string) string {
	inner := cols - 2 // interior width between the side bars

	// Content block = shield banner + blank + body lines.
	var content []segLine
	for _, bl := range bannerLines() {
		content = append(content, segLine{{bl, sgrBoldCyan}})
	}
	content = append(content, text(""))
	content = append(content, body...)

	// Interior rows between the borders; the last holds the footer, and the
	// content block is vertically centered in the rows above it.
	interior := rows - 2
	footerRow := interior - 1
	top := (footerRow - len(content)) / 2
	if top < 0 {
		top = 0
	}

	lines := make([]string, 0, rows)
	lines = append(lines, topBorder(cols, tag))
	for i := 0; i < interior; i++ {
		switch {
		case i == footerRow:
			lines = append(lines, wrapRow(footerLine(inner, foot, right), inner))
		case i >= top && i-top < len(content):
			lines = append(lines, wrapRow(centered(content[i-top], inner), inner))
		default:
			lines = append(lines, wrapRow(nil, inner))
		}
	}
	lines = append(lines, bottomBorder(cols))
	return clearHome + strings.Join(lines, "\n") + "\n"
}

// bannerLines returns the shield banner split into lines.
func bannerLines() []string {
	return strings.Split(strings.TrimRight(Banner(), "\n"), "\n")
}

// centered left-pads a line so its content is horizontally centered within
// width; right padding is added by wrapRow.
func centered(l segLine, width int) segLine {
	pw := l.plainLen()
	if pw >= width {
		return l
	}
	left := (width - pw) / 2
	if left <= 0 {
		return l
	}
	return append(segLine{{strings.Repeat(" ", left), ""}}, l...)
}

// wrapRow renders an interior line inside cyan side bars, right-padding with
// plain spaces so the total visible width is exactly cols (2 bars + inner).
func wrapRow(l segLine, inner int) string {
	pw := l.plainLen()
	pad := inner - pw
	if pad < 0 {
		pad = 0
	}
	return bar() + l.colored() + strings.Repeat(" ", pad) + bar()
}

// bar is a cyan vertical border segment.
func bar() string { return sgr(sgrBoldCyan, "|") }

// footerLine builds the footer interior line: a left hint (red if destructive)
// and a right-aligned dim version tag.
func footerLine(inner int, foot footerSpec, right string) segLine {
	leftColor := ""
	if foot.danger {
		leftColor = sgrBoldRed
	}
	left := "  " + foot.left
	rightTxt := right + "  "
	space := inner - len(left) - len(rightTxt)
	if space < 1 {
		// Not enough room for both; keep the left hint.
		return segLine{{left, leftColor}}
	}
	return segLine{
		{left, leftColor},
		{strings.Repeat(" ", space), ""},
		{rightTxt, sgrDim},
	}
}

// topBorder builds the top rule: ".<space>CryptOS PKI<dashes>tag<space>."
// spanning cols, drawn in bright cyan.
func topBorder(cols int, tag string) string {
	title := " CryptOS PKI "
	tg := " " + tag + " "
	dashes := cols - 2 - len(title) - len(tg)
	var plain string
	if dashes < 1 {
		d := cols - 2 - len(title)
		if d < 0 {
			d = 0
		}
		plain = "." + clip(title+strings.Repeat("-", d), cols-2) + "."
	} else {
		plain = "." + title + strings.Repeat("-", dashes) + tg + "."
	}
	return sgr(sgrBoldCyan, plain)
}

// bottomBorder builds the bottom rule spanning cols, in bright cyan.
func bottomBorder(cols int) string {
	return sgr(sgrBoldCyan, "'"+strings.Repeat("-", cols-2)+"'")
}

// clip truncates s to at most width bytes.
func clip(s string, width int) string {
	if width < 0 {
		return ""
	}
	if len(s) > width {
		return s[:width]
	}
	return s
}

// renderCompact is the tiny-terminal fallback: a minimal, unframed status dump
// that never overflows a small screen. It still colors status values.
func renderCompact(v View) string {
	var b strings.Builder
	b.WriteString(clearHome)
	p := v.pendingIdentity()
	switch {
	case p != nil:
		b.WriteString(sgr(sgrBoldCyan, "CryptOS PKI") + " [" + roleTag(v) + "]\n")
		b.WriteString(sgr(sgrYellow, p.title) + "\n")
		b.WriteString(p.hint + "\n")
		for _, l := range mgmtLines(v, 0) {
			b.WriteString(l.colored() + "\n")
		}
		b.WriteString(p.footer() + " " + sgr(sgrDim, version(v)) + "\n")
	case v.Maintenance:
		b.WriteString(sgr(sgrBoldCyan, "CryptOS PKI") + " [" + sgr(sgrYellow, "MAINTENANCE") + "]\n")
		b.WriteString(sgr(sgrYellow, "Awaiting configuration") + "\n")
		b.WriteString("Run: cryptosctl config apply\n")
		for _, l := range maintenanceLines(v, 0) {
			b.WriteString(l.colored() + "\n")
		}
		b.WriteString("MAINTENANCE MODE " + sgr(sgrDim, version(v)) + "\n")
	case v.Degraded:
		b.WriteString(sgr(sgrBoldCyan, "CryptOS PKI") + " [" + roleTag(v) + "]\n")
		b.WriteString("Root CA  " + v.RootCN + "\n")
		b.WriteString(sgr(sgrYellow, "degraded (reconnecting)") + "\n")
		b.WriteString(sgr(sgrBoldRed, "^R reset (destroys this CA)") + "  " + sgr(sgrDim, version(v)) + "\n")
	default:
		b.WriteString(sgr(sgrBoldCyan, "CryptOS PKI") + " [" + roleTag(v) + "]\n")
		for _, l := range fieldLines(v, 0) {
			b.WriteString(l.colored() + "\n")
		}
		b.WriteString(sgr(sgrBoldRed, "^R reset (destroys this CA)") + "  " + sgr(sgrDim, version(v)) + "\n")
	}
	return b.String()
}
