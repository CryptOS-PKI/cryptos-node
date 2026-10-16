package netlink

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
	"errors"
	"fmt"
	"net/netip"
	"syscall"
	"testing"
)

func TestRTAAlign(t *testing.T) {
	cases := map[int]int{0: 0, 1: 4, 4: 4, 5: 8, 8: 8}
	for in, want := range cases {
		if got := rtaAlign(in); got != want {
			t.Errorf("rtaAlign(%d) = %d, want %d", in, got, want)
		}
	}
}

func TestAttr(t *testing.T) {
	a := attr(ifaLocal, []byte{10, 0, 0, 10})
	if len(a) != 8 {
		t.Fatalf("attr len = %d, want 8 (4 hdr + 4 data)", len(a))
	}
	if got := native.Uint16(a[0:2]); got != 8 {
		t.Errorf("rta_len = %d, want 8", got)
	}
	if got := native.Uint16(a[2:4]); got != ifaLocal {
		t.Errorf("rta_type = %d, want %d", got, ifaLocal)
	}
	// Data with padding: 3-byte value -> rta_len 7, buffer padded to 8.
	p := attr(rtaOif, []byte{1, 2, 3})
	if len(p) != 8 {
		t.Errorf("padded attr len = %d, want 8", len(p))
	}
	if got := native.Uint16(p[0:2]); got != 7 {
		t.Errorf("padded rta_len = %d, want 7 (unpadded)", got)
	}
}

func TestBuildLinkUpRequest(t *testing.T) {
	msg := buildLinkUpRequest(1, 7)
	if len(msg) != nlmsghdrLen+ifinfomsgLen {
		t.Fatalf("len = %d, want %d", len(msg), nlmsghdrLen+ifinfomsgLen)
	}
	if native.Uint32(msg[0:4]) != uint32(len(msg)) {
		t.Error("nlmsg_len mismatch")
	}
	if native.Uint16(msg[4:6]) != rtmNewLink {
		t.Error("nlmsg_type != RTM_NEWLINK")
	}
	if native.Uint16(msg[6:8]) != (nlmFRequest | nlmFAck) {
		t.Error("flags != REQUEST|ACK")
	}
	body := msg[nlmsghdrLen:]
	if native.Uint32(body[4:8]) != 7 {
		t.Error("ifi_index != 7")
	}
	if native.Uint32(body[8:12]) != iffUp {
		t.Error("ifi_flags != IFF_UP")
	}
	if native.Uint32(body[12:16]) != iffUp {
		t.Error("ifi_change != IFF_UP")
	}
}

func TestBuildAddrRequest(t *testing.T) {
	p := netip.MustParsePrefix("10.0.0.10/24")
	msg := buildAddrRequest(2, 7, p)
	// 16 (nlmsghdr) + 8 (ifaddrmsg) + 8 (IFA_LOCAL) + 8 (IFA_ADDRESS).
	if len(msg) != 40 {
		t.Fatalf("len = %d, want 40", len(msg))
	}
	if native.Uint16(msg[4:6]) != rtmNewAddr {
		t.Error("type != RTM_NEWADDR")
	}
	if native.Uint16(msg[6:8]) != (nlmFRequest | nlmFAck | nlmFCreate | nlmFReplace) {
		t.Error("flags mismatch")
	}
	body := msg[nlmsghdrLen:]
	if body[0] != afInet {
		t.Error("ifa_family != AF_INET")
	}
	if body[1] != 24 {
		t.Errorf("ifa_prefixlen = %d, want 24", body[1])
	}
	if native.Uint32(body[4:8]) != 7 {
		t.Error("ifa_index != 7")
	}
	// First attr: IFA_LOCAL = 10.0.0.10
	a1 := body[ifaddrmsgLen:]
	if native.Uint16(a1[2:4]) != ifaLocal {
		t.Error("first attr type != IFA_LOCAL")
	}
	if got := [4]byte{a1[4], a1[5], a1[6], a1[7]}; got != [4]byte{10, 0, 0, 10} {
		t.Errorf("IFA_LOCAL addr = %v, want 10.0.0.10", got)
	}
	// Second attr: IFA_ADDRESS
	a2 := a1[8:]
	if native.Uint16(a2[2:4]) != ifaAddress {
		t.Error("second attr type != IFA_ADDRESS")
	}
}

func TestBuildDefaultRouteRequest(t *testing.T) {
	gw := netip.MustParseAddr("10.0.0.1")
	msg := buildDefaultRouteRequest(3, 7, gw)
	// 16 + 12 (rtmsg) + 8 (RTA_GATEWAY) + 8 (RTA_OIF).
	if len(msg) != 44 {
		t.Fatalf("len = %d, want 44", len(msg))
	}
	if native.Uint16(msg[4:6]) != rtmNewRoute {
		t.Error("type != RTM_NEWROUTE")
	}
	if native.Uint16(msg[6:8]) != (nlmFRequest | nlmFAck | nlmFCreate | nlmFReplace) {
		t.Error("flags mismatch")
	}
	body := msg[nlmsghdrLen:]
	if body[0] != afInet {
		t.Error("rtm_family != AF_INET")
	}
	if body[1] != 0 {
		t.Error("rtm_dst_len != 0 (default route)")
	}
	if body[4] != rtTableMain || body[7] != rtnUnicast {
		t.Error("rtm table/type mismatch")
	}
	a1 := body[rtmsgLen:]
	if native.Uint16(a1[2:4]) != rtaGateway {
		t.Error("first attr != RTA_GATEWAY")
	}
	if got := [4]byte{a1[4], a1[5], a1[6], a1[7]}; got != [4]byte{10, 0, 0, 1} {
		t.Errorf("gateway = %v, want 10.0.0.1", got)
	}
	a2 := a1[8:]
	if native.Uint16(a2[2:4]) != rtaOif {
		t.Error("second attr != RTA_OIF")
	}
	if native.Uint32(a2[4:8]) != 7 {
		t.Error("RTA_OIF index != 7")
	}
}

func TestParseAck(t *testing.T) {
	// Success: NLMSG_ERROR with errno 0.
	ok := make([]byte, nlmsghdrLen+4)
	native.PutUint16(ok[4:6], nlmsgError)
	if errno, found := parseAck(ok); !found || errno != 0 {
		t.Errorf("parseAck(success) = (%d,%v), want (0,true)", errno, found)
	}
	// Failure: errno -17 (-EEXIST).
	fail := make([]byte, nlmsghdrLen+4)
	native.PutUint16(fail[4:6], nlmsgError)
	var negErr int32 = -17
	native.PutUint32(fail[nlmsghdrLen:], uint32(negErr))
	if errno, found := parseAck(fail); !found || errno != -17 {
		t.Errorf("parseAck(fail) = (%d,%v), want (-17,true)", errno, found)
	}
	// Not an ERROR message (type 0 != NLMSG_ERROR).
	if _, found := parseAck(make([]byte, nlmsghdrLen+4)); found {
		t.Error("parseAck(non-error type) should not be ok")
	}
	if _, found := parseAck([]byte{1, 2}); found {
		t.Error("parseAck(short) should not be ok")
	}
}

// fakeNetlink records the requests configure/bringUpLoopback would send.
type fakeNetlink struct {
	indexByName map[string]int
	indexErr    error
	sent        [][]byte
	sendErr     error
	dumpMsgs    [][]byte
	dumpErr     error
}

func (f *fakeNetlink) index(name string) (int, error) {
	if f.indexErr != nil {
		return 0, f.indexErr
	}
	return f.indexByName[name], nil
}

func (f *fakeNetlink) send(msg []byte) error {
	f.sent = append(f.sent, msg)
	return f.sendErr
}

func (f *fakeNetlink) dump(_ []byte) ([][]byte, error) {
	return f.dumpMsgs, f.dumpErr
}

// noDump is a dumpFunc that returns an empty result — used by tests that
// only care about link-up / addr / route sequencing without preexisting addrs.
func noDump(_ []byte) ([][]byte, error) { return nil, nil }

func TestConfigure_SequenceAndOrder(t *testing.T) {
	f := &fakeNetlink{indexByName: map[string]int{"eth0": 3}}
	cfg := Config{
		Name:    "eth0",
		Address: netip.MustParsePrefix("10.0.0.10/24"),
		Gateway: netip.MustParseAddr("10.0.0.1"),
	}
	if err := configure(cfg, f.index, f.send, noDump); err != nil {
		t.Fatalf("configure: %v", err)
	}
	// link-up, NEWADDR, NEWROUTE — no existing addrs so no DELADDRs.
	if len(f.sent) != 3 {
		t.Fatalf("sent %d requests, want 3 (link up, addr, route)", len(f.sent))
	}
	types := []uint16{rtmNewLink, rtmNewAddr, rtmNewRoute}
	for i, want := range types {
		if got := native.Uint16(f.sent[i][4:6]); got != want {
			t.Errorf("request[%d] type = %d, want %d", i, got, want)
		}
	}
}

func TestConfigure_NoGatewaySkipsRoute(t *testing.T) {
	f := &fakeNetlink{indexByName: map[string]int{"eth0": 3}}
	cfg := Config{Name: "eth0", Address: netip.MustParsePrefix("10.0.0.10/24")}
	if err := configure(cfg, f.index, f.send, noDump); err != nil {
		t.Fatalf("configure: %v", err)
	}
	if len(f.sent) != 2 {
		t.Errorf("sent %d, want 2 (no gateway => no route)", len(f.sent))
	}
}

func TestConfigure_Errors(t *testing.T) {
	good := Config{Name: "eth0", Address: netip.MustParsePrefix("10.0.0.10/24")}

	if err := configure(Config{}, (&fakeNetlink{}).index, (&fakeNetlink{}).send, noDump); err == nil {
		t.Error("empty config should error")
	}
	// index lookup failure.
	f := &fakeNetlink{indexErr: errors.New("no such device")}
	if err := configure(good, f.index, f.send, noDump); err == nil {
		t.Error("index error should propagate")
	}
	// send failure on the first (link-up) request aborts.
	f2 := &fakeNetlink{indexByName: map[string]int{"eth0": 3}, sendErr: errors.New("boom")}
	if err := configure(good, f2.index, f2.send, noDump); err == nil {
		t.Error("send error should propagate")
	}
	if len(f2.sent) != 1 {
		t.Errorf("after first send failure, sent = %d, want 1 (aborts)", len(f2.sent))
	}
}

func TestBringUpLoopback_Builds(t *testing.T) {
	f := &fakeNetlink{indexByName: map[string]int{"lo": 1}}
	if err := bringUpLoopback(f.index, f.send); err != nil {
		t.Fatalf("bringUpLoopback: %v", err)
	}
	if len(f.sent) != 1 || native.Uint16(f.sent[0][4:6]) != rtmNewLink {
		t.Error("loopback should send one RTM_NEWLINK")
	}
}

func TestSetLinkUp_SendsOneNewLink(t *testing.T) {
	f := &fakeNetlink{indexByName: map[string]int{"eth0": 3}}
	if err := setLinkUp("eth0", f.index, f.send); err != nil {
		t.Fatalf("setLinkUp: %v", err)
	}
	if len(f.sent) != 1 || native.Uint16(f.sent[0][4:6]) != rtmNewLink {
		t.Fatalf("sent %d requests, want one RTM_NEWLINK", len(f.sent))
	}
	if native.Uint32(f.sent[0][nlmsghdrLen+4:nlmsghdrLen+8]) != 3 {
		t.Error("ifi_index != 3")
	}
}

// A self-assigned link-local address is added beside whatever the interface
// has: no flush, no dump, no default route.
func TestAddAddress_LinkUpThenAddrOnly(t *testing.T) {
	f := &fakeNetlink{indexByName: map[string]int{"eth0": 3}}
	p := netip.MustParsePrefix("169.254.12.34/16")
	if err := addAddress("eth0", p, f.index, f.send); err != nil {
		t.Fatalf("addAddress: %v", err)
	}
	if len(f.sent) != 2 {
		t.Fatalf("sent %d requests, want 2 (link up, addr)", len(f.sent))
	}
	for i, want := range []uint16{rtmNewLink, rtmNewAddr} {
		if got := native.Uint16(f.sent[i][4:6]); got != want {
			t.Errorf("request[%d] type = %d, want %d", i, got, want)
		}
	}
	body := f.sent[1][nlmsghdrLen:]
	if body[1] != 16 {
		t.Errorf("prefixlen = %d, want 16", body[1])
	}
}

func TestAddAddress_Errors(t *testing.T) {
	f := &fakeNetlink{indexByName: map[string]int{"eth0": 3}}
	if err := addAddress("eth0", netip.MustParsePrefix("fe80::1/64"), f.index, f.send); err == nil {
		t.Error("IPv6 prefix should error")
	}
	if err := addAddress("eth0", netip.Prefix{}, f.index, f.send); err == nil {
		t.Error("zero prefix should error")
	}
	if len(f.sent) != 0 {
		t.Errorf("invalid prefix still sent %d requests", len(f.sent))
	}
	fi := &fakeNetlink{indexErr: errors.New("no such device")}
	if err := addAddress("eth0", netip.MustParsePrefix("169.254.1.1/16"), fi.index, fi.send); err == nil {
		t.Error("index error should propagate")
	}
	fs := &fakeNetlink{indexByName: map[string]int{"eth0": 3}, sendErr: errors.New("boom")}
	if err := addAddress("eth0", netip.MustParsePrefix("169.254.1.1/16"), fs.index, fs.send); err == nil {
		t.Error("send error should propagate")
	}
	if len(fs.sent) != 1 {
		t.Errorf("after link-up failure, sent = %d, want 1 (aborts)", len(fs.sent))
	}
}

// buildFakeAddrMsg assembles a minimal RTM_NEWADDR netlink message for
// ifIndex with the given IPv4 prefix. Used to seed parseAddrMessages tests
// and the configure flush tests.
func buildFakeAddrMsg(ifIndex int, p netip.Prefix) []byte {
	addr := p.Addr().As4()
	body := make([]byte, ifaddrmsgLen)
	body[0] = afInet
	body[1] = byte(p.Bits())
	body[2] = 0
	body[3] = rtScopeUniverse
	native.PutUint32(body[4:8], uint32(int32(ifIndex)))
	body = append(body, attr(ifaLocal, addr[:])...)
	return frame(rtmNewAddr, nlmFRequest, 0, body)
}

// buildFakeDoneMsg assembles an NLMSG_DONE message.
func buildFakeDoneMsg() []byte {
	return frame(nlmsgDone, 0, 0, make([]byte, 4))
}

// ---- message builder unit tests ----

func TestBuildAddrDumpRequest(t *testing.T) {
	msg := buildAddrDumpRequest(5)
	if len(msg) < nlmsghdrLen+ifaddrmsgLen {
		t.Fatalf("too short: %d", len(msg))
	}
	if native.Uint16(msg[4:6]) != rtmGetAddr {
		t.Errorf("type = %d, want RTM_GETADDR (%d)", native.Uint16(msg[4:6]), rtmGetAddr)
	}
	if native.Uint16(msg[6:8]) != (nlmFRequest | nlmFDump) {
		t.Errorf("flags = %#x, want REQUEST|DUMP (%#x)", native.Uint16(msg[6:8]), nlmFRequest|nlmFDump)
	}
	body := msg[nlmsghdrLen:]
	if body[0] != afInet {
		t.Errorf("ifa_family = %d, want AF_INET (%d)", body[0], afInet)
	}
}

func TestBuildAddrDelRequest(t *testing.T) {
	p := netip.MustParsePrefix("192.168.1.50/24")
	msg := buildAddrDelRequest(7, 5, p)
	if native.Uint16(msg[4:6]) != rtmDelAddr {
		t.Errorf("type = %d, want RTM_DELADDR (%d)", native.Uint16(msg[4:6]), rtmDelAddr)
	}
	if native.Uint16(msg[6:8]) != (nlmFRequest | nlmFAck) {
		t.Errorf("flags = %#x, want REQUEST|ACK", native.Uint16(msg[6:8]))
	}
	body := msg[nlmsghdrLen:]
	if body[0] != afInet {
		t.Errorf("ifa_family = %d, want AF_INET", body[0])
	}
	if body[1] != 24 {
		t.Errorf("ifa_prefixlen = %d, want 24", body[1])
	}
	if native.Uint32(body[4:8]) != 5 {
		t.Errorf("ifa_index = %d, want 5", native.Uint32(body[4:8]))
	}
	// First attr must be IFA_LOCAL with the address.
	a1 := body[ifaddrmsgLen:]
	if native.Uint16(a1[2:4]) != ifaLocal {
		t.Errorf("first attr type = %d, want IFA_LOCAL (%d)", native.Uint16(a1[2:4]), ifaLocal)
	}
	if got := [4]byte{a1[4], a1[5], a1[6], a1[7]}; got != [4]byte{192, 168, 1, 50} {
		t.Errorf("IFA_LOCAL = %v, want 192.168.1.50", got)
	}
}

func TestParseAddrMessages(t *testing.T) {
	// Two addrs on ifIndex=3, one on a different index, one IPv6-family (zero family), NLMSG_DONE.
	addr1 := netip.MustParsePrefix("10.0.0.10/24")
	addr2 := netip.MustParsePrefix("192.168.5.1/16")
	otherIdx := netip.MustParsePrefix("198.51.100.1/24")

	// Build a fake IPv6 message: same index but family != AF_INET.
	ipv6Body := make([]byte, ifaddrmsgLen)
	ipv6Body[0] = 10 // AF_INET6
	ipv6Body[1] = 64
	native.PutUint32(ipv6Body[4:8], 3) // same ifIndex
	ipv6Msg := frame(rtmNewAddr, 0, 0, ipv6Body)

	msgs := [][]byte{
		buildFakeAddrMsg(3, addr1),
		buildFakeAddrMsg(3, addr2),
		buildFakeAddrMsg(7, otherIdx), // different ifIndex
		ipv6Msg,
		buildFakeDoneMsg(),
	}

	got, err := parseAddrMessages(msgs, 3)
	if err != nil {
		t.Fatalf("parseAddrMessages: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d prefixes, want 2", len(got))
	}
	// Results should include addr1 and addr2 (order matches input).
	wantSet := map[string]bool{addr1.String(): true, addr2.String(): true}
	for _, p := range got {
		if !wantSet[p.String()] {
			t.Errorf("unexpected prefix %s", p)
		}
	}
}

// ---- configure flow tests covering the flush path ----

func TestConfigure_FlushThenStaticAddr(t *testing.T) {
	// dump returns two existing addresses on the interface.
	p1 := netip.MustParsePrefix("192.168.1.10/24")
	p2 := netip.MustParsePrefix("10.5.5.5/8")
	dumpMsgs := [][]byte{
		buildFakeAddrMsg(3, p1),
		buildFakeAddrMsg(3, p2),
		buildFakeDoneMsg(),
	}
	f := &fakeNetlink{
		indexByName: map[string]int{"eth0": 3},
		dumpMsgs:    dumpMsgs,
	}
	cfg := Config{
		Name:    "eth0",
		Address: netip.MustParsePrefix("10.0.0.10/24"),
		Gateway: netip.MustParseAddr("10.0.0.1"),
	}
	if err := configure(cfg, f.index, f.send, f.dump); err != nil {
		t.Fatalf("configure: %v", err)
	}
	// Expected: link-up, DELADDR(p1), DELADDR(p2), NEWADDR(static), NEWROUTE.
	if len(f.sent) != 5 {
		t.Fatalf("sent %d requests, want 5 (link-up, del×2, addr, route)", len(f.sent))
	}
	wantTypes := []uint16{rtmNewLink, rtmDelAddr, rtmDelAddr, rtmNewAddr, rtmNewRoute}
	for i, want := range wantTypes {
		if got := native.Uint16(f.sent[i][4:6]); got != want {
			t.Errorf("request[%d] type = %d, want %d", i, got, want)
		}
	}
}

func TestConfigure_NoExistingAddrs(t *testing.T) {
	// dump returns only NLMSG_DONE — no existing addresses.
	f := &fakeNetlink{
		indexByName: map[string]int{"eth0": 3},
		dumpMsgs:    [][]byte{buildFakeDoneMsg()},
	}
	cfg := Config{Name: "eth0", Address: netip.MustParsePrefix("10.0.0.10/24")}
	if err := configure(cfg, f.index, f.send, f.dump); err != nil {
		t.Fatalf("configure: %v", err)
	}
	// No DELADDRs emitted: only link-up and NEWADDR.
	if len(f.sent) != 2 {
		t.Fatalf("sent %d requests, want 2 (no existing addrs)", len(f.sent))
	}
	if native.Uint16(f.sent[0][4:6]) != rtmNewLink {
		t.Error("first request should be RTM_NEWLINK")
	}
	if native.Uint16(f.sent[1][4:6]) != rtmNewAddr {
		t.Error("second request should be RTM_NEWADDR")
	}
}

func TestConfigure_EADDRNOTAVAILSkipped(t *testing.T) {
	// dump returns one address but the delete returns EADDRNOTAVAIL — flow
	// must still complete without error.
	p1 := netip.MustParsePrefix("192.168.1.10/24")
	dumpMsgs := [][]byte{buildFakeAddrMsg(3, p1), buildFakeDoneMsg()}

	// sendErr causes the DELADDR to fail; we override with a per-call error.
	// The DELADDR fails with EADDRNOTAVAIL (wrapped in a syscall.Errno so
	// isAddrNotFound recognises it); configure must skip it and still add the
	// static address.
	callCount := 0
	var capturedSent [][]byte
	fakeSend := func(msg []byte) error {
		capturedSent = append(capturedSent, msg)
		callCount++
		if callCount == 2 { // link-up=1, DELADDR=2
			return fmt.Errorf("netlink: kernel rejected request: %w", syscall.EADDRNOTAVAIL)
		}
		return nil
	}

	f := &fakeNetlink{
		indexByName: map[string]int{"eth0": 3},
		dumpMsgs:    dumpMsgs,
	}
	cfg := Config{Name: "eth0", Address: netip.MustParsePrefix("10.0.0.10/24")}
	if err := configure(cfg, f.index, fakeSend, f.dump); err != nil {
		t.Fatalf("configure returned error on EADDRNOTAVAIL: %v", err)
	}
	// link-up, DELADDR (skipped), NEWADDR — 3 total (DELADDR still sent, just error ignored).
	if len(capturedSent) != 3 {
		t.Fatalf("sent %d messages, want 3 (link-up, del-skipped, addr)", len(capturedSent))
	}
	if got := native.Uint16(capturedSent[2][4:6]); got != rtmNewAddr {
		t.Errorf("after a skipped DELADDR, message[2] type = %d, want RTM_NEWADDR(%d)", got, rtmNewAddr)
	}
}
