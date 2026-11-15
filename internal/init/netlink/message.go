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
	"encoding/binary"
	"net/netip"
)

// rtnetlink ABI constants (stable Linux kernel values). Defined locally
// so the message builders — the fiddly, bug-prone part — are
// OS-independent and unit-testable on any host. The actual AF_NETLINK
// socket I/O lives in the linux-tagged file.
const (
	rtmNewLink  = 16 // RTM_NEWLINK
	rtmNewAddr  = 20 // RTM_NEWADDR
	rtmDelAddr  = 21 // RTM_DELADDR
	rtmGetAddr  = 22 // RTM_GETADDR
	rtmNewRoute = 24 // RTM_NEWROUTE

	nlmFRequest = 0x001 // NLM_F_REQUEST
	nlmFAck     = 0x004 // NLM_F_ACK
	nlmFDump    = 0x300 // NLM_F_ROOT|NLM_F_MATCH (dump)
	nlmFReplace = 0x100 // NLM_F_REPLACE
	nlmFCreate  = 0x400 // NLM_F_CREATE

	nlmsgError = 0x2 // NLMSG_ERROR
	nlmsgDone  = 0x3 // NLMSG_DONE

	iffUp = 0x1 // IFF_UP

	ifaLocal   = 2 // IFA_LOCAL
	ifaAddress = 1 // IFA_ADDRESS

	rtaGateway = 5 // RTA_GATEWAY
	rtaOif     = 4 // RTA_OIF

	rtnUnicast      = 1   // RTN_UNICAST
	rtProtBoot      = 3   // RTPROT_BOOT
	rtScopeUniverse = 0   // RT_SCOPE_UNIVERSE
	rtTableMain     = 254 // RT_TABLE_MAIN

	afUnspec = 0 // AF_UNSPEC
	afInet   = 2 // AF_INET

	nlmsghdrLen  = 16 // sizeof(struct nlmsghdr)
	ifinfomsgLen = 16 // sizeof(struct ifinfomsg)
	ifaddrmsgLen = 8  // sizeof(struct ifaddrmsg)
	rtmsgLen     = 12 // sizeof(struct rtmsg)
	rtattrHdrLen = 4  // sizeof(struct rtattr)
)

// native is the host byte order; netlink uses host endianness on the wire.
var native = binary.NativeEndian

// rtaAlign rounds n up to the 4-byte rtattr/netlink alignment.
func rtaAlign(n int) int { return (n + 3) &^ 3 }

// attr encodes a single rtattr TLV: a 4-byte header (len, type) followed
// by data, padded to the 4-byte alignment. The length field counts the
// header + data but not the trailing padding (kernel convention).
func attr(typ uint16, data []byte) []byte {
	l := rtattrHdrLen + len(data)
	buf := make([]byte, rtaAlign(l))
	native.PutUint16(buf[0:2], uint16(l)) //nolint:gosec // G115: an rtattr carries a few bytes of payload; its length is 16 bits on the wire
	native.PutUint16(buf[2:4], typ)
	copy(buf[4:], data)
	return buf
}

// frame prepends an nlmsghdr to body and sets the total length. seq is
// the request sequence number; pid is left 0 (kernel).
func frame(msgType, flags uint16, seq uint32, body []byte) []byte {
	buf := make([]byte, nlmsghdrLen+len(body))
	native.PutUint32(buf[0:4], uint32(len(buf))) //nolint:gosec // G115: a netlink message here is a few dozen bytes; its length is 32 bits on the wire
	native.PutUint16(buf[4:6], msgType)
	native.PutUint16(buf[6:8], flags)
	native.PutUint32(buf[8:12], seq)
	native.PutUint32(buf[12:16], 0)
	copy(buf[nlmsghdrLen:], body)
	return buf
}

// buildLinkUpRequest builds an RTM_NEWLINK message that sets IFF_UP on
// the interface at ifIndex.
func buildLinkUpRequest(seq uint32, ifIndex int) []byte {
	body := make([]byte, ifinfomsgLen)
	body[0] = afUnspec
	// [1] pad, [2:4] type — left zero.
	//nolint:gosec // G115: ifIndex is a kernel interface index, a positive int32; the field carries its bits
	native.PutUint32(body[4:8], uint32(int32(ifIndex))) // ifi_index
	native.PutUint32(body[8:12], iffUp)                 // ifi_flags
	native.PutUint32(body[12:16], iffUp)                // ifi_change
	return frame(rtmNewLink, nlmFRequest|nlmFAck, seq, body)
}

// buildAddrRequest builds an RTM_NEWADDR message assigning p to ifIndex.
func buildAddrRequest(seq uint32, ifIndex int, p netip.Prefix) []byte {
	addr := p.Addr().As4()
	body := make([]byte, ifaddrmsgLen)
	body[0] = afInet // ifa_family
	//nolint:gosec // G115: an IPv4 prefix length is 0 to 32
	body[1] = byte(p.Bits())  // ifa_prefixlen
	body[2] = 0               // ifa_flags
	body[3] = rtScopeUniverse // ifa_scope
	//nolint:gosec // G115: ifIndex is a kernel interface index, a positive int32; the field carries its bits
	native.PutUint32(body[4:8], uint32(int32(ifIndex))) // ifa_index
	body = append(body, attr(ifaLocal, addr[:])...)
	body = append(body, attr(ifaAddress, addr[:])...)
	return frame(rtmNewAddr, nlmFRequest|nlmFAck|nlmFCreate|nlmFReplace, seq, body)
}

// buildDefaultRouteRequest builds an RTM_NEWROUTE message adding a
// default route (0.0.0.0/0) via gw out of ifIndex.
func buildDefaultRouteRequest(seq uint32, ifIndex int, gw netip.Addr) []byte {
	g := gw.As4()
	body := make([]byte, rtmsgLen)
	body[0] = afInet          // rtm_family
	body[1] = 0               // rtm_dst_len (0 => default route)
	body[4] = rtTableMain     // rtm_table
	body[5] = rtProtBoot      // rtm_protocol
	body[6] = rtScopeUniverse // rtm_scope
	body[7] = rtnUnicast      // rtm_type
	body = append(body, attr(rtaGateway, g[:])...)
	oif := make([]byte, 4)
	native.PutUint32(oif, uint32(int32(ifIndex))) //nolint:gosec // G115: ifIndex is a kernel interface index, a positive int32; the field carries its bits
	body = append(body, attr(rtaOif, oif)...)
	// Use NLM_F_REPLACE so init is authoritative over the default route even when
	// the kernel's ip=dhcp autoconfig has already installed one; without REPLACE
	// the kernel returns EEXIST and init boot-loops on the installed path.
	return frame(rtmNewRoute, nlmFRequest|nlmFAck|nlmFCreate|nlmFReplace, seq, body)
}

// buildAddrDumpRequest builds an RTM_GETADDR dump request that asks the
// kernel to enumerate all IPv4 addresses (ifa_family = AF_INET; all
// interfaces). The caller filters by ifIndex via parseAddrMessages.
func buildAddrDumpRequest(seq uint32) []byte {
	body := make([]byte, ifaddrmsgLen)
	body[0] = afInet // ifa_family — filter to IPv4
	// remaining fields (prefixlen, flags, scope, index) left zero.
	return frame(rtmGetAddr, nlmFRequest|nlmFDump, seq, body)
}

// buildAddrDelRequest builds an RTM_DELADDR message that removes prefix p
// from the interface at ifIndex. The ifaddrmsg body mirrors buildAddrRequest.
func buildAddrDelRequest(seq uint32, ifIndex int, p netip.Prefix) []byte {
	addr := p.Addr().As4()
	body := make([]byte, ifaddrmsgLen)
	body[0] = afInet // ifa_family
	//nolint:gosec // G115: an IPv4 prefix length is 0 to 32
	body[1] = byte(p.Bits())  // ifa_prefixlen
	body[2] = 0               // ifa_flags
	body[3] = rtScopeUniverse // ifa_scope
	//nolint:gosec // G115: ifIndex is a kernel interface index, a positive int32; the field carries its bits
	native.PutUint32(body[4:8], uint32(int32(ifIndex))) // ifa_index
	body = append(body, attr(ifaLocal, addr[:])...)
	body = append(body, attr(ifaAddress, addr[:])...)
	return frame(rtmDelAddr, nlmFRequest|nlmFAck, seq, body)
}

// parseAddrMessages walks raw netlink messages returned by a RTM_GETADDR
// dump and returns the IPv4 prefixes assigned to ifIndex. NLMSG_DONE and
// other message types are silently skipped. Non-AF_INET and non-matching
// ifIndex entries are ignored.
func parseAddrMessages(msgs [][]byte, ifIndex int) ([]netip.Prefix, error) {
	var result []netip.Prefix
	for _, msg := range msgs {
		if len(msg) < nlmsghdrLen {
			continue
		}
		msgType := native.Uint16(msg[4:6])
		if msgType == nlmsgDone {
			continue
		}
		if msgType != rtmNewAddr {
			continue
		}
		if len(msg) < nlmsghdrLen+ifaddrmsgLen {
			continue
		}
		ifa := msg[nlmsghdrLen : nlmsghdrLen+ifaddrmsgLen]
		family := ifa[0]
		prefixLen := ifa[1]
		idx := int(int32(native.Uint32(ifa[4:8]))) //nolint:gosec // G115: the wire field is a signed int32, so the bits are reinterpreted
		if family != afInet || idx != ifIndex {
			continue
		}

		// Walk rtattrs after the ifaddrmsg to find IFA_LOCAL (preferred) or
		// IFA_ADDRESS (fallback). Both carry a 4-byte IPv4 address.
		attrs := msg[nlmsghdrLen+ifaddrmsgLen:]
		var localAddr, addrAddr [4]byte
		var hasLocal, hasAddr bool
		for len(attrs) >= rtattrHdrLen {
			rtaLen := int(native.Uint16(attrs[0:2]))
			if rtaLen < rtattrHdrLen || rtaLen > len(attrs) {
				break
			}
			rtaType := native.Uint16(attrs[2:4])
			dataLen := rtaLen - rtattrHdrLen
			if rtaType == ifaLocal && dataLen == 4 {
				copy(localAddr[:], attrs[rtattrHdrLen:rtaLen])
				hasLocal = true
			} else if rtaType == ifaAddress && dataLen == 4 {
				copy(addrAddr[:], attrs[rtattrHdrLen:rtaLen])
				hasAddr = true
			}
			attrs = attrs[rtaAlign(rtaLen):]
		}

		var raw [4]byte
		switch {
		case hasLocal:
			raw = localAddr
		case hasAddr:
			raw = addrAddr
		default:
			continue // no usable address attr
		}
		a, ok := netip.AddrFromSlice(raw[:])
		if !ok {
			continue
		}
		// AddrFromSlice on 4 bytes yields an IPv4-in-IPv6 form; unmap to pure
		// IPv4 so these prefixes match the rest of the codebase's addrs.
		result = append(result, netip.PrefixFrom(a.Unmap(), int(prefixLen)))
	}
	return result, nil
}

// parseAck interprets a kernel reply to an NLM_F_ACK request. A reply of
// type NLMSG_ERROR carries an int32 errno: 0 means success. Returns the
// errno (0 on success) and whether a well-formed ACK/ERROR was found.
func parseAck(resp []byte) (errno int32, ok bool) {
	if len(resp) < nlmsghdrLen {
		return 0, false
	}
	msgType := native.Uint16(resp[4:6])
	if msgType != nlmsgError {
		return 0, false
	}
	if len(resp) < nlmsghdrLen+4 {
		return 0, false
	}
	return int32(native.Uint32(resp[nlmsghdrLen : nlmsghdrLen+4])), true //nolint:gosec // G115: the wire field is a signed int32, so the bits are reinterpreted
}
