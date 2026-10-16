//go:build linux

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
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/sys/unix"
)

// interfaceIndex resolves an interface name to its kernel index.
func interfaceIndex(name string) (int, error) {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	return ifc.Index, nil
}

// BringUpLoopback sets the loopback interface up.
func BringUpLoopback() error {
	return bringUpLoopback(interfaceIndex, sendAck)
}

// ConfigureInterface brings cfg.Name up, flushes any existing IPv4
// addresses, assigns its static IPv4 address, and installs the default
// route via cfg.Gateway.
func ConfigureInterface(cfg Config) error {
	return configure(cfg, interfaceIndex, sendAck, sendDump)
}

// SetLinkUp sets the named interface up.
func SetLinkUp(name string) error {
	return setLinkUp(name, interfaceIndex, sendAck)
}

// AddAddress brings the named interface up and adds the IPv4 prefix p to it,
// leaving any address it already has in place.
func AddAddress(name string, p netip.Prefix) error {
	return addAddress(name, p, interfaceIndex, sendAck)
}

// sendDump opens an AF_NETLINK route socket, sends a dump request
// (NLM_F_DUMP), and collects all response messages until NLMSG_DONE.
// Each Recvfrom call may carry multiple netlink messages; they are split
// and accumulated. An NLMSG_ERROR response with non-zero errno is
// returned as an error.
func sendDump(msg []byte) ([][]byte, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("netlink: dump socket: %w", err)
	}
	defer func() { _ = unix.Close(fd) }()

	sa := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	if err := unix.Bind(fd, sa); err != nil {
		return nil, fmt.Errorf("netlink: dump bind: %w", err)
	}
	if err := unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("netlink: dump send: %w", err)
	}

	buf := make([]byte, 4*unix.Getpagesize())
	var result [][]byte
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			return nil, fmt.Errorf("netlink: dump recv: %w", err)
		}
		data := buf[:n]
		for len(data) >= nlmsghdrLen {
			msgLen := int(native.Uint32(data[0:4]))
			if msgLen < nlmsghdrLen || msgLen > len(data) {
				break
			}
			msgType := native.Uint16(data[4:6])
			rawMsg := make([]byte, msgLen)
			copy(rawMsg, data[:msgLen])
			result = append(result, rawMsg)
			if msgType == nlmsgDone {
				return result, nil
			}
			if msgType == nlmsgError {
				if msgLen >= nlmsghdrLen+4 {
					errno := int32(native.Uint32(data[nlmsghdrLen : nlmsghdrLen+4]))
					if errno != 0 {
						return nil, fmt.Errorf("netlink: dump error: %w", syscall.Errno(-errno))
					}
				}
				return result, nil
			}
			data = data[rtaAlign(msgLen):]
		}
	}
}

// sendAck opens an AF_NETLINK route socket, sends one request, and waits
// for the kernel's ACK, returning any error the kernel reports.
func sendAck(msg []byte) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("netlink: socket: %w", err)
	}
	defer func() { _ = unix.Close(fd) }()

	sa := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	if err := unix.Bind(fd, sa); err != nil {
		return fmt.Errorf("netlink: bind: %w", err)
	}
	if err := unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("netlink: send: %w", err)
	}

	resp := make([]byte, unix.Getpagesize())
	n, _, err := unix.Recvfrom(fd, resp, 0)
	if err != nil {
		return fmt.Errorf("netlink: recv ack: %w", err)
	}
	errno, ok := parseAck(resp[:n])
	if !ok {
		return fmt.Errorf("netlink: unexpected reply (%d bytes)", n)
	}
	if errno != 0 {
		// netlink reports negative errno.
		return fmt.Errorf("netlink: kernel rejected request: %w", syscall.Errno(-errno))
	}
	return nil
}
