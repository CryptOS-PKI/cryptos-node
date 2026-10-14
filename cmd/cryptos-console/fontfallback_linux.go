//go:build linux

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
	"unsafe"

	"golang.org/x/sys/unix"
)

// KDFONTOP and the console_font_op layout (linux/kd.h) are not exposed by
// golang.org/x/sys/unix, so they are declared here.
const (
	kdFontOp           = 0x4B72 // KDFONTOP
	kdFontOpSetDefault = 2      // KD_FONT_OP_SET_DEFAULT
)

// consoleFontOp mirrors struct console_font_op from linux/kd.h for the
// KD_FONT_OP_SET_DEFAULT operation, where data points to the font name and
// the other fields are unused. The pad field matches the compiler-inserted
// padding before the pointer on 64-bit (amd64, arm64), the only targets this
// binary builds for.
type consoleFontOp struct {
	op        uint32
	flags     uint32
	width     uint32
	height    uint32
	charcount uint32
	pad       uint32
	data      *byte
}

// vga8x16Name is the kernel's built-in 8x16 font name (CONFIG_FONT_8x16),
// NUL-terminated as KD_FONT_OP_SET_DEFAULT expects.
var vga8x16Name = append([]byte("VGA8x16"), 0)

// kdFontSwitcher switches the console at fd to the kernel's built-in default
// font via the KDFONTOP ioctl.
type kdFontSwitcher struct{ fd int }

func (s kdFontSwitcher) setDefaultFont() error {
	op := consoleFontOp{op: kdFontOpSetDefault, data: &vga8x16Name[0]}
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(s.fd), uintptr(kdFontOp), uintptr(unsafe.Pointer(&op)))
	if errno != 0 {
		return errno
	}
	return nil
}
