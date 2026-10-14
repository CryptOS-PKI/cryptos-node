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
	"log"

	"github.com/CryptOS-PKI/cryptos-node/internal/console"
)

// fontSwitcher abstracts the console font switch behind an interface so
// ensureConsoleFits is unit-tested with a fake, never the real KDFONTOP ioctl.
type fontSwitcher interface {
	// setDefaultFont switches the console tty to the kernel's built-in
	// default font (VGA8x16, CONFIG_FONT_8x16), which leaves more rows and
	// columns than the prod cmdline's TER16x32 on the same framebuffer.
	setDefaultFont() error
}

// ensureConsoleFits requests the kernel's built-in 8x16 font when cols x rows
// is below the floor the dashboard needs to drop out of its compact render
// (console.NeedsCompact), then re-reads the size with readSize so the caller
// draws at whatever the switch produced. A switch failure is logged and the
// original size is kept unchanged; the compact view still runs at that size.
func ensureConsoleFits(sw fontSwitcher, readSize func() (cols, rows int), cols, rows int) (int, int) {
	if !console.NeedsCompact(cols, rows) {
		return cols, rows
	}
	if err := sw.setDefaultFont(); err != nil {
		log.Printf("console: font: %dx%d is below the compact floor; VGA8x16 fallback failed: %v", cols, rows, err)
		return cols, rows
	}
	newCols, newRows := readSize()
	log.Printf("console: font: %dx%d was below the compact floor; switched to VGA8x16, now %dx%d", cols, rows, newCols, newRows)
	return newCols, newRows
}
