package ukisign

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
	"bytes"
	"fmt"
)

// AnchorName is the path of the anchor certificate inside the appended
// initramfs archive. The kernel unpacks it as /upgrade-anchor.der, where
// cryptos-switchroot reads it.
const AnchorName = "upgrade-anchor.der"

// anchorArchive is an uncompressed newc cpio archive holding der as the
// read-only regular file AnchorName, owned by root, with a zero mtime so the
// same certificate always gives the same bytes. Its length is a multiple of
// 4, as every newc entry is padded to 4 bytes.
func anchorArchive(der []byte) []byte {
	var b bytes.Buffer
	newcEntry(&b, 1, 0o100444, AnchorName, der)
	newcEntry(&b, 0, 0, "TRAILER!!!", nil)

	return b.Bytes()
}

// newcEntry writes one newc ("070701") header, name and data, each padded to
// a 4-byte boundary of the archive.
func newcEntry(b *bytes.Buffer, ino, mode uint32, name string, data []byte) {
	// Fields: ino, mode, uid, gid, nlink, mtime, filesize, devmajor,
	// devminor, rdevmajor, rdevminor, namesize (with its NUL), check.
	fmt.Fprintf(b, "070701%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X",
		ino, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name)+1, 0)
	b.WriteString(name)
	b.WriteByte(0)
	pad4(b)
	b.Write(data)
	pad4(b)
}

func pad4(b *bytes.Buffer) {
	for b.Len()%4 != 0 {
		b.WriteByte(0)
	}
}
