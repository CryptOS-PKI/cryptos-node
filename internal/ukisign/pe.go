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
	"debug/pe"
	"encoding/binary"
	"fmt"
)

// PE/COFF layout constants (Microsoft PE format specification).
const (
	coffHeaderSize    = 20
	sectionHeaderSize = 40
	magicPE32         = 0x10b
	magicPE32Plus     = 0x20b
	dirSecurity       = 4
	scnInitData       = 0x00000040
	certRevision      = 0x0200
	certTypePKCS      = 0x0002
	certAlign         = 8
	maxImage          = 1<<32 - 1
)

// peSection is one section header, with the file offset of the header so it
// can be rewritten in place.
type peSection struct {
	name    string
	hdrOff  int
	vsize   uint32
	va      uint32
	rawSize uint32
	rawPtr  uint32
	chars   uint32
}

// extent is the section's size in memory. A zero VirtualSize means the raw
// size, as the loader reads it.
func (s peSection) extent() uint32 {
	if s.vsize == 0 {
		return s.rawSize
	}

	return s.vsize
}

// peImage is a parsed PE image: the offsets of every header field this
// package reads or writes, and the section table.
type peImage struct {
	data          []byte
	coffOff       int
	optOff        int
	sizeOfHeaders uint32
	sectionAlign  uint32
	fileAlign     uint32
	checksumOff   int
	sizeOfImgOff  int
	initDataOff   int
	entryPoint    uint32
	dirOff        int
	numDirs       uint32
	sections      []peSection
}

// secDirOff is the file offset of the security (certificate table) data
// directory entry.
func (p *peImage) secDirOff() int { return p.dirOff + dirSecurity*8 }

// certTable returns the certificate table's file offset and size, zero when
// the image carries none.
func (p *peImage) certTable() (uint32, uint32) {
	off := p.secDirOff()

	return binary.LittleEndian.Uint32(p.data[off:]), binary.LittleEndian.Uint32(p.data[off+4:])
}

// rawEnd is the end of the last section's raw data in the file.
func (p *peImage) rawEnd() uint32 {
	end := p.sizeOfHeaders
	for _, s := range p.sections {
		if s.rawSize > 0 && s.rawPtr+s.rawSize > end {
			end = s.rawPtr + s.rawSize
		}
	}

	return end
}

// parsePE reads the headers of a PE image and checks that every structure it
// will touch lies inside the file. It parses with debug/pe first so anything
// the standard library rejects is refused before the raw offsets are trusted.
func parsePE(b []byte) (*peImage, error) {
	f, err := pe.NewFile(bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("%w: not a PE image: %w", ErrNotUKI, err)
	}
	_ = f.Close()

	if len(b) < 0x40 || uint64(len(b)) > maxImage {
		return nil, fmt.Errorf("%w: implausible size %d", ErrNotUKI, len(b))
	}
	lfanew := int(binary.LittleEndian.Uint32(b[0x3c:]))
	if lfanew < 0x40 || lfanew > len(b)-4-coffHeaderSize || !bytes.Equal(b[lfanew:lfanew+4], []byte("PE\x00\x00")) {
		return nil, fmt.Errorf("%w: no PE signature", ErrNotUKI)
	}
	p := &peImage{data: b, coffOff: lfanew + 4}
	numSections := int(binary.LittleEndian.Uint16(b[p.coffOff+2:]))
	optSize := int(binary.LittleEndian.Uint16(b[p.coffOff+16:]))
	p.optOff = p.coffOff + coffHeaderSize
	if p.optOff+optSize > len(b) {
		return nil, fmt.Errorf("%w: optional header runs past the end of the file", ErrNotUKI)
	}

	var dirsAt int
	switch magic := binary.LittleEndian.Uint16(b[p.optOff:]); magic {
	case magicPE32:
		dirsAt = 96
	case magicPE32Plus:
		dirsAt = 112
	default:
		return nil, fmt.Errorf("%w: optional header magic %#x", ErrNotUKI, magic)
	}
	if optSize < dirsAt {
		return nil, fmt.Errorf("%w: optional header is %d bytes, too short", ErrNotUKI, optSize)
	}
	p.initDataOff = p.optOff + 8
	p.entryPoint = binary.LittleEndian.Uint32(b[p.optOff+16:])
	p.sectionAlign = binary.LittleEndian.Uint32(b[p.optOff+32:])
	p.fileAlign = binary.LittleEndian.Uint32(b[p.optOff+36:])
	p.sizeOfImgOff = p.optOff + 56
	p.sizeOfHeaders = binary.LittleEndian.Uint32(b[p.optOff+60:])
	p.checksumOff = p.optOff + 64
	p.numDirs = binary.LittleEndian.Uint32(b[p.optOff+dirsAt-4:])
	p.dirOff = p.optOff + dirsAt
	if p.numDirs <= dirSecurity || p.dirOff+int(p.numDirs)*8 > p.optOff+optSize {
		return nil, fmt.Errorf("%w: no room for the certificate table directory", ErrNotUKI)
	}

	sectOff := p.optOff + optSize
	if sectOff+numSections*sectionHeaderSize > int(p.sizeOfHeaders) || int(p.sizeOfHeaders) > len(b) {
		return nil, fmt.Errorf("%w: section table does not fit in the headers", ErrNotUKI)
	}
	for i := range numSections {
		off := sectOff + i*sectionHeaderSize
		s := peSection{
			name:    string(bytes.TrimRight(b[off:off+8], "\x00")),
			hdrOff:  off,
			vsize:   binary.LittleEndian.Uint32(b[off+8:]),
			va:      binary.LittleEndian.Uint32(b[off+12:]),
			rawSize: binary.LittleEndian.Uint32(b[off+16:]),
			rawPtr:  binary.LittleEndian.Uint32(b[off+20:]),
			chars:   binary.LittleEndian.Uint32(b[off+36:]),
		}
		if s.rawSize > 0 && (uint64(s.rawPtr)+uint64(s.rawSize) > uint64(len(b)) || s.rawPtr < p.sizeOfHeaders) {
			return nil, fmt.Errorf("%w: section %q raw data lies outside the file", ErrNotUKI, s.name)
		}
		p.sections = append(p.sections, s)
	}

	if off, size := p.certTable(); size > 0 {
		if uint64(off)+uint64(size) > uint64(len(b)) || off < p.rawEnd() {
			return nil, fmt.Errorf("%w: certificate table lies outside the trailing data", ErrNotUKI)
		}
	}

	return p, nil
}

// uki checks that the image is a single-profile UKI with exactly one .linux
// and one .initrd, and returns the index of the .initrd section.
func (p *peImage) uki() (int, error) {
	initrd, linux := -1, 0
	for i, s := range p.sections {
		switch s.name {
		case ".profile":
			return 0, fmt.Errorf("%w: multi-profile UKIs are not supported", ErrNotUKI)
		case ".linux":
			linux++
		case ".initrd":
			if initrd >= 0 {
				return 0, fmt.Errorf("%w: more than one .initrd section", ErrNotUKI)
			}
			initrd = i
		}
	}
	if linux != 1 {
		return 0, fmt.Errorf("%w: %d .linux sections, want exactly one", ErrNotUKI, linux)
	}
	if initrd < 0 {
		return 0, fmt.Errorf("%w: no .initrd section", ErrNotUKI)
	}

	return initrd, nil
}

// loaded returns a section's contents as the firmware maps them: its extent
// in bytes, the raw data truncated or zero-filled to fit.
func (p *peImage) loaded(s peSection) []byte {
	out := make([]byte, s.extent())
	if s.rawSize > 0 {
		copy(out, p.data[s.rawPtr:s.rawPtr+s.rawSize])
	}

	return out
}

func alignUp(v, a uint64) uint64 { return (v + a - 1) / a * a }

func isPow2(v uint32) bool { return v != 0 && v&(v-1) == 0 }

// relayout returns the image with archive appended to the .initrd contents.
//
// Every byte before the .initrd's raw data -- the headers and every earlier
// section, which includes all of systemd-stub's own code and data -- is kept
// as it is, at the same file offset and RVA; only header fields change. The
// .initrd keeps its RVA and file offset and grows in place, and every later
// section moves up to the next aligned RVA and file offset, in the same
// order. Any certificate table is dropped, CheckSum and the certificate table
// directory are zeroed, and the result is padded to the 8-byte boundary a
// certificate table must start on.
func relayout(p *peImage, idx int, archive []byte) ([]byte, error) {
	if !isPow2(p.sectionAlign) || !isPow2(p.fileAlign) || p.fileAlign > p.sectionAlign {
		return nil, fmt.Errorf("%w: section alignment %#x and file alignment %#x are not usable", ErrNotUKI, p.sectionAlign, p.fileAlign)
	}
	in := p.sections[idx]
	if in.rawSize == 0 || in.vsize == 0 {
		return nil, fmt.Errorf("%w: the .initrd section is empty", ErrNotUKI)
	}
	// A payload section is file-backed, so it is never larger in memory than
	// the whole file; the bound keeps a bad header from asking for gigabytes.
	if uint64(in.vsize) > uint64(len(p.data)) {
		return nil, fmt.Errorf("%w: the .initrd section claims %d bytes in memory", ErrNotUKI, in.vsize)
	}
	if in.va%p.sectionAlign != 0 || in.rawPtr%p.fileAlign != 0 {
		return nil, fmt.Errorf("%w: the .initrd section is not aligned", ErrNotUKI)
	}

	// Sections must ascend and not overlap, in memory and in the file, or
	// "the sections after .initrd" is not a well-defined set to move.
	var rawCursor uint32
	for i, s := range p.sections {
		if i > 0 {
			prev := p.sections[i-1]
			if uint64(s.va) < uint64(prev.va)+uint64(prev.extent()) {
				return nil, fmt.Errorf("%w: section %q is out of order or overlaps %q in memory", ErrNotUKI, s.name, prev.name)
			}
		}
		if s.rawSize == 0 {
			continue
		}
		if s.rawPtr < rawCursor {
			return nil, fmt.Errorf("%w: section %q is out of order or overlaps in the file", ErrNotUKI, s.name)
		}
		rawCursor = s.rawPtr + s.rawSize
		if i > idx && (s.rawSize%p.fileAlign != 0 || s.rawPtr%p.fileAlign != 0) {
			return nil, fmt.Errorf("%w: section %q is not aligned to the file alignment", ErrNotUKI, s.name)
		}
	}

	// Moving the sections after .initrd is only safe if nothing refers to
	// them by address: the entry point, the data directories and the COFF
	// symbol table must all lie before it. In a UKI they belong to the stub.
	if p.entryPoint >= in.va {
		return nil, fmt.Errorf("%w: the entry point lies in or after .initrd", ErrNotUKI)
	}
	for d := range int(p.numDirs) {
		if d == dirSecurity {
			continue
		}
		off := p.dirOff + d*8
		rva, size := binary.LittleEndian.Uint32(p.data[off:]), binary.LittleEndian.Uint32(p.data[off+4:])
		if size > 0 && uint64(rva)+uint64(size) > uint64(in.va) {
			return nil, fmt.Errorf("%w: data directory %d lies in or after .initrd", ErrNotUKI, d)
		}
	}
	if sym := binary.LittleEndian.Uint32(p.data[p.coffOff+8:]); sym != 0 && sym >= in.rawPtr {
		return nil, fmt.Errorf("%w: the COFF symbol table lies in or after .initrd", ErrNotUKI)
	}

	// Bytes after .initrd that no section or certificate table owns would be
	// lost by the move. Padding is fine; anything else is refused.
	if err := p.unownedAreZero(idx); err != nil {
		return nil, err
	}

	content := p.loaded(in)
	// The kernel only recognises an uncompressed cpio archive that starts on
	// a 4-byte boundary of the initramfs; the gap is zeros, which it skips.
	content = append(content, make([]byte, alignUp(uint64(len(content)), 4)-uint64(len(content)))...)
	content = append(content, archive...)
	newVSize := uint64(len(content))
	newRaw := alignUp(newVSize, uint64(p.fileAlign))

	out := make([]byte, 0, len(p.data)+len(archive)+int(p.fileAlign))
	out = append(out, p.data[:in.rawPtr]...)
	out = append(out, content...)
	out = append(out, make([]byte, newRaw-newVSize)...)
	putSection(out, in.hdrOff, uint32(newVSize), in.va, uint32(newRaw), in.rawPtr)

	prevEnd := uint64(in.va) + newVSize
	for _, s := range p.sections[idx+1:] {
		va := alignUp(prevEnd, uint64(p.sectionAlign))
		var rawPtr uint64
		if s.rawSize > 0 {
			rawPtr = uint64(len(out))
			out = append(out, p.data[s.rawPtr:s.rawPtr+s.rawSize]...)
		}
		if va+uint64(s.extent()) > maxImage || rawPtr > maxImage {
			return nil, fmt.Errorf("%w: the signed image would exceed 4 GiB", ErrNotUKI)
		}
		putSection(out, s.hdrOff, s.vsize, uint32(va), s.rawSize, uint32(rawPtr))
		prevEnd = va + uint64(s.extent())
	}

	sizeOfImage := alignUp(prevEnd, uint64(p.sectionAlign))
	if sizeOfImage > maxImage || uint64(len(out)) > maxImage {
		return nil, fmt.Errorf("%w: the signed image would exceed 4 GiB", ErrNotUKI)
	}
	binary.LittleEndian.PutUint32(out[p.sizeOfImgOff:], uint32(sizeOfImage))
	if in.chars&scnInitData != 0 {
		initData := uint64(binary.LittleEndian.Uint32(out[p.initDataOff:])) + newRaw - uint64(in.rawSize)
		binary.LittleEndian.PutUint32(out[p.initDataOff:], uint32(min(initData, maxImage)))
	}
	binary.LittleEndian.PutUint32(out[p.checksumOff:], 0)
	binary.LittleEndian.PutUint64(out[p.secDirOff():], 0)

	return append(out, make([]byte, alignUp(uint64(len(out)), certAlign)-uint64(len(out)))...), nil
}

// unownedAreZero checks that every byte from the .initrd's raw data to the end
// of the file belongs to a section or the certificate table, or is zero.
func (p *peImage) unownedAreZero(idx int) error {
	type span struct{ start, end uint64 }
	var owned []span
	for _, s := range p.sections[idx:] {
		if s.rawSize > 0 {
			owned = append(owned, span{uint64(s.rawPtr), uint64(s.rawPtr) + uint64(s.rawSize)})
		}
	}
	if off, size := p.certTable(); size > 0 {
		owned = append(owned, span{uint64(off), uint64(off) + uint64(size)})
	}
	cursor := uint64(p.sections[idx].rawPtr)
	for _, o := range owned {
		if o.start > cursor && !allZero(p.data[cursor:o.start]) {
			return fmt.Errorf("%w: unknown data at file offset %#x after .initrd", ErrNotUKI, cursor)
		}
		cursor = max(cursor, o.end)
	}
	if cursor < uint64(len(p.data)) && !allZero(p.data[cursor:]) {
		return fmt.Errorf("%w: unknown data at file offset %#x after the last section", ErrNotUKI, cursor)
	}

	return nil
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}

	return true
}

func putSection(b []byte, hdrOff int, vsize, va, rawSize, rawPtr uint32) {
	binary.LittleEndian.PutUint32(b[hdrOff+8:], vsize)
	binary.LittleEndian.PutUint32(b[hdrOff+12:], va)
	binary.LittleEndian.PutUint32(b[hdrOff+16:], rawSize)
	binary.LittleEndian.PutUint32(b[hdrOff+20:], rawPtr)
}

// appendCertificate appends cms as a WIN_CERTIFICATE (revision 2.0, PKCS
// SignedData) to an image relayout produced, points the certificate table
// directory at it and fills in the CheckSum.
func appendCertificate(p *peImage, cms []byte) []byte {
	off := len(p.data)
	length := alignUp(uint64(8+len(cms)), certAlign)
	out := make([]byte, off, off+int(length))
	copy(out, p.data)
	out = binary.LittleEndian.AppendUint32(out, uint32(length))
	out = binary.LittleEndian.AppendUint16(out, certRevision)
	out = binary.LittleEndian.AppendUint16(out, certTypePKCS)
	out = append(out, cms...)
	out = append(out, make([]byte, off+int(length)-len(out))...)

	binary.LittleEndian.PutUint32(out[p.secDirOff():], uint32(off))
	binary.LittleEndian.PutUint32(out[p.secDirOff()+4:], uint32(length))
	binary.LittleEndian.PutUint32(out[p.checksumOff:], 0)
	binary.LittleEndian.PutUint32(out[p.checksumOff:], checksum(out))

	return out
}

// checksum is the PE image checksum (the algorithm of imagehlp's
// CheckSumMappedFile): a ones'-complement-style 16-bit sum of the file with
// the CheckSum field zero, plus the file length. Firmware does not check it,
// but tools that do expect it to be right or zero.
func checksum(b []byte) uint32 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.LittleEndian.Uint16(b[i:]))
		sum = (sum & 0xffff) + (sum >> 16)
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1])
		sum = (sum & 0xffff) + (sum >> 16)
	}
	sum = (sum & 0xffff) + (sum >> 16)

	return sum + uint32(len(b))
}

// certificateBlob returns the CMS SignedData in the image's certificate table.
func (p *peImage) certificateBlob() ([]byte, error) {
	off, size := p.certTable()
	if size < 8 {
		return nil, fmt.Errorf("%w: no certificate table", ErrSelfCheck)
	}
	entry := p.data[off : off+size]
	length := binary.LittleEndian.Uint32(entry)
	if length < 8 || length > size ||
		binary.LittleEndian.Uint16(entry[4:]) != certRevision ||
		binary.LittleEndian.Uint16(entry[6:]) != certTypePKCS {
		return nil, fmt.Errorf("%w: the certificate table entry is malformed", ErrSelfCheck)
	}

	return entry[8:length], nil
}
