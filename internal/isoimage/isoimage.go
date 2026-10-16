// Package isoimage finds the Unified Kernel Image inside a CryptOS ISO and
// replaces every copy of it, in pure Go, with no root and no external tools
// (cryptos-appliance#83).
//
// cryptos-appliance's build/iso/build.sh carries the UKI twice:
//
//   - as EFI/BOOT/BOOTX64.EFI in a FAT image that the El Torito catalog names
//     as the EFI boot image, which the firmware boots;
//   - as a plain file in the ISO 9660 tree (/cryptos.uki), which the
//     installer copies to the disk it installs.
//
// Open finds the first through the El Torito catalog and every other copy by
// its content, in every directory tree the volume descriptors describe.
// ReplaceUKI writes a new UKI into each: inside the FAT image it frees the
// old cluster chain and allocates a new one, so the FAT image keeps its size
// and its place; a tree copy that no longer fits its extent moves to new
// sectors at the end of the volume. Everything that describes the image's
// size or what follows that point (the volume space size, an MBR, a GPT and
// its backup at the end of the image) is updated to match.
//
// It handles the narrow layout that build would write and refuses anything
// it cannot rewrite safely; it is not a general ISO or FAT library.
package isoimage

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
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"path"
	"strings"
	"unicode/utf16"
)

// SectorSize is the ISO 9660 logical block size every CryptOS ISO uses.
const SectorSize = 2048

const (
	firstVDSector  = 16
	maxVDs         = 64
	maxDirDepth    = 16
	elToritoID     = "EL TORITO SPECIFICATION"
	flagDirectory  = 0x02
	flagMultiExtnt = 0x80
)

var (
	// ErrNotISO is wrapped when the input is not an ISO 9660 image.
	ErrNotISO = errors.New("isoimage: not an ISO 9660 image")
	// ErrNoUKI is wrapped when no El Torito boot image holds a UKI at the
	// UEFI removable-media path.
	ErrNoUKI = errors.New("isoimage: no El Torito EFI boot image holds EFI/BOOT/BOOTX64.EFI")
	// ErrLayout is wrapped when the ISO is laid out in a way this package
	// does not rewrite.
	ErrLayout = errors.New("isoimage: unsupported ISO layout")
)

// efiBootPaths are the UEFI removable-media boot paths looked for in an El
// Torito boot image, in order.
var efiBootPaths = [][]string{
	{"EFI", "BOOT", "BOOTX64.EFI"},
	{"EFI", "BOOT", "BOOTAA64.EFI"},
}

// IsISO reports whether b starts like an ISO 9660 image: a volume descriptor
// with the standard identifier "CD001" at sector 16.
func IsISO(b []byte) bool {
	off := firstVDSector * SectorSize
	return len(b) >= off+SectorSize && string(b[off+1:off+6]) == "CD001"
}

// fileRec is one file or directory record found in a directory tree.
type fileRec struct {
	off  int // byte offset of the directory record in the image
	lba  uint32
	size uint32
	path string
	dir  bool
	// multi marks one part of a multi-extent file; such a file is never
	// taken as a UKI copy.
	multi bool
}

// bootFAT is a FAT boot image the El Torito catalog names that holds a UKI.
type bootFAT struct {
	off   int // byte offset of the FAT image in the ISO
	size  int // FAT image length in bytes
	entry int // offset of the UKI's directory entry inside the FAT image
	name  string
}

// Image is a parsed ISO and the UKI it carries.
type Image struct {
	b         []byte
	vds       []int // byte offsets of the primary and supplementary descriptors
	files     []fileRec
	boots     []bootFAT
	isoCopies []fileRec // one record per distinct extent holding the UKI
	uki       []byte
}

// Open parses iso and finds every copy of its UKI. It fails if no El Torito
// boot image holds one, or if the copies it finds differ.
func Open(iso []byte) (*Image, error) {
	if !IsISO(iso) {
		return nil, ErrNotISO
	}
	im := &Image{b: iso}

	var catalogs []uint32
	for i := range maxVDs {
		off := (firstVDSector + i) * SectorSize
		if off+SectorSize > len(iso) {
			return nil, fmt.Errorf("%w: the volume descriptors run past the end of the image", ErrNotISO)
		}
		vd := iso[off : off+SectorSize]
		if string(vd[1:6]) != "CD001" {
			return nil, fmt.Errorf("%w: volume descriptor %d has no CD001 identifier", ErrNotISO, i)
		}
		typ := vd[0]
		if typ == 255 {
			break
		}
		switch typ {
		case 0:
			if strings.TrimRight(string(vd[7:39]), "\x00 ") == elToritoID {
				catalogs = append(catalogs, binary.LittleEndian.Uint32(vd[0x47:]))
			}
		case 1, 2:
			im.vds = append(im.vds, off)
		}
		if i == maxVDs-1 {
			return nil, fmt.Errorf("%w: no volume descriptor set terminator", ErrNotISO)
		}
	}
	if len(im.vds) == 0 || iso[im.vds[0]] != 1 {
		return nil, fmt.Errorf("%w: no primary volume descriptor", ErrNotISO)
	}
	if bs := binary.LittleEndian.Uint16(iso[im.vds[0]+128:]); bs != SectorSize {
		return nil, fmt.Errorf("%w: logical block size %d, want %d", ErrLayout, bs, SectorSize)
	}

	for _, off := range im.vds {
		joliet := iso[off] == 2 && bytes.HasPrefix(iso[off+88:off+120], []byte("%/"))
		root := iso[off+156 : off+156+34]
		seen := map[uint32]bool{}
		if err := im.walk(binary.LittleEndian.Uint32(root[2:]), binary.LittleEndian.Uint32(root[10:]), "/", joliet, 0, seen); err != nil {
			return nil, err
		}
	}

	if err := im.findBootUKIs(catalogs); err != nil {
		return nil, err
	}
	im.findTreeCopies()

	return im, nil
}

// UKI returns the UKI the ISO boots.
func (im *Image) UKI() []byte { return im.uki }

// Copies names every place the UKI was found: the El Torito boot image path
// first, then each ISO 9660 file.
func (im *Image) Copies() []string {
	var out []string
	for _, bt := range im.boots {
		out = append(out, bt.name)
	}
	for _, c := range im.isoCopies {
		out = append(out, c.path)
	}

	return out
}

// walk records every entry of the directory at lba and recurses into its
// subdirectories.
func (im *Image) walk(lba, size uint32, dir string, joliet bool, depth int, seen map[uint32]bool) error {
	if depth > maxDirDepth {
		return fmt.Errorf("%w: directories nest deeper than %d", ErrLayout, maxDirDepth)
	}
	if seen[lba] {
		return nil
	}
	seen[lba] = true
	start := int(lba) * SectorSize
	end := start + int(size)
	if end > len(im.b) || end < start {
		return fmt.Errorf("%w: directory %s runs past the end of the image", ErrNotISO, dir)
	}
	for off := start; off < end; {
		n := int(im.b[off])
		if n == 0 {
			// Records never cross a sector boundary; the rest of the sector
			// is padding.
			off = (off/SectorSize + 1) * SectorSize
			continue
		}
		if n < 34 || off+n > end {
			return fmt.Errorf("%w: malformed directory record in %s", ErrNotISO, dir)
		}
		rec := im.b[off : off+n]
		nameLen := int(rec[32])
		if 33+nameLen > n {
			return fmt.Errorf("%w: malformed directory record name in %s", ErrNotISO, dir)
		}
		ident := rec[33 : 33+nameLen]
		if nameLen == 1 && (ident[0] == 0 || ident[0] == 1) {
			off += n
			continue
		}
		r := fileRec{
			off:   off,
			lba:   binary.LittleEndian.Uint32(rec[2:]),
			size:  binary.LittleEndian.Uint32(rec[10:]),
			path:  path.Join(dir, recordName(rec, joliet)),
			dir:   rec[25]&flagDirectory != 0,
			multi: rec[25]&flagMultiExtnt != 0,
		}
		im.files = append(im.files, r)
		if r.dir {
			if err := im.walk(r.lba, r.size, r.path, joliet, depth+1, seen); err != nil {
				return err
			}
		}
		off += n
	}

	return nil
}

// recordName is the name a reader sees for a directory record: the Rock
// Ridge NM name when there is one, else the Joliet or ISO 9660 identifier
// without its ";1" version.
func recordName(rec []byte, joliet bool) string {
	nameLen := int(rec[32])
	ident := rec[33 : 33+nameLen]
	if joliet {
		u := make([]uint16, 0, len(ident)/2)
		for i := 0; i+1 < len(ident); i += 2 {
			u = append(u, binary.BigEndian.Uint16(ident[i:]))
		}
		name, _, _ := strings.Cut(string(utf16.Decode(u)), ";")
		return name
	}
	suOff := 33 + nameLen
	if nameLen%2 == 0 {
		suOff++
	}
	var nm strings.Builder
	for su := rec[min(suOff, len(rec)):]; len(su) >= 4; {
		l := int(su[2])
		if l < 4 || l > len(su) {
			break
		}
		// NM flags 0x02 and 0x04 mean "." and "..", which carry no name.
		if string(su[:2]) == "NM" && l >= 5 && su[4]&0x06 == 0 {
			nm.Write(su[5:l])
		}
		su = su[l:]
	}
	if nm.Len() > 0 {
		return nm.String()
	}
	name, _, _ := strings.Cut(string(ident), ";")
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// findBootUKIs reads each El Torito catalog and keeps every boot image that
// is a FAT image holding a UKI at a UEFI removable-media path.
func (im *Image) findBootUKIs(catalogs []uint32) error {
	seen := map[uint32]bool{}
	for _, cat := range catalogs {
		off := int(cat) * SectorSize
		if off+SectorSize > len(im.b) {
			return fmt.Errorf("%w: the El Torito catalog is past the end of the image", ErrNotISO)
		}
		for _, lba := range bootImageLBAs(im.b[off : off+SectorSize]) {
			if seen[lba] {
				continue
			}
			seen[lba] = true
			if err := im.addBootUKI(lba); err != nil {
				return err
			}
		}
	}
	if len(im.boots) == 0 {
		return ErrNoUKI
	}

	return nil
}

func (im *Image) addBootUKI(lba uint32) error {
	off := int(lba) * SectorSize
	if off >= len(im.b) {
		return fmt.Errorf("%w: an El Torito boot image is past the end of the image", ErrNotISO)
	}
	v, err := openFAT(im.b[off:])
	if err != nil {
		// A boot image that is not a FAT file system (a BIOS loader, say)
		// is not where a UKI lives.
		return nil
	}
	for _, p := range efiBootPaths {
		entry, err := v.find(p)
		if err != nil {
			continue
		}
		data, err := v.readFile(entry)
		if err != nil {
			return fmt.Errorf("isoimage: El Torito boot image at sector %d: %w", lba, err)
		}
		if im.uki != nil && !bytes.Equal(im.uki, data) {
			return fmt.Errorf("%w: two El Torito boot images hold different UKIs", ErrLayout)
		}
		im.uki = data
		where := fmt.Sprintf("El Torito EFI boot image at sector %d", lba)
		for _, f := range im.files {
			if !f.dir && f.lba == lba {
				where = "El Torito EFI boot image " + f.path
				break
			}
		}
		im.boots = append(im.boots, bootFAT{off: off, size: len(v.b), entry: entry, name: where + ": " + strings.Join(p, "/")})
		return nil
	}

	return nil
}

// bootImageLBAs lists the load sector of every bootable entry in an El
// Torito boot catalog: the default entry and the entries of each section.
func bootImageLBAs(cat []byte) []uint32 {
	if len(cat) < 64 || cat[0] != 0x01 || cat[30] != 0x55 || cat[31] != 0xAA {
		return nil
	}
	var lbas []uint32
	add := func(e []byte) {
		if e[0] == 0x88 {
			if lba := binary.LittleEndian.Uint32(e[8:]); lba != 0 {
				lbas = append(lbas, lba)
			}
		}
	}
	add(cat[32:64])
	for off := 64; off+32 <= len(cat); {
		h := cat[off]
		if h != 0x90 && h != 0x91 {
			break
		}
		n := int(binary.LittleEndian.Uint16(cat[off+2:]))
		off += 32
		for i := 0; i < n && off+32 <= len(cat); i++ {
			add(cat[off : off+32])
			off += 32
			// Selection-criteria extension entries belong to the entry
			// before them.
			for off+32 <= len(cat) && cat[off] == 0x44 {
				off += 32
			}
		}
		if h == 0x91 {
			break
		}
	}

	return lbas
}

// findTreeCopies keeps one record for each distinct extent in the directory
// trees whose content is the UKI, leaving out the boot images themselves.
func (im *Image) findTreeCopies() {
	seen := map[uint32]bool{}
	for _, f := range im.files {
		if f.dir || f.multi || int(f.size) != len(im.uki) || seen[f.lba] {
			continue
		}
		start := int(f.lba) * SectorSize
		if start+int(f.size) > len(im.b) {
			continue
		}
		if bytes.Equal(im.b[start:start+int(f.size)], im.uki) {
			seen[f.lba] = true
			im.isoCopies = append(im.isoCopies, f)
		}
	}
}

// ReplaceUKI returns a copy of the ISO with every copy of its UKI replaced
// by uki. The input image is not changed.
func (im *Image) ReplaceUKI(uki []byte) ([]byte, error) {
	if len(uki) == 0 {
		return nil, errors.New("isoimage: the new UKI is empty")
	}
	if uint64(len(uki)) > math.MaxUint32 {
		return nil, fmt.Errorf("%w: a %d-byte UKI does not fit one ISO 9660 extent", ErrLayout, len(uki))
	}
	out := bytes.Clone(im.b)

	for _, bt := range im.boots {
		v, err := openFAT(out[bt.off : bt.off+bt.size])
		if err != nil {
			return nil, fmt.Errorf("isoimage: %s: %w", bt.name, err)
		}
		if err := v.replaceFile(bt.entry, uki); err != nil {
			return nil, fmt.Errorf("isoimage: %s: %w", bt.name, err)
		}
	}

	newSectors := sectors(len(uki))
	var moved []fileRec
	for _, c := range im.isoCopies {
		if newSectors > sectors(int(c.size)) {
			moved = append(moved, c)
			continue
		}
		ext := out[int(c.lba)*SectorSize : (int(c.lba)+sectors(int(c.size)))*SectorSize]
		clear(ext[copy(ext, uki):])
		im.patchRecords(out, c.lba, c.lba, uint32(len(uki)))
	}
	if len(moved) == 0 {
		return out, nil
	}

	p, err := im.insertionPoint(out)
	if err != nil {
		return nil, err
	}
	grow := len(moved) * newSectors * SectorSize
	out, err = insert(out, im.vds, p, grow)
	if err != nil {
		return nil, err
	}
	for i, c := range moved {
		lba := p/SectorSize + i*newSectors
		if uint64(lba) > math.MaxUint32 {
			return nil, fmt.Errorf("%w: the image outgrows 32-bit sector numbers", ErrLayout)
		}
		copy(out[lba*SectorSize:], uki)
		clear(out[int(c.lba)*SectorSize : (int(c.lba)+sectors(int(c.size)))*SectorSize])
		im.patchRecords(out, c.lba, uint32(lba), uint32(len(uki)))
	}

	return out, nil
}

// insertionPoint is where moved UKI copies go: the end of the ISO 9660
// volume, or the start of a GPT backup that sits inside it at the end of the
// image. Everything ReplaceUKI rewrites in place must lie before it.
func (im *Image) insertionPoint(b []byte) (int, error) {
	vol := int(binary.LittleEndian.Uint32(b[im.vds[0]+80:]))
	p := vol * SectorSize
	if p > len(b) {
		return 0, fmt.Errorf("%w: the volume space size (%d sectors) is larger than the image", ErrLayout, vol)
	}
	if tail, ok := gptTailStart(b); ok && tail < p {
		p = tail
	}
	p = p / SectorSize * SectorSize
	for _, f := range im.files {
		if f.off+34 > p || (f.size > 0 && int(f.lba)*SectorSize >= p) {
			return 0, fmt.Errorf("%w: %s lies past the end of the volume", ErrLayout, f.path)
		}
		if !f.dir && f.size > 0 && int(f.lba)*SectorSize+int(f.size) > p {
			return 0, fmt.Errorf("%w: %s runs past the end of the volume", ErrLayout, f.path)
		}
	}
	for _, bt := range im.boots {
		if bt.off+bt.size > p {
			return 0, fmt.Errorf("%w: %s runs past the end of the volume", ErrLayout, bt.name)
		}
	}

	return p, nil
}

// insert returns b with grow zero bytes inserted at p, a sector boundary,
// and every size and position that pointed at or past p updated: the
// volume space size of each descriptor, the MBR partitions and the GPT.
func insert(b []byte, vds []int, p, grow int) ([]byte, error) {
	out := make([]byte, len(b)+grow)
	copy(out, b[:p])
	copy(out[p+grow:], b[p:])
	for _, off := range vds {
		vol := uint64(binary.LittleEndian.Uint32(out[off+80:])) + uint64(grow/SectorSize)
		if vol > math.MaxUint32 {
			return nil, fmt.Errorf("%w: the image outgrows 32-bit sector numbers", ErrLayout)
		}
		putBoth32(out[off+80:], uint32(vol))
	}
	th, d := uint64(p/blockSize), uint64(grow/blockSize)
	fixMBR(out, th, d)
	if err := fixGPT(out, th, d); err != nil {
		return nil, err
	}

	return out, nil
}

// patchRecords points every file record at oldLBA, in every directory tree,
// at lba with the given size.
func (im *Image) patchRecords(b []byte, oldLBA, lba, size uint32) {
	for _, f := range im.files {
		if f.dir || f.lba != oldLBA {
			continue
		}
		putBoth32(b[f.off+2:], lba)
		putBoth32(b[f.off+10:], size)
	}
}

// putBoth32 writes v in the ISO 9660 both-byte-order form: little-endian,
// then big-endian.
func putBoth32(b []byte, v uint32) {
	binary.LittleEndian.PutUint32(b, v)
	binary.BigEndian.PutUint32(b[4:], v)
}

func sectors(n int) int { return (n + SectorSize - 1) / SectorSize }
