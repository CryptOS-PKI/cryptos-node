// Package isotest builds small synthetic CryptOS ISOs for tests, laid out
// the way cryptos-appliance's build/iso/build.sh lays out a real one: a FAT
// EFI boot image holding the UKI as EFI/BOOT/BOOTX64.EFI, named by the El
// Torito catalog and also present in the tree as /efiboot.img, a plain copy
// of the UKI at /cryptos.uki with Rock Ridge names, padding after the files,
// and optionally the MBR and GPT of a hybrid image with the GPT backup at
// the end. It writes every structure itself, so tests need no xorriso or
// mtools.
package isotest

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
	"hash/crc32"
	"testing"
)

const (
	sector    = 2048
	block     = 512
	padSecs   = 150 // xorriso's default 300 KiB of padding
	tailSecs  = 9   // 33 GPT blocks, rounded up to whole sectors
	gptBlocks = 33  // 32 blocks of entries plus the header
)

// Fixed sectors of the synthetic layout.
const (
	pvdLBA    = 16
	bootLBA   = 17
	termLBA   = 18
	lptLBA    = 19
	mptLBA    = 20
	rootLBA   = 21
	docsLBA   = 22
	catLBA    = 23
	readmeLBA = 24
	efiLBA    = 25
)

// OtherFile is the content of STARTUP.NSH, the file the FAT image holds
// right after the UKI's clusters, so a grown UKI cannot simply extend in
// place.
var OtherFile = bytes.Repeat([]byte("echo startup\r\n"), 100)

// Readme is the content of /docs/readme.txt in the ISO tree.
var Readme = []byte("a file in a subdirectory\n")

// Options picks the variant to build.
type Options struct {
	// FAT is the FAT type of the boot image: 12, 16 (the default) or 32.
	FAT int
	// TightFAT sizes the FAT image with no free clusters at all.
	TightFAT bool
	// GPT writes a protective MBR and a GPT, with a partition over the ISO
	// volume and one over the EFI boot image, and the GPT backup in the
	// last sectors of the image.
	GPT bool
	// MBR writes an MBR with a partition over the whole image and one over
	// the EFI boot image (and no GPT).
	MBR bool
	// VolumeCoversTail counts the GPT backup sectors in the volume space
	// size instead of leaving them after the volume.
	VolumeCoversTail bool
	// EFISection puts the EFI boot image in a catalog section with platform
	// 0xEF instead of the default entry.
	EFISection bool
	// NoTreeCopy leaves /cryptos.uki out of the tree.
	NoTreeCopy bool
}

// ISO is a built image and where things are in it.
type ISO struct {
	Image []byte
	// EFILBA is the sector of the FAT boot image; FATSize its length.
	EFILBA  int
	FATSize int
	// UKILBA is the sector of /cryptos.uki (0 with NoTreeCopy).
	UKILBA int
	// VolumeEnd is the first sector after the files and padding, where the
	// GPT backup (if any) starts.
	VolumeEnd int
}

func sectors(n int) int { return (n + sector - 1) / sector }

// Build writes a synthetic ISO carrying uki.
func Build(t testing.TB, uki []byte, o Options) ISO {
	t.Helper()
	if o.FAT == 0 {
		o.FAT = 16
	}
	fat := buildFAT(t, o.FAT, uki, o.TightFAT)

	ukiLBA := efiLBA + sectors(len(fat))
	end := ukiLBA
	if !o.NoTreeCopy {
		end += sectors(len(uki))
	}
	volEnd := end + padSecs
	total := volEnd
	if o.GPT {
		total += tailSecs
	}
	volSize := volEnd
	if o.VolumeCoversTail {
		volSize = total
	}
	img := make([]byte, total*sector)

	// Volume descriptors.
	pvd := img[pvdLBA*sector:]
	vdHeader(pvd, 1)
	copy(pvd[8:40], pad("CRYPTOS", 32))
	copy(pvd[40:72], pad("CRYPTOS_vmware", 32))
	both32(pvd[80:], uint32(volSize))
	both16(pvd[120:], 1)
	both16(pvd[124:], 1)
	both16(pvd[128:], sector)
	pathTable := []byte{1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 4, 0, 0, 0, 0, 0, 1, 0, 'D', 'O', 'C', 'S'}
	both32(pvd[132:], uint32(len(pathTable)))
	binary.LittleEndian.PutUint32(pvd[140:], lptLBA)
	binary.BigEndian.PutUint32(pvd[148:], mptLBA)
	copy(pvd[156:], dirRecord(rootLBA, sector, 2, []byte{0}, ""))
	pvd[881] = 1

	br := img[bootLBA*sector:]
	vdHeader(br, 0)
	copy(br[7:], "EL TORITO SPECIFICATION")
	binary.LittleEndian.PutUint32(br[0x47:], catLBA)

	vdHeader(img[termLBA*sector:], 255)

	// Path tables: the root and /docs.
	l := img[lptLBA*sector:]
	copy(l, pathTable)
	binary.LittleEndian.PutUint32(l[2:], rootLBA)
	binary.LittleEndian.PutUint32(l[12:], docsLBA)
	m := img[mptLBA*sector:]
	copy(m, pathTable)
	binary.BigEndian.PutUint32(m[2:], rootLBA)
	binary.BigEndian.PutUint16(m[6:], 1)
	binary.BigEndian.PutUint32(m[12:], docsLBA)
	binary.BigEndian.PutUint16(m[16:], 1)

	// The root directory, in identifier order, and /docs.
	recs := [][]byte{
		dirRecord(rootLBA, sector, 2, []byte{0}, ""),
		dirRecord(rootLBA, sector, 2, []byte{1}, ""),
	}
	if !o.NoTreeCopy {
		recs = append(recs, dirRecord(uint32(ukiLBA), uint32(len(uki)), 0, []byte("CRYPTOS.UKI;1"), "cryptos.uki"))
	}
	recs = append(recs,
		dirRecord(docsLBA, sector, 2, []byte("DOCS"), "docs"),
		dirRecord(efiLBA, uint32(len(fat)), 0, []byte("EFIBOOT.IMG;1"), "efiboot.img"),
	)
	copy(img[rootLBA*sector:], bytes.Join(recs, nil))
	copy(img[docsLBA*sector:], bytes.Join([][]byte{
		dirRecord(docsLBA, sector, 2, []byte{0}, ""),
		dirRecord(rootLBA, sector, 2, []byte{1}, ""),
		dirRecord(readmeLBA, uint32(len(Readme)), 0, []byte("README.TXT;1"), "readme.txt"),
	}, nil))
	copy(img[readmeLBA*sector:], Readme)

	// The El Torito boot catalog.
	cat := img[catLBA*sector:]
	cat[0] = 0x01
	copy(cat[4:], "CRYPTOS")
	cat[30], cat[31] = 0x55, 0xAA
	entry := func(e []byte) {
		e[0] = 0x88
		binary.LittleEndian.PutUint16(e[6:], uint16(min(len(fat)/block, 0xFFFF)))
		binary.LittleEndian.PutUint32(e[8:], efiLBA)
	}
	if o.EFISection {
		cat[1] = 0x00 // the validation entry and the default entry: BIOS, not bootable
		cat[64] = 0x91
		cat[65] = 0xEF
		binary.LittleEndian.PutUint16(cat[66:], 1)
		entry(cat[96:128])
	} else {
		cat[1] = 0xEF
		entry(cat[32:64])
	}
	var sum uint16
	for i := 0; i < 32; i += 2 {
		sum += binary.LittleEndian.Uint16(cat[i:])
	}
	binary.LittleEndian.PutUint16(cat[28:], -sum)

	copy(img[efiLBA*sector:], fat)
	if !o.NoTreeCopy {
		copy(img[ukiLBA*sector:], uki)
	}

	switch {
	case o.GPT:
		writeGPT(img, total, volEnd, len(fat))
	case o.MBR:
		mbrEntry(img, 0, 0x83, 0, uint32(total*sector/block))
		mbrEntry(img, 1, 0xEF, efiLBA*sector/block, uint32(len(fat)/block))
		img[510], img[511] = 0x55, 0xAA
	}

	iso := ISO{Image: img, EFILBA: efiLBA, FATSize: len(fat), VolumeEnd: volEnd}
	if !o.NoTreeCopy {
		iso.UKILBA = ukiLBA
	}

	return iso
}

func vdHeader(b []byte, typ byte) {
	b[0] = typ
	copy(b[1:6], "CD001")
	b[6] = 1
}

func pad(s string, n int) []byte {
	b := bytes.Repeat([]byte{' '}, n)
	copy(b, s)
	return b
}

func both16(b []byte, v uint16) {
	binary.LittleEndian.PutUint16(b, v)
	binary.BigEndian.PutUint16(b[2:], v)
}

func both32(b []byte, v uint32) {
	binary.LittleEndian.PutUint32(b, v)
	binary.BigEndian.PutUint32(b[4:], v)
}

// dirRecord is an ISO 9660 directory record, with a Rock Ridge NM entry
// when nm is set.
func dirRecord(lba, size uint32, flags byte, ident []byte, nm string) []byte {
	var su []byte
	if nm != "" {
		su = append([]byte{'N', 'M', byte(5 + len(nm)), 1, 0}, nm...)
	}
	n := 33 + len(ident)
	if len(ident)%2 == 0 {
		n++
	}
	suOff := n
	n += len(su)
	if n%2 == 1 {
		n++
	}
	r := make([]byte, n)
	r[0] = byte(n)
	both32(r[2:], lba)
	both32(r[10:], size)
	r[18] = 126 // 2026
	r[19], r[20] = 1, 1
	r[25] = flags
	both16(r[28:], 1)
	r[32] = byte(len(ident))
	copy(r[33:], ident)
	copy(r[suOff:], su)

	return r
}

func mbrEntry(img []byte, i int, typ byte, start int, size uint32) {
	e := img[446+16*i:]
	e[4] = typ
	binary.LittleEndian.PutUint32(e[8:], uint32(start))
	binary.LittleEndian.PutUint32(e[12:], size)
}

// writeGPT writes a protective MBR, the primary GPT and its backup in the
// last blocks of the image.
func writeGPT(img []byte, total, volEnd, fatLen int) {
	blocks := total * sector / block
	mbrEntry(img, 0, 0xEE, 1, uint32(blocks-1))
	img[510], img[511] = 0x55, 0xAA

	entries := make([]byte, 128*128)
	part := func(i int, typ byte, first, last int) {
		e := entries[i*128:]
		for j := range 16 {
			e[j] = typ + byte(j)
			e[16+j] = byte(0x40 + i + j)
		}
		binary.LittleEndian.PutUint64(e[32:], uint64(first))
		binary.LittleEndian.PutUint64(e[40:], uint64(last))
		copy(e[56:], []byte{'I', 0, 'S', 0, 'O', 0})
	}
	efiFirst := efiLBA * sector / block
	part(0, 0xA2, 64, volEnd*sector/block-1)
	part(1, 0x28, efiFirst, efiFirst+fatLen/block-1)
	crc := crc32.ChecksumIEEE(entries)

	backupEntries := blocks - gptBlocks
	header := func(my, alt, entriesAt int) []byte {
		h := make([]byte, 92)
		copy(h, "EFI PART")
		binary.LittleEndian.PutUint32(h[8:], 0x00010000)
		binary.LittleEndian.PutUint32(h[12:], 92)
		binary.LittleEndian.PutUint64(h[24:], uint64(my))
		binary.LittleEndian.PutUint64(h[32:], uint64(alt))
		binary.LittleEndian.PutUint64(h[40:], 34)
		binary.LittleEndian.PutUint64(h[48:], uint64(backupEntries-1))
		for j := range 16 {
			h[56+j] = byte(0x90 + j)
		}
		binary.LittleEndian.PutUint64(h[72:], uint64(entriesAt))
		binary.LittleEndian.PutUint32(h[80:], 128)
		binary.LittleEndian.PutUint32(h[84:], 128)
		binary.LittleEndian.PutUint32(h[88:], crc)
		binary.LittleEndian.PutUint32(h[16:], crc32.ChecksumIEEE(h))
		return h
	}
	copy(img[block:], header(1, blocks-1, 2))
	copy(img[2*block:], entries)
	copy(img[backupEntries*block:], entries)
	copy(img[(blocks-1)*block:], header(blocks-1, 1, backupEntries))
}
