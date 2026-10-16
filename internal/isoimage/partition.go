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

// The system area of a hybrid ISO can carry an MBR and a GPT so the same
// image also boots from a USB stick. Both count in 512-byte blocks, and the
// GPT keeps a backup header and entry array in the last blocks of the image.
// When ReplaceUKI grows the image, these move with it.

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"math"
)

const (
	blockSize    = 512
	gptHeaderOff = blockSize // the primary GPT header is at LBA 1
	gptSignature = "EFI PART"
	mbrTableOff  = 446
)

// gptHeader returns the GPT header at off and its declared size, if there
// is a valid-looking one there.
func gptHeader(b []byte, off int) ([]byte, int, bool) {
	if off < 0 || off+blockSize > len(b) || string(b[off:off+8]) != gptSignature {
		return nil, 0, false
	}
	size := int(binary.LittleEndian.Uint32(b[off+12:]))
	if size < 92 || size > blockSize {
		return nil, 0, false
	}

	return b[off : off+size], size, true
}

// gptTailStart is the sector-aligned byte offset where the GPT backup (its
// entry array and header) begins, when the image has a GPT.
func gptTailStart(b []byte) (int, bool) {
	h, _, ok := gptHeader(b, gptHeaderOff)
	if !ok {
		return 0, false
	}
	alt := binary.LittleEndian.Uint64(h[32:])
	if alt == 0 || alt > uint64(len(b)/blockSize) {
		return 0, false
	}
	start := alt
	if bh, _, ok := gptHeader(b, int(alt)*blockSize); ok {
		start = min(start, binary.LittleEndian.Uint64(bh[72:]))
	}

	return int(start) * blockSize / SectorSize * SectorSize, true
}

// fixMBR updates the MBR partition entries for grow blocks inserted at
// block th: a partition that starts at or after th moves, and one that
// starts before th and reaches it grows.
func fixMBR(b []byte, th, grow uint64) {
	if len(b) < blockSize || b[510] != 0x55 || b[511] != 0xAA {
		return
	}
	for i := range 4 {
		e := b[mbrTableOff+16*i : mbrTableOff+16*(i+1)]
		if e[4] == 0 {
			continue
		}
		start := uint64(binary.LittleEndian.Uint32(e[8:]))
		size := uint64(binary.LittleEndian.Uint32(e[12:]))
		switch {
		case start >= th:
			start += grow
		case start+size >= th:
			size += grow
		}
		binary.LittleEndian.PutUint32(e[8:], uint32(min(start, math.MaxUint32)))
		binary.LittleEndian.PutUint32(e[12:], uint32(min(size, math.MaxUint32-min(start, math.MaxUint32))))
	}
}

// fixGPT updates the GPT for grow blocks inserted at block th: partitions
// and the last usable block that reach th grow, anything at or after th
// moves, the backup header and entry array (now at the new end of the image)
// get the new entries, and both headers get fresh CRCs.
func fixGPT(b []byte, th, grow uint64) error {
	h, _, ok := gptHeader(b, gptHeaderOff)
	if !ok {
		return nil
	}
	n := int(binary.LittleEndian.Uint32(h[80:]))
	esz := int(binary.LittleEndian.Uint32(h[84:]))
	entriesLBA := binary.LittleEndian.Uint64(h[72:])
	if esz < 128 || n <= 0 || n*esz > 1<<20 || entriesLBA >= th {
		return fmt.Errorf("%w: GPT with %d entries of %d bytes at block %d", ErrLayout, n, esz, entriesLBA)
	}
	eo := int(entriesLBA) * blockSize
	if eo+n*esz > len(b) {
		return fmt.Errorf("%w: the GPT entry array runs past the end of the image", ErrLayout)
	}
	entries := b[eo : eo+n*esz]
	shift := func(v uint64) uint64 {
		if v >= th {
			return v + grow
		}
		return v
	}
	for i := range n {
		e := entries[i*esz : (i+1)*esz]
		if allZero(e[:16]) {
			continue
		}
		first, last := binary.LittleEndian.Uint64(e[32:]), binary.LittleEndian.Uint64(e[40:])
		binary.LittleEndian.PutUint64(e[32:], shift(first))
		if last+1 >= th {
			binary.LittleEndian.PutUint64(e[40:], last+grow)
		}
	}
	entriesCRC := crc32.ChecksumIEEE(entries)

	lastUsable := binary.LittleEndian.Uint64(h[48:])
	if lastUsable+1 >= th {
		lastUsable += grow
	}
	oldAlt := binary.LittleEndian.Uint64(h[32:])
	alt := shift(oldAlt)
	binary.LittleEndian.PutUint64(h[32:], alt)
	binary.LittleEndian.PutUint64(h[48:], lastUsable)
	binary.LittleEndian.PutUint32(h[88:], entriesCRC)
	setHeaderCRC(h)

	bh, _, ok := gptHeader(b, int(alt)*blockSize)
	if !ok {
		// No backup where the primary says it is: nothing more to keep in
		// step.
		return nil
	}
	backupEntries := shift(binary.LittleEndian.Uint64(bh[72:]))
	beo := int(backupEntries) * blockSize
	if beo+len(entries) > len(b) {
		return fmt.Errorf("%w: the GPT backup entry array runs past the end of the image", ErrLayout)
	}
	copy(b[beo:], entries)
	binary.LittleEndian.PutUint64(bh[24:], alt)
	binary.LittleEndian.PutUint64(bh[48:], lastUsable)
	binary.LittleEndian.PutUint64(bh[72:], backupEntries)
	binary.LittleEndian.PutUint32(bh[88:], entriesCRC)
	setHeaderCRC(bh)

	return nil
}

// setHeaderCRC fills in a GPT header's CRC32, computed with the field zero.
func setHeaderCRC(h []byte) {
	binary.LittleEndian.PutUint32(h[16:], 0)
	binary.LittleEndian.PutUint32(h[16:], crc32.ChecksumIEEE(h))
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}

	return true
}
