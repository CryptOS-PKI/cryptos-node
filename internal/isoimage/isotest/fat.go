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
	"encoding/binary"
	"testing"
)

const fatSector = 512

// fatImage is a FAT file system being written: one sector per cluster, two
// FATs.
type fatImage struct {
	b        []byte
	kind     int
	reserved int
	fatSz    int
	rootOff  int // FAT12/16 fixed root directory
	dataOff  int
	next     uint32
}

func (f *fatImage) set(c, val uint32) {
	for i := range 2 {
		base := (f.reserved + i*f.fatSz) * fatSector
		switch f.kind {
		case 12:
			o := base + int(c)*3/2
			w := binary.LittleEndian.Uint16(f.b[o:])
			if c%2 == 1 {
				w = w&0x000F | uint16(val&0xFFF)<<4
			} else {
				w = w&0xF000 | uint16(val&0xFFF)
			}
			binary.LittleEndian.PutUint16(f.b[o:], w)
		case 16:
			binary.LittleEndian.PutUint16(f.b[base+int(c)*2:], uint16(val))
		default:
			binary.LittleEndian.PutUint32(f.b[base+int(c)*4:], val&0x0FFFFFFF)
		}
	}
}

func (f *fatImage) eoc() uint32 {
	switch f.kind {
	case 12:
		return 0xFFF
	case 16:
		return 0xFFFF
	default:
		return 0x0FFFFFFF
	}
}

// alloc chains the next n clusters and returns the first (0 for n == 0).
func (f *fatImage) alloc(n int) uint32 {
	if n == 0 {
		return 0
	}
	first := f.next
	for i := range n {
		c := first + uint32(i)
		next := c + 1
		if i == n-1 {
			next = f.eoc()
		}
		f.set(c, next)
	}
	f.next += uint32(n)

	return first
}

func (f *fatImage) cluster(c uint32) []byte {
	o := f.dataOff + (int(c)-2)*fatSector
	return f.b[o : o+fatSector]
}

func (f *fatImage) write(first uint32, data []byte) {
	for i := 0; i*fatSector < len(data); i++ {
		copy(f.cluster(first+uint32(i)), data[i*fatSector:])
	}
}

func dirEntry(name string, attr byte, first uint32, size int) []byte {
	e := make([]byte, 32)
	copy(e, name)
	e[11] = attr
	binary.LittleEndian.PutUint16(e[20:], uint16(first>>16))
	binary.LittleEndian.PutUint16(e[26:], uint16(first))
	binary.LittleEndian.PutUint32(e[28:], uint32(size))
	return e
}

func clustersFor(n int) int { return (n + fatSector - 1) / fatSector }

// buildFAT writes a FAT image of the given type holding EFI/BOOT/BOOTX64.EFI
// (uki) and STARTUP.NSH (OtherFile), allocated in that order. tight leaves
// no free cluster.
func buildFAT(t testing.TB, kind int, uki []byte, tight bool) []byte {
	t.Helper()
	reserved, rootEnt := 1, 512
	if kind == 32 {
		reserved, rootEnt = 32, 0
	}
	rootSecs := rootEnt * 32 / fatSector
	need := 2 + clustersFor(len(uki)) + clustersFor(len(OtherFile))
	if kind == 32 {
		need++
	}

	var total, fatSz int
	if tight {
		for fatSz = 1; ; fatSz++ {
			if fatSz*fatSector*8 >= (need+2)*kind {
				break
			}
		}
		total = reserved + 2*fatSz + rootSecs + need
	} else {
		switch kind {
		case 12:
			total = 2048
		case 16:
			total = 16384
		default:
			total = 70000
		}
		fatSz = ((total+2)*kind/8 + fatSector) / fatSector
	}
	clusters := total - reserved - 2*fatSz - rootSecs
	got := 32
	switch {
	case clusters < 4085:
		got = 12
	case clusters < 65525:
		got = 16
	}
	if got != kind || clusters < need {
		t.Fatalf("isotest: a FAT%d layout came out as FAT%d with %d clusters (need %d)", kind, got, clusters, need)
	}

	f := &fatImage{
		b:        make([]byte, total*fatSector),
		kind:     kind,
		reserved: reserved,
		fatSz:    fatSz,
		rootOff:  (reserved + 2*fatSz) * fatSector,
		dataOff:  (reserved + 2*fatSz + rootSecs) * fatSector,
		next:     2,
	}
	b := f.b
	copy(b, []byte{0xEB, 0x3C, 0x90})
	copy(b[3:11], "mkfs.fat")
	binary.LittleEndian.PutUint16(b[11:], fatSector)
	b[13] = 1
	binary.LittleEndian.PutUint16(b[14:], uint16(reserved))
	b[16] = 2
	binary.LittleEndian.PutUint16(b[17:], uint16(rootEnt))
	if total < 65536 {
		binary.LittleEndian.PutUint16(b[19:], uint16(total))
	} else {
		binary.LittleEndian.PutUint32(b[32:], uint32(total))
	}
	b[21] = 0xF8
	if kind == 32 {
		binary.LittleEndian.PutUint32(b[36:], uint32(fatSz))
		binary.LittleEndian.PutUint32(b[44:], 2)
		binary.LittleEndian.PutUint16(b[48:], 1)
		binary.LittleEndian.PutUint16(b[50:], 6)
	} else {
		binary.LittleEndian.PutUint16(b[22:], uint16(fatSz))
	}
	b[510], b[511] = 0x55, 0xAA

	f.set(0, 0x0FFFFFF8)
	f.set(1, f.eoc())

	var root []byte
	var rootClus uint32
	if kind == 32 {
		rootClus = f.alloc(1)
	}
	efi := f.alloc(1)
	boot := f.alloc(1)
	ukiFirst := f.alloc(clustersFor(len(uki)))
	other := f.alloc(clustersFor(len(OtherFile)))

	root = append(root, dirEntry("CRYPTOS    ", 0x08, 0, 0)...)
	root = append(root, dirEntry("EFI        ", 0x10, efi, 0)...)
	root = append(root, dirEntry("STARTUP NSH", 0x20, other, len(OtherFile))...)
	if kind == 32 {
		copy(f.cluster(rootClus), root)
	} else {
		copy(b[f.rootOff:], root)
	}
	efiDir := append(dirEntry(".          ", 0x10, efi, 0), dirEntry("..         ", 0x10, 0, 0)...)
	efiDir = append(efiDir, dirEntry("BOOT       ", 0x10, boot, 0)...)
	copy(f.cluster(efi), efiDir)
	bootDir := append(dirEntry(".          ", 0x10, boot, 0), dirEntry("..         ", 0x10, efi, 0)...)
	// A long-name entry ahead of the short one, as some tools write.
	lfn := make([]byte, 32)
	lfn[0], lfn[11] = 0x41, 0x0F
	copy(lfn[1:], []byte{'b', 0, 'o', 0, 'o', 0, 't', 0, 'x', 0})
	bootDir = append(bootDir, lfn...)
	bootDir = append(bootDir, dirEntry("BOOTX64 EFI", 0x20, ukiFirst, len(uki))...)
	copy(f.cluster(boot), bootDir)
	f.write(ukiFirst, uki)
	f.write(other, OtherFile)

	if kind == 32 {
		free := uint32(clusters + 2 - int(f.next))
		for _, sec := range []int{1, 7} {
			s := b[sec*fatSector:]
			binary.LittleEndian.PutUint32(s, 0x41615252)
			binary.LittleEndian.PutUint32(s[484:], 0x61417272)
			binary.LittleEndian.PutUint32(s[488:], free)
			binary.LittleEndian.PutUint32(s[492:], f.next)
			binary.LittleEndian.PutUint32(s[508:], 0xAA550000)
		}
		copy(b[6*fatSector:7*fatSector], b[:fatSector])
	}

	return b
}
