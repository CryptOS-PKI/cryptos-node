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
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

const (
	dirEntrySize  = 32
	attrVolumeID  = 0x08
	attrDirectory = 0x10
	attrLongName  = 0x0F
	fsInfoLead    = 0x41615252
	fsInfoStruct  = 0x61417272
)

// ErrFATFull is wrapped when the FAT boot image has too little free space
// for the new UKI.
var ErrFATFull = errors.New("isoimage: the FAT boot image has no room for the new UKI")

// fatVolume is a FAT12, FAT16 or FAT32 file system image, read and written
// in place.
type fatVolume struct {
	b           []byte
	bps         int
	clusterSize int
	nFATs       int
	fatOff      int // byte offset of the first FAT
	fatBytes    int // bytes per FAT
	rootDirOff  int // FAT12/16: byte offset of the fixed root directory
	rootDirLen  int
	dataOff     int
	clusters    int // number of data clusters
	kind        int // 12, 16 or 32
	rootClus    uint32
	fsInfo      []int // byte offsets of the FAT32 FSInfo sector and its backup
}

// openFAT parses the FAT boot sector at the start of b. The volume it
// returns covers exactly the file system's sectors.
func openFAT(b []byte) (*fatVolume, error) {
	if len(b) < 512 || b[510] != 0x55 || b[511] != 0xAA {
		return nil, errors.New("isoimage: no FAT boot sector")
	}
	le16 := func(o int) int { return int(binary.LittleEndian.Uint16(b[o:])) }
	le32 := func(o int) int { return int(binary.LittleEndian.Uint32(b[o:])) }
	bps, spc, reserved, nFATs := le16(11), int(b[13]), le16(14), int(b[16])
	rootEnt, total, fatSz := le16(17), le16(19), le16(22)
	if total == 0 {
		total = le32(32)
	}
	if fatSz == 0 {
		fatSz = le32(36)
	}
	switch {
	case bps != 512 && bps != 1024 && bps != 2048 && bps != 4096:
		return nil, fmt.Errorf("isoimage: FAT sector size %d", bps)
	case spc == 0 || spc&(spc-1) != 0:
		return nil, fmt.Errorf("isoimage: FAT sectors per cluster %d", spc)
	case reserved == 0 || nFATs == 0 || fatSz == 0 || total == 0:
		return nil, errors.New("isoimage: FAT boot sector has a zero reserved, FAT or total sector count")
	}
	rootDirSectors := (rootEnt*dirEntrySize + bps - 1) / bps
	meta := reserved + nFATs*fatSz + rootDirSectors
	if total <= meta || total*bps > len(b) {
		return nil, fmt.Errorf("isoimage: FAT image of %d sectors does not fit its %d bytes", total, len(b))
	}
	v := &fatVolume{
		b:           b[:total*bps],
		bps:         bps,
		clusterSize: spc * bps,
		nFATs:       nFATs,
		fatOff:      reserved * bps,
		fatBytes:    fatSz * bps,
		rootDirOff:  (reserved + nFATs*fatSz) * bps,
		rootDirLen:  rootDirSectors * bps,
		dataOff:     meta * bps,
		clusters:    (total - meta) / spc,
	}
	switch {
	case v.clusters < 4085:
		v.kind = 12
	case v.clusters < 65525:
		v.kind = 16
	default:
		v.kind = 32
	}
	if (v.clusters+2)*v.kind > v.fatBytes*8 {
		return nil, errors.New("isoimage: the FAT is too small for the cluster count")
	}
	if v.kind == 32 {
		if rootEnt != 0 {
			return nil, errors.New("isoimage: FAT32 boot sector with a fixed root directory")
		}
		v.rootClus = binary.LittleEndian.Uint32(b[44:])
		for _, sec := range []int{le16(48), le16(50) + 1} {
			o := sec * bps
			if sec > 0 && sec < reserved && o+512 <= len(v.b) &&
				binary.LittleEndian.Uint32(v.b[o:]) == fsInfoLead &&
				binary.LittleEndian.Uint32(v.b[o+484:]) == fsInfoStruct {
				v.fsInfo = append(v.fsInfo, o)
			}
		}
	}

	return v, nil
}

func (v *fatVolume) get(c uint32) uint32 {
	switch v.kind {
	case 12:
		w := binary.LittleEndian.Uint16(v.b[v.fatOff+int(c)+int(c)/2:])
		if c&1 == 1 {
			return uint32(w >> 4)
		}
		return uint32(w & 0x0FFF)
	case 16:
		return uint32(binary.LittleEndian.Uint16(v.b[v.fatOff+int(c)*2:]))
	default:
		return binary.LittleEndian.Uint32(v.b[v.fatOff+int(c)*4:]) & 0x0FFFFFFF
	}
}

// set writes entry c in every copy of the FAT.
func (v *fatVolume) set(c, val uint32) {
	for i := range v.nFATs {
		base := v.fatOff + i*v.fatBytes
		switch v.kind {
		case 12:
			o := base + int(c) + int(c)/2
			w := binary.LittleEndian.Uint16(v.b[o:])
			if c&1 == 1 {
				w = w&0x000F | uint16(val&0x0FFF)<<4
			} else {
				w = w&0xF000 | uint16(val&0x0FFF)
			}
			binary.LittleEndian.PutUint16(v.b[o:], w)
		case 16:
			binary.LittleEndian.PutUint16(v.b[base+int(c)*2:], uint16(val))
		default:
			o := base + int(c)*4
			old := binary.LittleEndian.Uint32(v.b[o:])
			binary.LittleEndian.PutUint32(v.b[o:], old&0xF0000000|val&0x0FFFFFFF)
		}
	}
}

func (v *fatVolume) endOfChain() uint32 {
	switch v.kind {
	case 12:
		return 0xFFF
	case 16:
		return 0xFFFF
	default:
		return 0x0FFFFFFF
	}
}

func (v *fatVolume) isEndOfChain(x uint32) bool {
	switch v.kind {
	case 12:
		return x >= 0xFF8
	case 16:
		return x >= 0xFFF8
	default:
		return x >= 0x0FFFFFF8
	}
}

// chain follows the cluster chain that starts at start.
func (v *fatVolume) chain(start uint32) ([]uint32, error) {
	var cs []uint32
	for c := start; !v.isEndOfChain(c); c = v.get(c) {
		if c < 2 || c >= uint32(v.clusters)+2 {
			return nil, fmt.Errorf("isoimage: the FAT chain from cluster %d reaches cluster %#x", start, c)
		}
		if len(cs) >= v.clusters {
			return nil, fmt.Errorf("isoimage: the FAT chain from cluster %d loops", start)
		}
		cs = append(cs, c)
	}

	return cs, nil
}

func (v *fatVolume) clusterOff(c uint32) int { return v.dataOff + (int(c)-2)*v.clusterSize }

// dirEntries lists the byte offset of every entry slot of a directory: the
// fixed FAT12/16 root when first is 0, else the directory's cluster chain.
func (v *fatVolume) dirEntries(first uint32) ([]int, error) {
	var offs []int
	if first == 0 && v.kind != 32 {
		for o := 0; o+dirEntrySize <= v.rootDirLen; o += dirEntrySize {
			offs = append(offs, v.rootDirOff+o)
		}
		return offs, nil
	}
	if first == 0 {
		first = v.rootClus
	}
	cs, err := v.chain(first)
	if err != nil {
		return nil, err
	}
	for _, c := range cs {
		for o := 0; o+dirEntrySize <= v.clusterSize; o += dirEntrySize {
			offs = append(offs, v.clusterOff(c)+o)
		}
	}

	return offs, nil
}

// find returns the offset of the directory entry at p, a path of 8.3 names
// from the root.
func (v *fatVolume) find(p []string) (int, error) {
	dir := uint32(0)
	for i, name := range p {
		offs, err := v.dirEntries(dir)
		if err != nil {
			return 0, err
		}
		o, ok := v.lookup(offs, shortName(name))
		if !ok {
			return 0, fmt.Errorf("isoimage: %s not found", strings.Join(p[:i+1], "/"))
		}
		isDir := v.b[o+11]&attrDirectory != 0
		if i == len(p)-1 {
			if isDir {
				return 0, fmt.Errorf("isoimage: %s is a directory", strings.Join(p, "/"))
			}
			return o, nil
		}
		if !isDir {
			return 0, fmt.Errorf("isoimage: %s is not a directory", strings.Join(p[:i+1], "/"))
		}
		dir = v.firstCluster(o)
		if dir == 0 {
			return 0, fmt.Errorf("isoimage: directory %s has no clusters", strings.Join(p[:i+1], "/"))
		}
	}

	return 0, errors.New("isoimage: empty FAT path")
}

func (v *fatVolume) lookup(offs []int, name [11]byte) (int, bool) {
	for _, o := range offs {
		e := v.b[o : o+dirEntrySize]
		switch {
		case e[0] == 0x00:
			return 0, false
		case e[0] == 0xE5, e[11]&attrLongName == attrLongName, e[11]&attrVolumeID != 0:
			continue
		}
		if [11]byte(e[:11]) == name {
			return o, true
		}
	}

	return 0, false
}

// shortName is the space-padded, upper-case 8.3 form of name.
func shortName(name string) [11]byte {
	var s [11]byte
	for i := range s {
		s[i] = ' '
	}
	base, ext, _ := strings.Cut(strings.ToUpper(name), ".")
	copy(s[:8], base)
	copy(s[8:], ext)

	return s
}

func (v *fatVolume) firstCluster(o int) uint32 {
	c := uint32(binary.LittleEndian.Uint16(v.b[o+26:]))
	if v.kind == 32 {
		c |= uint32(binary.LittleEndian.Uint16(v.b[o+20:])) << 16
	}

	return c
}

// readFile returns the content of the file whose directory entry is at o.
func (v *fatVolume) readFile(o int) ([]byte, error) {
	size := int(binary.LittleEndian.Uint32(v.b[o+28:]))
	if size == 0 {
		return []byte{}, nil
	}
	cs, err := v.chain(v.firstCluster(o))
	if err != nil {
		return nil, err
	}
	if len(cs)*v.clusterSize < size {
		return nil, fmt.Errorf("isoimage: a %d-byte file has only %d clusters", size, len(cs))
	}
	data := make([]byte, 0, size)
	for _, c := range cs {
		n := min(v.clusterSize, size-len(data))
		data = append(data, v.b[v.clusterOff(c):v.clusterOff(c)+n]...)
	}

	return data, nil
}

// replaceFile gives the file whose directory entry is at o the content data:
// it frees the old cluster chain, allocates a new one (contiguous when there
// is room), writes data and updates the entry's size and first cluster.
func (v *fatVolume) replaceFile(o int, data []byte) error {
	if first := v.firstCluster(o); first != 0 {
		old, err := v.chain(first)
		if err != nil {
			return err
		}
		for _, c := range old {
			v.set(c, 0)
		}
	}
	cs, err := v.allocate((len(data) + v.clusterSize - 1) / v.clusterSize)
	if err != nil {
		return err
	}
	for i, c := range cs {
		next := v.endOfChain()
		if i+1 < len(cs) {
			next = cs[i+1]
		}
		v.set(c, next)
		dst := v.b[v.clusterOff(c) : v.clusterOff(c)+v.clusterSize]
		clear(dst[copy(dst, data[i*v.clusterSize:]):])
	}
	var first uint32
	if len(cs) > 0 {
		first = cs[0]
	}
	binary.LittleEndian.PutUint16(v.b[o+26:], uint16(first))
	if v.kind == 32 {
		binary.LittleEndian.PutUint16(v.b[o+20:], uint16(first>>16))
	}
	binary.LittleEndian.PutUint32(v.b[o+28:], uint32(len(data)))
	v.updateFSInfo()

	return nil
}

// allocate picks n free clusters: the first contiguous run of n when there
// is one, else the first n free clusters.
func (v *fatVolume) allocate(n int) ([]uint32, error) {
	if n == 0 {
		return nil, nil
	}
	var free []uint32
	runStart, runLen := uint32(0), 0
	for c := uint32(2); c < uint32(v.clusters)+2; c++ {
		if v.get(c) != 0 {
			runLen = 0
			continue
		}
		free = append(free, c)
		if runLen == 0 {
			runStart = c
		}
		runLen++
		if runLen == n {
			cs := make([]uint32, n)
			for i := range cs {
				cs[i] = runStart + uint32(i)
			}
			return cs, nil
		}
	}
	if len(free) < n {
		return nil, fmt.Errorf("%w: it needs %d clusters and %d are free", ErrFATFull, n, len(free))
	}

	return free[:n], nil
}

// updateFSInfo rewrites the FAT32 free-cluster count hint and clears the
// next-free hint.
func (v *fatVolume) updateFSInfo() {
	if len(v.fsInfo) == 0 {
		return
	}
	var free uint32
	for c := uint32(2); c < uint32(v.clusters)+2; c++ {
		if v.get(c) == 0 {
			free++
		}
	}
	for _, o := range v.fsInfo {
		binary.LittleEndian.PutUint32(v.b[o+488:], free)
		binary.LittleEndian.PutUint32(v.b[o+492:], 0xFFFFFFFF)
	}
}
