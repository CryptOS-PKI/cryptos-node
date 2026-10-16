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
	"hash/crc32"
	"slices"
	"testing"

	"github.com/CryptOS-PKI/cryptos-node/internal/isoimage/isotest"
)

// testUKI stands in for a UKI: the package treats it as opaque bytes.
func testUKI(n int, fill byte) []byte {
	b := bytes.Repeat([]byte{fill}, n)
	copy(b, "MZ")
	return b
}

var variants = map[string]isotest.Options{
	"FAT12":                    {FAT: 12},
	"FAT16":                    {FAT: 16},
	"FAT32":                    {FAT: 32},
	"FAT16 GPT":                {FAT: 16, GPT: true},
	"FAT32 GPT":                {FAT: 32, GPT: true},
	"GPT inside the volume":    {FAT: 16, GPT: true, VolumeCoversTail: true},
	"MBR":                      {FAT: 16, MBR: true},
	"EFI in a catalog section": {FAT: 12, EFISection: true},
}

var wantCopies = []string{"El Torito EFI boot image /efiboot.img: EFI/BOOT/BOOTX64.EFI", "/cryptos.uki"}

func TestIsISO(t *testing.T) {
	iso := isotest.Build(t, testUKI(5000, 'u'), isotest.Options{})
	if !IsISO(iso.Image) {
		t.Error("IsISO = false for an ISO")
	}
	for name, b := range map[string][]byte{
		"empty":     nil,
		"a UKI":     testUKI(40000, 'u'),
		"too short": iso.Image[:16*SectorSize+5],
	} {
		if IsISO(b) {
			t.Errorf("IsISO = true for %s", name)
		}
	}
}

func TestOpen_FindsEveryCopy(t *testing.T) {
	uki := testUKI(9000, 'u')
	for name, o := range variants {
		t.Run(name, func(t *testing.T) {
			im, err := Open(isotest.Build(t, uki, o).Image)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(im.UKI(), uki) {
				t.Error("UKI() is not the UKI in the boot image")
			}
			if got := im.Copies(); !slices.Equal(got, wantCopies) {
				t.Errorf("Copies() = %q, want %q", got, wantCopies)
			}
		})
	}
}

func TestOpen_Refusals(t *testing.T) {
	uki := testUKI(9000, 'u')

	if _, err := Open(testUKI(100000, 'u')); !errors.Is(err, ErrNotISO) {
		t.Errorf("a UKI: err = %v, want ErrNotISO", err)
	}

	noBoot := isotest.Build(t, uki, isotest.Options{}).Image
	copy(noBoot[17*SectorSize+7:], "NOT EL TORITO")
	if _, err := Open(noBoot); !errors.Is(err, ErrNoUKI) {
		t.Errorf("no El Torito catalog: err = %v, want ErrNoUKI", err)
	}

	noFile := isotest.Build(t, uki, isotest.Options{FAT: 16})
	im, err := Open(noFile.Image)
	if err != nil {
		t.Fatal(err)
	}
	// Rename BOOTX64.EFI inside the FAT image.
	entry := im.boots[0].off + im.boots[0].entry
	copy(noFile.Image[entry:], "BOOTIA32EFI")
	if _, err := Open(noFile.Image); !errors.Is(err, ErrNoUKI) {
		t.Errorf("no BOOTX64.EFI: err = %v, want ErrNoUKI", err)
	}
}

func TestReplaceUKI_GrowsEveryCopy(t *testing.T) {
	uki := testUKI(9000, 'u')
	// A signed UKI is a few kilobytes larger, enough to outgrow both the
	// file's extent in the tree and its last FAT cluster.
	next := testUKI(9000+5000, 's')
	for name, o := range variants {
		t.Run(name, func(t *testing.T) {
			built := isotest.Build(t, uki, o)
			in := bytes.Clone(built.Image)
			im, err := Open(built.Image)
			if err != nil {
				t.Fatal(err)
			}
			out, err := im.ReplaceUKI(next)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(built.Image, in) {
				t.Error("ReplaceUKI changed its input")
			}
			grow := sectors(len(next)) * SectorSize
			if len(out) != len(in)+grow {
				t.Fatalf("len(out) = %d, want %d", len(out), len(in)+grow)
			}

			got, err := Open(out)
			if err != nil {
				t.Fatalf("re-open: %v", err)
			}
			if !bytes.Equal(got.UKI(), next) {
				t.Error("the boot image does not hold the new UKI")
			}
			if !slices.Equal(got.Copies(), wantCopies) {
				t.Errorf("Copies() after = %q, want %q", got.Copies(), wantCopies)
			}

			// The tree copy moved to the old insertion point; its old
			// sectors are zero.
			rec := recordFor(t, got, "/cryptos.uki")
			if int(rec.lba) != built.VolumeEnd || int(rec.size) != len(next) {
				t.Errorf("/cryptos.uki at sector %d size %d, want sector %d size %d", rec.lba, rec.size, built.VolumeEnd, len(next))
			}
			old := out[built.UKILBA*SectorSize : (built.UKILBA+sectors(len(uki)))*SectorSize]
			if !allZero(old) {
				t.Error("the old /cryptos.uki sectors were not cleared")
			}

			vol := binary.LittleEndian.Uint32(in[16*SectorSize+80:])
			if gotVol := binary.LittleEndian.Uint32(out[16*SectorSize+80:]); gotVol != vol+uint32(grow/SectorSize) ||
				binary.BigEndian.Uint32(out[16*SectorSize+84:]) != gotVol {
				t.Errorf("volume space size = %d, want %d in both byte orders", gotVol, vol+uint32(grow/SectorSize))
			}

			// Nothing else changed: the other FAT file, the file in the
			// subdirectory and the boot image's place and size.
			v := fatOf(t, got)
			if data := readFATFile(t, v, "STARTUP.NSH"); !bytes.Equal(data, isotest.OtherFile) {
				t.Error("STARTUP.NSH changed")
			}
			readme := recordFor(t, got, "/docs/readme.txt")
			if !bytes.Equal(out[int(readme.lba)*SectorSize:int(readme.lba)*SectorSize+int(readme.size)], isotest.Readme) {
				t.Error("/docs/readme.txt changed")
			}
			if got.boots[0].off != built.EFILBA*SectorSize || got.boots[0].size != built.FATSize {
				t.Error("the FAT boot image moved or changed size")
			}
			if v.kind == 32 {
				checkFSInfo(t, v)
			}

			switch {
			case o.GPT:
				checkGPT(t, out, built)
			case o.MBR:
				checkMBR(t, out, built)
			}
		})
	}
}

func TestReplaceUKI_SameSizeStaysInPlace(t *testing.T) {
	uki := testUKI(9000, 'u')
	built := isotest.Build(t, uki, isotest.Options{FAT: 16, GPT: true})
	im, err := Open(built.Image)
	if err != nil {
		t.Fatal(err)
	}
	next := testUKI(9000, 's')
	out, err := im.ReplaceUKI(next)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != len(built.Image) {
		t.Fatalf("len(out) = %d, want %d", len(out), len(built.Image))
	}
	got, err := Open(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.UKI(), next) || len(got.Copies()) != 2 {
		t.Fatalf("copies after = %q", got.Copies())
	}
	if rec := recordFor(t, got, "/cryptos.uki"); int(rec.lba) != built.UKILBA {
		t.Errorf("/cryptos.uki moved to sector %d, want %d", rec.lba, built.UKILBA)
	}
	// The partition tables are untouched.
	if !bytes.Equal(out[:16*SectorSize], built.Image[:16*SectorSize]) {
		t.Error("the system area changed")
	}
}

func TestReplaceUKI_OnlyTheBootImage(t *testing.T) {
	uki := testUKI(9000, 'u')
	built := isotest.Build(t, uki, isotest.Options{FAT: 32, NoTreeCopy: true})
	im, err := Open(built.Image)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(im.Copies()); n != 1 {
		t.Fatalf("Copies() = %q, want only the boot image", im.Copies())
	}
	next := testUKI(14000, 's')
	out, err := im.ReplaceUKI(next)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != len(built.Image) {
		t.Errorf("len(out) = %d, want %d: only the FAT image changes", len(out), len(built.Image))
	}
	got, err := Open(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.UKI(), next) {
		t.Error("the boot image does not hold the new UKI")
	}
}

func TestReplaceUKI_FullFATIsRefused(t *testing.T) {
	uki := testUKI(9000, 'u')
	built := isotest.Build(t, uki, isotest.Options{FAT: 12, TightFAT: true})
	im, err := Open(built.Image)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := im.ReplaceUKI(testUKI(14000, 's')); !errors.Is(err, ErrFATFull) {
		t.Errorf("err = %v, want ErrFATFull", err)
	}
	if _, err := im.ReplaceUKI(nil); err == nil {
		t.Error("an empty UKI was accepted")
	}
}

func recordFor(t *testing.T, im *Image, p string) fileRec {
	t.Helper()
	for _, f := range im.files {
		if f.path == p {
			return f
		}
	}
	t.Fatalf("no %s in the tree", p)
	return fileRec{}
}

func fatOf(t *testing.T, im *Image) *fatVolume {
	t.Helper()
	bt := im.boots[0]
	v, err := openFAT(im.b[bt.off : bt.off+bt.size])
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func readFATFile(t *testing.T, v *fatVolume, p ...string) []byte {
	t.Helper()
	o, err := v.find(p)
	if err != nil {
		t.Fatal(err)
	}
	data, err := v.readFile(o)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func checkFSInfo(t *testing.T, v *fatVolume) {
	t.Helper()
	var free uint32
	for c := uint32(2); c < uint32(v.clusters)+2; c++ {
		if v.get(c) == 0 {
			free++
		}
	}
	if len(v.fsInfo) == 0 {
		t.Fatal("no FSInfo sector found")
	}
	for _, o := range v.fsInfo {
		if got := binary.LittleEndian.Uint32(v.b[o+488:]); got != free {
			t.Errorf("FSInfo free count = %d, want %d", got, free)
		}
	}
}

// checkGPT reads the GPT back on its own terms: both headers carry valid
// CRCs, the backup is in the last block, the partition over the volume grew
// with it, and the one over the boot image did not move.
func checkGPT(t *testing.T, out []byte, built isotest.ISO) {
	t.Helper()
	blocks := uint64(len(out) / 512)
	header := func(lba uint64) []byte {
		h := out[lba*512 : lba*512+92]
		if string(h[:8]) != "EFI PART" {
			t.Fatalf("no GPT header at block %d", lba)
		}
		c := bytes.Clone(h)
		binary.LittleEndian.PutUint32(c[16:], 0)
		if crc32.ChecksumIEEE(c) != binary.LittleEndian.Uint32(h[16:]) {
			t.Errorf("GPT header at block %d has a bad CRC", lba)
		}
		return h
	}
	primary := header(1)
	if alt := binary.LittleEndian.Uint64(primary[32:]); alt != blocks-1 {
		t.Fatalf("primary header's backup LBA = %d, want %d", alt, blocks-1)
	}
	backup := header(blocks - 1)
	if my := binary.LittleEndian.Uint64(backup[24:]); my != blocks-1 {
		t.Errorf("backup header's own LBA = %d, want %d", my, blocks-1)
	}
	entries := func(h []byte) []byte {
		at := binary.LittleEndian.Uint64(h[72:])
		e := out[at*512 : at*512+128*128]
		if crc32.ChecksumIEEE(e) != binary.LittleEndian.Uint32(h[88:]) {
			t.Errorf("entry array at block %d has a bad CRC", at)
		}
		return e
	}
	pe, be := entries(primary), entries(backup)
	if !bytes.Equal(pe, be) {
		t.Error("the backup entry array differs from the primary")
	}
	backupAt := binary.LittleEndian.Uint64(backup[72:])
	if last := binary.LittleEndian.Uint64(primary[48:]); last != backupAt-1 {
		t.Errorf("last usable LBA = %d, want %d", last, backupAt-1)
	}
	grow := uint64(len(out)-len(built.Image)) / 512
	if last := binary.LittleEndian.Uint64(pe[40:]); last != uint64(built.VolumeEnd)*4-1+grow {
		t.Errorf("the ISO partition ends at %d, want %d", last, uint64(built.VolumeEnd)*4-1+grow)
	}
	efiFirst := uint64(built.EFILBA) * 4
	if first, last := binary.LittleEndian.Uint64(pe[128+32:]), binary.LittleEndian.Uint64(pe[128+40:]); first != efiFirst ||
		last != efiFirst+uint64(built.FATSize/512)-1 {
		t.Errorf("the EFI partition is %d-%d, want it unchanged", first, last)
	}
	if size := binary.LittleEndian.Uint32(out[446+12:]); uint64(size) != blocks-1 {
		t.Errorf("protective MBR size = %d, want %d", size, blocks-1)
	}
}

func checkMBR(t *testing.T, out []byte, built isotest.ISO) {
	t.Helper()
	if size := binary.LittleEndian.Uint32(out[446+12:]); int(size) != len(out)/512 {
		t.Errorf("MBR partition 1 size = %d, want %d", size, len(out)/512)
	}
	if start, size := binary.LittleEndian.Uint32(out[446+16+8:]), binary.LittleEndian.Uint32(out[446+16+12:]); int(start) != built.EFILBA*4 ||
		int(size) != built.FATSize/512 {
		t.Errorf("MBR partition 2 = %d+%d, want it unchanged", start, size)
	}
}
