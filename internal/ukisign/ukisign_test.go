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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"debug/pe"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"math/big"
	"strconv"
	"testing"
	"time"

	"github.com/CryptOS-PKI/cryptos-node/internal/imageupgrade"
	"github.com/CryptOS-PKI/cryptos-node/internal/ukipcr"
)

const (
	testLfanew   = 0x80
	testOptSize  = 240
	testSecAlign = 0x1000
	testFileAlgn = 0x200
	chrCode      = 0x60000020
	chrData      = 0x40000040
)

type testSection struct {
	name  string
	data  []byte
	chars uint32
}

// buildUKI writes a PE32+ image laid out the way a linker and ukify lay out a
// UKI: sections in table order at ascending, aligned RVAs and file offsets,
// raw data padded to the file alignment, the entry point in .text and the
// base relocation directory in .reloc.
func buildUKI(t *testing.T, sections ...testSection) []byte {
	t.Helper()

	align := func(v, a int) int { return (v + a - 1) / a * a }
	hdrEnd := testLfanew + 4 + coffHeaderSize + testOptSize + sectionHeaderSize*len(sections)
	sizeOfHeaders := align(hdrEnd, testFileAlgn)
	b := make([]byte, sizeOfHeaders)
	copy(b, "MZ")
	binary.LittleEndian.PutUint32(b[0x3c:], testLfanew)
	copy(b[testLfanew:], "PE\x00\x00")

	coff := testLfanew + 4
	binary.LittleEndian.PutUint16(b[coff:], 0x8664)
	binary.LittleEndian.PutUint16(b[coff+2:], uint16(len(sections)))
	binary.LittleEndian.PutUint16(b[coff+16:], testOptSize)
	binary.LittleEndian.PutUint16(b[coff+18:], 0x22)

	opt := coff + coffHeaderSize
	binary.LittleEndian.PutUint16(b[opt:], magicPE32Plus)
	binary.LittleEndian.PutUint32(b[opt+16:], testSecAlign)
	binary.LittleEndian.PutUint32(b[opt+32:], testSecAlign)
	binary.LittleEndian.PutUint32(b[opt+36:], testFileAlgn)
	binary.LittleEndian.PutUint32(b[opt+60:], uint32(sizeOfHeaders))
	binary.LittleEndian.PutUint16(b[opt+68:], 10)
	binary.LittleEndian.PutUint32(b[opt+108:], 16)

	va := testSecAlign
	var initData uint32
	for i, s := range sections {
		rawSize := align(len(s.data), testFileAlgn)
		hdr := opt + testOptSize + sectionHeaderSize*i
		copy(b[hdr:hdr+8], s.name)
		binary.LittleEndian.PutUint32(b[hdr+8:], uint32(len(s.data)))
		binary.LittleEndian.PutUint32(b[hdr+12:], uint32(va))
		binary.LittleEndian.PutUint32(b[hdr+16:], uint32(rawSize))
		binary.LittleEndian.PutUint32(b[hdr+20:], uint32(len(b)))
		binary.LittleEndian.PutUint32(b[hdr+36:], s.chars)
		if s.chars&scnInitData != 0 {
			initData += uint32(rawSize)
		}
		if s.name == ".reloc" {
			binary.LittleEndian.PutUint32(b[opt+112+5*8:], uint32(va))
			binary.LittleEndian.PutUint32(b[opt+112+5*8+4:], uint32(len(s.data)))
		}
		b = append(b, s.data...)
		b = append(b, make([]byte, rawSize-len(s.data))...)
		va = align(va+len(s.data), testSecAlign)
	}
	binary.LittleEndian.PutUint32(b[opt+8:], initData)
	binary.LittleEndian.PutUint32(b[opt+56:], uint32(va))

	return b
}

var (
	stubText    = bytes.Repeat([]byte("stub code "), 70)
	initrdBytes = []byte("\x1f\x8bnot really gzip, but the length is odd")
	kernelBytes = bytes.Repeat([]byte("kernel "), 300)
)

func stubSections() []testSection {
	return []testSection{
		{".text", stubText, chrCode},
		{".reloc", []byte{0, 0x10, 0, 0, 8, 0, 0, 0}, chrData},
		{".data", []byte("stub data"), chrData},
		{".sdmagic", []byte("#### LoaderInfo: systemd-stub 257 ####"), chrData},
	}
}

func testUKI(t *testing.T) []byte {
	t.Helper()

	return buildUKI(t, append(stubSections(),
		testSection{".osrel", []byte("ID=cryptos\n"), chrData},
		testSection{".cmdline", []byte("console=ttyS0"), chrData},
		testSection{".initrd", initrdBytes, chrData},
		testSection{".linux", kernelBytes, chrCode},
		testSection{".sbat", []byte("sbat,1,SBAT Version,sbat,1\n"), chrData},
	)...)
}

func testSigner(t *testing.T, cn string) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		NotAfter:     time.Now().Add(time.Hour),
		NotBefore:    time.Now().Add(-time.Hour),
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	return key, cert
}

func mustSign(t *testing.T, image []byte, key *rsa.PrivateKey, cert *x509.Certificate) Result {
	t.Helper()

	res, err := Sign(image, key, cert)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	return res
}

func openPE(t *testing.T, b []byte) *pe.File {
	t.Helper()

	f, err := pe.NewFile(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("debug/pe: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })

	return f
}

func sectionNamed(t *testing.T, f *pe.File, name string) (*pe.Section, int) {
	t.Helper()

	for i, s := range f.Sections {
		if s.Name == name {
			return s, i
		}
	}
	t.Fatalf("no section %s", name)

	return nil, 0
}

func loadedData(t *testing.T, s *pe.Section) []byte {
	t.Helper()

	raw, err := s.Data()
	if err != nil {
		t.Fatalf("read %s: %v", s.Name, err)
	}
	out := make([]byte, s.VirtualSize)
	copy(out, raw)

	return out
}

type cpioFile struct {
	name                         string
	mode, uid, gid, nlink, mtime uint32
	data                         []byte
}

// parseNewc reads one newc archive starting at off, up to and including its
// trailer, and returns its files and the offset just past it.
func parseNewc(t *testing.T, b []byte, off int) ([]cpioFile, int) {
	t.Helper()

	align4 := func(v int) int { return (v + 3) &^ 3 }
	var files []cpioFile
	for {
		if off+110 > len(b) || string(b[off:off+6]) != "070701" {
			t.Fatalf("no newc header at %d", off)
		}
		field := func(i int) uint32 {
			v, err := strconv.ParseUint(string(b[off+6+8*i:off+14+8*i]), 16, 32)
			if err != nil {
				t.Fatalf("newc field %d: %v", i, err)
			}
			return uint32(v)
		}
		nameSize, fileSize := int(field(11)), int(field(6))
		nameAt := off + 110
		name := string(b[nameAt : nameAt+nameSize-1])
		dataAt := align4(nameAt + nameSize)
		f := cpioFile{
			name: name, mode: field(1), uid: field(2), gid: field(3), nlink: field(4), mtime: field(5),
			data: b[dataAt : dataAt+fileSize],
		}
		off = align4(dataAt + fileSize)
		if name == "TRAILER!!!" {
			return files, off
		}
		files = append(files, f)
	}
}

// Everything before .initrd, which is all of systemd-stub, keeps its bytes,
// RVA and file offset; .initrd and what follows are re-laid out aligned and
// in order, and SizeOfImage covers them.
func TestSign_KeepsTheStubAndReLaysOutThePayload(t *testing.T) {
	key, cert := testSigner(t, "Example Release Signing")
	in := testUKI(t)
	res := mustSign(t, in, key, cert)

	fin, fout := openPE(t, in), openPE(t, res.Image)
	if len(fin.Sections) != len(fout.Sections) {
		t.Fatalf("section count %d -> %d", len(fin.Sections), len(fout.Sections))
	}
	_, idx := sectionNamed(t, fout, ".initrd")
	for i, so := range fout.Sections {
		si := fin.Sections[i]
		if so.Name != si.Name {
			t.Fatalf("section %d renamed %s -> %s", i, si.Name, so.Name)
		}
		if so.VirtualAddress%testSecAlign != 0 || so.Offset%testFileAlgn != 0 {
			t.Errorf("%s at RVA %#x offset %#x is not aligned", so.Name, so.VirtualAddress, so.Offset)
		}
		if i > 0 {
			prev := fout.Sections[i-1]
			if so.VirtualAddress < prev.VirtualAddress+prev.VirtualSize || so.Offset < prev.Offset+prev.Size {
				t.Errorf("%s overlaps %s or is out of order", so.Name, prev.Name)
			}
		}
		if i < idx {
			if so.SectionHeader != si.SectionHeader {
				t.Errorf("stub section %s header changed: %+v -> %+v", so.Name, si.SectionHeader, so.SectionHeader)
			}
			if !bytes.Equal(res.Image[so.Offset:so.Offset+so.Size], in[si.Offset:si.Offset+si.Size]) {
				t.Errorf("stub section %s bytes changed", so.Name)
			}
		}
		if i > idx && !bytes.Equal(loadedData(t, so), loadedData(t, si)) {
			t.Errorf("payload section %s contents changed", so.Name)
		}
	}

	oh := fout.OptionalHeader.(*pe.OptionalHeader64)
	last := fout.Sections[len(fout.Sections)-1]
	wantSize := (last.VirtualAddress + last.VirtualSize + testSecAlign - 1) &^ (testSecAlign - 1)
	if oh.SizeOfImage != wantSize {
		t.Errorf("SizeOfImage = %#x, want %#x", oh.SizeOfImage, wantSize)
	}
	ohIn := fin.OptionalHeader.(*pe.OptionalHeader64)
	if oh.AddressOfEntryPoint != ohIn.AddressOfEntryPoint || oh.DataDirectory[5] != ohIn.DataDirectory[5] {
		t.Error("entry point or base relocation directory moved")
	}
	initIn, _ := sectionNamed(t, fin, ".initrd")
	initOut, _ := sectionNamed(t, fout, ".initrd")
	if oh.SizeOfInitializedData != ohIn.SizeOfInitializedData+initOut.Size-initIn.Size {
		t.Errorf("SizeOfInitializedData = %#x, want it grown by the .initrd", oh.SizeOfInitializedData)
	}
	if oh.CheckSum == 0 || oh.CheckSum != checksumWithFieldZeroed(res.Image) {
		t.Errorf("CheckSum = %#x, want the PE checksum of the file", oh.CheckSum)
	}
}

func checksumWithFieldZeroed(b []byte) uint32 {
	c := bytes.Clone(b)
	off := int(binary.LittleEndian.Uint32(c[0x3c:])) + 4 + coffHeaderSize + 64
	binary.LittleEndian.PutUint32(c[off:], 0)

	return checksum(c)
}

// The .initrd keeps its original bytes and gains, at the next 4-byte
// boundary, a newc archive holding the certificate as upgrade-anchor.der.
func TestSign_AppendsTheAnchorArchive(t *testing.T) {
	key, cert := testSigner(t, "Example Release Signing")
	res := mustSign(t, testUKI(t), key, cert)

	s, _ := sectionNamed(t, openPE(t, res.Image), ".initrd")
	initrd := loadedData(t, s)
	if !bytes.HasPrefix(initrd, initrdBytes) {
		t.Fatal("the original initrd bytes were not kept")
	}
	at := (len(initrdBytes) + 3) &^ 3
	if !allZero(initrd[len(initrdBytes):at]) {
		t.Error("the gap before the anchor archive is not zeros")
	}
	files, end := parseNewc(t, initrd, at)
	if end != len(initrd) {
		t.Errorf("archive ends at %d, initrd at %d", end, len(initrd))
	}
	if len(files) != 1 {
		t.Fatalf("archive holds %d files, want 1", len(files))
	}
	f := files[0]
	if f.name != AnchorName || !bytes.Equal(f.data, cert.Raw) {
		t.Errorf("archive holds %q (%d bytes), want %q with the certificate", f.name, len(f.data), AnchorName)
	}
	if f.mode != 0o100444 || f.uid != 0 || f.gid != 0 || f.nlink != 1 || f.mtime != 0 {
		t.Errorf("file metadata mode=%o uid=%d gid=%d nlink=%d mtime=%d", f.mode, f.uid, f.gid, f.nlink, f.mtime)
	}
}

// Signing a signed image again appends a second anchor, which the kernel
// unpacks last so it wins, and replaces the Authenticode signature.
func TestSign_SigningAgainReplacesTheAnchor(t *testing.T) {
	key1, cert1 := testSigner(t, "Example Release Signing 1")
	key2, cert2 := testSigner(t, "Example Release Signing 2")
	first := mustSign(t, testUKI(t), key1, cert1)
	second := mustSign(t, first.Image, key2, cert2)

	s, _ := sectionNamed(t, openPE(t, second.Image), ".initrd")
	initrd := loadedData(t, s)
	filesA, end := parseNewc(t, initrd, (len(initrdBytes)+3)&^3)
	filesB, end := parseNewc(t, initrd, (end+3)&^3)
	if end != len(initrd) {
		t.Errorf("found data after the second archive (%d of %d)", end, len(initrd))
	}
	if len(filesA) != 1 || !bytes.Equal(filesA[0].data, cert1.Raw) {
		t.Error("the first archive does not hold the first certificate")
	}
	if len(filesB) != 1 || filesB[0].name != AnchorName || !bytes.Equal(filesB[0].data, cert2.Raw) {
		t.Error("the last archive does not hold the new certificate")
	}

	if err := Check(second.Image, second.Signature, cert2); err != nil {
		t.Errorf("Check with the new certificate: %v", err)
	}
	if err := Check(second.Image, second.Signature, cert1); err == nil {
		t.Error("Check passed with the old certificate")
	}
	p, err := parsePE(second.Image)
	if err != nil {
		t.Fatal(err)
	}
	if off, size := p.certTable(); int(off)+int(size) != len(second.Image) {
		t.Error("the image does not end with its single certificate table")
	}
	blob, err := p.certificateBlob()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, cert1.Raw) {
		t.Error("the old signature is still in the certificate table")
	}
}

// The Authenticode digest matches an independent computation. With sections
// packed straight after the headers, as here, the image hash is the SHA-256
// of the file up to the certificate table with the CheckSum field and the
// certificate table directory entry cut out.
func TestSign_AuthenticodeHashMatchesAnIndependentComputation(t *testing.T) {
	key, cert := testSigner(t, "Example Release Signing")
	res := mustSign(t, testUKI(t), key, cert)

	f := openPE(t, res.Image)
	oh := f.OptionalHeader.(*pe.OptionalHeader64)
	dir := oh.DataDirectory[dirSecurity]
	if dir.VirtualAddress == 0 || int(dir.VirtualAddress+dir.Size) != len(res.Image) || dir.VirtualAddress%8 != 0 {
		t.Fatalf("certificate table at %#x size %#x in a %#x byte file", dir.VirtualAddress, dir.Size, len(res.Image))
	}
	if f.Sections[0].Offset != oh.SizeOfHeaders {
		t.Fatal("test precondition: sections are not packed after the headers")
	}
	opt := testLfanew + 4 + coffHeaderSize
	csAt, sdAt := opt+64, opt+112+dirSecurity*8
	var buf []byte
	buf = append(buf, res.Image[:csAt]...)
	buf = append(buf, res.Image[csAt+4:sdAt]...)
	buf = append(buf, res.Image[sdAt+8:dir.VirtualAddress]...)
	want := sha256.Sum256(buf)

	entry := res.Image[dir.VirtualAddress:]
	if binary.LittleEndian.Uint32(entry) != dir.Size || binary.LittleEndian.Uint16(entry[4:]) != 0x0200 || binary.LittleEndian.Uint16(entry[6:]) != 0x0002 {
		t.Fatal("WIN_CERTIFICATE header is not revision 2.0 PKCS SignedData of the table's size")
	}
	got, err := verifyAuthenticode(entry[8:], cert)
	if err != nil {
		t.Fatalf("verifyAuthenticode: %v", err)
	}
	if !bytes.Equal(got, want[:]) {
		t.Errorf("signed image hash %x, independent %x", got, want)
	}
}

// The detached signature is the one `image stage` sends and the node checks.
func TestSign_DetachedSignatureVerifies(t *testing.T) {
	key, cert := testSigner(t, "Example Release Signing")
	res := mustSign(t, testUKI(t), key, cert)

	if err := imageupgrade.Verify(res.Image, res.Signature, cert); err != nil {
		t.Fatalf("imageupgrade.Verify: %v", err)
	}
	tampered := bytes.Clone(res.Image)
	tampered[len(tampered)/2] ^= 1
	if err := imageupgrade.Verify(tampered, res.Signature, cert); err == nil {
		t.Error("the detached signature verified over a tampered image")
	}
	if err := Check(tampered, res.Signature, cert); err == nil {
		t.Error("Check passed a tampered image")
	}
}

// A node sealed to PCR 11 must still be able to predict the signed image, and
// the prediction must change, because the anchor is measured with .initrd.
func TestSign_PCR11StaysPredictable(t *testing.T) {
	key, cert := testSigner(t, "Example Release Signing")
	in := testUKI(t)
	res := mustSign(t, in, key, cert)

	before, err := ukipcr.Predict(in)
	if err != nil {
		t.Fatalf("Predict(unsigned): %v", err)
	}
	after, err := ukipcr.Predict(res.Image)
	if err != nil {
		t.Fatalf("Predict(signed): %v", err)
	}
	if bytes.Equal(before.Value, after.Value) {
		t.Error("PCR 11 did not change, so the anchor is not measured")
	}
}

func TestSign_Refusals(t *testing.T) {
	key, cert := testSigner(t, "Example Release Signing")
	otherKey, _ := testSigner(t, "Someone Else")
	stub := stubSections()
	osrel := testSection{".osrel", []byte("ID=cryptos\n"), chrData}
	initrd := testSection{".initrd", initrdBytes, chrData}
	linux := testSection{".linux", kernelBytes, chrCode}

	trailing := append(testUKI(t), []byte("junk after the last section")...)
	entryLate := testUKI(t)
	binary.LittleEndian.PutUint32(entryLate[testLfanew+4+coffHeaderSize+16:], 0x100000)

	for name, image := range map[string][]byte{
		"not a PE":           []byte("this is not a PE image at all, just some text"),
		"no .initrd":         buildUKI(t, append(stub, osrel, linux)...),
		"two .initrd":        buildUKI(t, append(stub, osrel, initrd, initrd, linux)...),
		"no .linux":          buildUKI(t, append(stub, osrel, initrd)...),
		"two .linux":         buildUKI(t, append(stub, osrel, initrd, linux, linux)...),
		"multi-profile":      buildUKI(t, append(stub, osrel, testSection{".profile", []byte("ID=a"), chrData}, initrd, linux)...),
		"trailing data":      trailing,
		"entry after initrd": entryLate,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Sign(image, key, cert); !errors.Is(err, ErrNotUKI) {
				t.Errorf("err = %v, want ErrNotUKI", err)
			}
		})
	}

	t.Run("key does not match the certificate", func(t *testing.T) {
		if _, err := Sign(testUKI(t), otherKey, cert); err == nil {
			t.Error("Sign accepted a key that is not the certificate's")
		}
	})
	t.Run("non-RSA certificate", func(t *testing.T) {
		ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), NotAfter: time.Now().Add(time.Hour)}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &ec.PublicKey, ec)
		if err != nil {
			t.Fatal(err)
		}
		ecCert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Sign(testUKI(t), ec, ecCert); err == nil {
			t.Error("Sign accepted an ECDSA certificate")
		}
	})
}

func TestParseKey(t *testing.T) {
	key, _ := testSigner(t, "Example Release Signing")
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecPKCS8, err := x509.MarshalPKCS8PrivateKey(ec)
	if err != nil {
		t.Fatal(err)
	}

	for name, in := range map[string][]byte{
		"PKCS#1": pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
		"PKCS#8": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}),
	} {
		t.Run(name, func(t *testing.T) {
			got, err := ParseKey(in)
			if err != nil {
				t.Fatalf("ParseKey: %v", err)
			}
			if !key.PublicKey.Equal(got.Public()) {
				t.Error("ParseKey returned a different key")
			}
		})
	}
	for name, in := range map[string][]byte{
		"ECDSA":     pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ecPKCS8}),
		"encrypted": pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte{1}}),
		"no PEM":    []byte("not a key"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseKey(in); err == nil {
				t.Error("ParseKey accepted it")
			}
		})
	}
}

func TestParseCertificate(t *testing.T) {
	_, cert := testSigner(t, "Example Release Signing")
	for name, in := range map[string][]byte{
		"PEM": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}),
		"DER": cert.Raw,
	} {
		t.Run(name, func(t *testing.T) {
			got, err := ParseCertificate(in)
			if err != nil {
				t.Fatalf("ParseCertificate: %v", err)
			}
			if !got.Equal(cert) {
				t.Error("ParseCertificate returned a different certificate")
			}
		})
	}
	if _, err := ParseCertificate(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}})); err == nil {
		t.Error("ParseCertificate accepted a key block")
	}
}

func TestDefaultOut(t *testing.T) {
	for in, want := range map[string]string{
		"out/cryptos-amd64.uki.unsigned": "out/cryptos-amd64.uki",
		"cryptos-amd64.uki":              "cryptos-amd64.signed.uki",
		"image.efi":                      "image.efi.signed.uki",
	} {
		if got := DefaultOut(in); got != want {
			t.Errorf("DefaultOut(%q) = %q, want %q", in, got, want)
		}
	}
}
