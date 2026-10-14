package imageupgrade

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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"
)

// memFS is the ESP in memory. failWrite lets a test interrupt the sequence at
// the point that decides whether a node is left bootable. ops records every
// call in order (including Sync), so a test can assert the directory sync
// happens after the rename that it is meant to make durable.
type memFS struct {
	files     map[string][]byte
	failWrite map[string]error
	failSync  error
	writes    []string
	ops       []string
}

func newMemFS() *memFS {
	return &memFS{failWrite: map[string]error{}, files: map[string][]byte{}}
}

func (m *memFS) Exists(rel string) (bool, error) { _, ok := m.files[rel]; return ok, nil }

func (m *memFS) ReadFile(rel string) ([]byte, error) {
	data, ok := m.files[rel]
	if !ok {
		return nil, errors.New("not found: " + rel)
	}

	return data, nil
}

func (m *memFS) Remove(rel string) error { delete(m.files, rel); return nil }

func (m *memFS) Rename(from, to string) error {
	m.ops = append(m.ops, "rename:"+from+"->"+to)
	data, ok := m.files[from]
	if !ok {
		return errors.New("not found: " + from)
	}
	m.files[to] = data
	delete(m.files, from)

	return nil
}

func (m *memFS) WriteFile(rel string, data []byte) error {
	m.writes = append(m.writes, rel)
	m.ops = append(m.ops, "write:"+rel)
	if err := m.failWrite[rel]; err != nil {
		return err
	}
	m.files[rel] = append([]byte(nil), data...)

	return nil
}

// Sync stands in for fsyncing the ESP's mounted directory: the durability
// barrier a vfat rename needs that a file's own fsync does not provide.
func (m *memFS) Sync() error {
	m.ops = append(m.ops, "sync")

	return m.failSync
}

type release struct {
	cert *x509.Certificate
	key  *rsa.PrivateKey
}

func newRelease(t *testing.T) release {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		NotAfter:     time.Now().Add(time.Hour),
		NotBefore:    time.Now().Add(-time.Hour),
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "CryptOS Release Signing"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	return release{cert: cert, key: key}
}

func (r release) sign(t *testing.T, image []byte) []byte {
	t.Helper()

	sum := sha256.Sum256(image)
	sig, err := rsa.SignPKCS1v15(rand.Reader, r.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("SignPKCS1v15: %v", err)
	}

	return sig
}

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	out := make([]byte, 0, len(sum)*2)
	const hexdigits = "0123456789abcdef"
	for _, c := range sum {
		out = append(out, hexdigits[c>>4], hexdigits[c&0x0f])
	}

	return string(out)
}

// The upgrade that #208 is for: a new image becomes the one the firmware boots,
// and the identity on the state partition is not involved at all.
func TestStage_ActivatesTheNewImageAndRetainsTheOld(t *testing.T) {
	rel := newRelease(t)
	fs := newMemFS()
	fs.files[ActiveRelPath] = []byte("old image")

	s, err := New(fs, rel.cert)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	image := []byte("new image")
	status, err := s.Stage(image, rel.sign(t, image))
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}

	if got := string(fs.files[ActiveRelPath]); got != "new image" {
		t.Errorf("active image = %q, want the new one", got)
	}
	// Retained on purpose: the thing being upgraded is the node's only
	// management surface, so booting to nothing must be recoverable remotely.
	if got := string(fs.files[PreviousRelPath]); got != "old image" {
		t.Errorf("previous image = %q, want the old one retained", got)
	}
	if status.ActiveDigest != digest(image) {
		t.Errorf("ActiveDigest = %q, want the new image's digest", status.ActiveDigest)
	}
	if status.PreviousDigest != digest([]byte("old image")) {
		t.Errorf("PreviousDigest = %q, want the old image's digest", status.PreviousDigest)
	}
}

// An image that cannot be attributed must never reach the disk. Writing it and
// letting the firmware refuse it would strand the node.
func TestStage_RefusesAnUnsignedImageWithoutWriting(t *testing.T) {
	rel := newRelease(t)
	fs := newMemFS()
	fs.files[ActiveRelPath] = []byte("old image")

	s, _ := New(fs, rel.cert)

	if _, err := s.Stage([]byte("hostile image"), []byte("not a signature")); err == nil {
		t.Fatal("Stage accepted an unsigned image")
	}
	if len(fs.writes) != 0 {
		t.Errorf("wrote %v before verifying; nothing should reach the disk", fs.writes)
	}
	if got := string(fs.files[ActiveRelPath]); got != "old image" {
		t.Errorf("active image = %q, want it untouched", got)
	}
}

// A different key is the realistic attack and the realistic mistake -- a CI
// build signed with the per-run ephemeral key rather than the release key.
func TestStage_RefusesAnImageSignedByAnotherKey(t *testing.T) {
	rel := newRelease(t)
	other := newRelease(t)
	fs := newMemFS()
	fs.files[ActiveRelPath] = []byte("old image")

	s, _ := New(fs, rel.cert)

	image := []byte("new image")
	if _, err := s.Stage(image, other.sign(t, image)); err == nil {
		t.Fatal("Stage accepted an image signed by a key that is not the release key")
	}
	if got := string(fs.files[ActiveRelPath]); got != "old image" {
		t.Error("the active image changed despite a failed verification")
	}
}

// A signature over different bytes must not carry over to this image.
func TestStage_RefusesASignatureOverOtherBytes(t *testing.T) {
	rel := newRelease(t)
	fs := newMemFS()
	s, _ := New(fs, rel.cert)

	if _, err := s.Stage([]byte("image A"), rel.sign(t, []byte("image B"))); err == nil {
		t.Fatal("Stage accepted a signature made over different bytes")
	}
}

// If the write fails, the node must still boot what it booted before.
func TestStage_LeavesTheNodeBootableWhenTheWriteFails(t *testing.T) {
	rel := newRelease(t)
	fs := newMemFS()
	fs.files[ActiveRelPath] = []byte("old image")
	fs.failWrite[incomingRelPath] = errors.New("no space left on device")

	s, _ := New(fs, rel.cert)

	image := []byte("new image")
	if _, err := s.Stage(image, rel.sign(t, image)); err == nil {
		t.Fatal("Stage reported success despite a failed write")
	}
	if got := string(fs.files[ActiveRelPath]); got != "old image" {
		t.Errorf("active image = %q, want the previous one still bootable", got)
	}
}

// A first install has nothing to retain, and that is not an error.
func TestStage_OnANodeWithNoActiveImage(t *testing.T) {
	rel := newRelease(t)
	fs := newMemFS()
	s, _ := New(fs, rel.cert)

	image := []byte("first image")
	status, err := s.Stage(image, rel.sign(t, image))
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if got := string(fs.files[ActiveRelPath]); got != "first image" {
		t.Errorf("active image = %q", got)
	}
	if status.PreviousDigest != "" {
		t.Errorf("PreviousDigest = %q, want empty when there was nothing to retain", status.PreviousDigest)
	}
}

// A vfat rename isn't durable across a power loss on its own: the directory
// entry update needs its own fsync. Stage must call it right after the
// rename that makes the incoming image the active one (#373).
func TestStage_SyncsTheESPDirectoryAfterTheRename(t *testing.T) {
	rel := newRelease(t)
	fs := newMemFS()
	fs.files[ActiveRelPath] = []byte("old image")
	s, _ := New(fs, rel.cert)

	image := []byte("new image")
	if _, err := s.Stage(image, rel.sign(t, image)); err != nil {
		t.Fatalf("Stage: %v", err)
	}

	wantLast := "rename:" + incomingRelPath + "->" + ActiveRelPath
	if n := len(fs.ops); n < 2 || fs.ops[n-2] != wantLast || fs.ops[n-1] != "sync" {
		t.Fatalf("ops = %v, want the activating rename immediately followed by a sync", fs.ops)
	}
}

// If the directory sync fails, Stage must say so rather than reporting
// success over a rename that might not survive a power loss.
func TestStage_ReturnsAnErrorWhenTheDirectorySyncFails(t *testing.T) {
	rel := newRelease(t)
	fs := newMemFS()
	fs.failSync = errors.New("input/output error")
	s, _ := New(fs, rel.cert)

	image := []byte("new image")
	if _, err := s.Stage(image, rel.sign(t, image)); err == nil {
		t.Fatal("Stage reported success despite a failed directory sync")
	}
}

func TestRollback_RestoresThePreviousImage(t *testing.T) {
	rel := newRelease(t)
	fs := newMemFS()
	fs.files[ActiveRelPath] = []byte("old image")
	s, _ := New(fs, rel.cert)

	image := []byte("bad image")
	if _, err := s.Stage(image, rel.sign(t, image)); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if err := s.Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}

	if got := string(fs.files[ActiveRelPath]); got != "old image" {
		t.Errorf("active image = %q, want the previous one restored", got)
	}
}

// Rollback's final rename needs the same directory durability barrier as
// Stage's (#373).
func TestRollback_SyncsTheESPDirectoryAfterTheRename(t *testing.T) {
	rel := newRelease(t)
	fs := newMemFS()
	fs.files[ActiveRelPath] = []byte("old image")
	s, _ := New(fs, rel.cert)

	image := []byte("bad image")
	if _, err := s.Stage(image, rel.sign(t, image)); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	fs.ops = nil // only Rollback's own ops matter here

	if err := s.Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}

	wantLast := "rename:" + incomingRelPath + "->" + ActiveRelPath
	if n := len(fs.ops); n < 2 || fs.ops[n-2] != wantLast || fs.ops[n-1] != "sync" {
		t.Fatalf("ops = %v, want the restoring rename immediately followed by a sync", fs.ops)
	}
}

func TestRollback_ReturnsAnErrorWhenTheDirectorySyncFails(t *testing.T) {
	rel := newRelease(t)
	fs := newMemFS()
	fs.files[ActiveRelPath] = []byte("old image")
	s, _ := New(fs, rel.cert)

	image := []byte("bad image")
	if _, err := s.Stage(image, rel.sign(t, image)); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	fs.failSync = errors.New("input/output error")

	if err := s.Rollback(); err == nil {
		t.Fatal("Rollback reported success despite a failed directory sync")
	}
}

func TestRollback_WithNothingRetained(t *testing.T) {
	rel := newRelease(t)
	s, _ := New(newMemFS(), rel.cert)

	if err := s.Rollback(); !errors.Is(err, ErrNoPrevious) {
		t.Errorf("Rollback error = %v, want ErrNoPrevious", err)
	}
}

// A build that forgot to embed a release certificate must fail at construction,
// not quietly accept every image.
func TestNew_RequiresAReleaseCertificate(t *testing.T) {
	if _, err := New(newMemFS(), nil); err == nil {
		t.Error("New accepted a nil release certificate")
	}
	rel := newRelease(t)
	if _, err := New(nil, rel.cert); err == nil {
		t.Error("New accepted a nil filesystem")
	}
}
