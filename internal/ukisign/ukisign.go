// Package ukisign signs an unsigned CryptOS Unified Kernel Image with an
// operator's own key and makes that key the image's upgrade anchor
// (cryptos-appliance#41).
//
// Release assets are built unsigned and carry no upgrade anchor, so a node
// installed from one cannot take an in-place upgrade. Sign fixes that after
// the fact, with no rebuild, no root and no external tools:
//
//  1. It appends an uncompressed newc cpio archive holding AnchorName (the
//     signing certificate, DER) to the UKI's .initrd. The kernel unpacks
//     concatenated initramfs archives in order, so the file appears as
//     /upgrade-anchor.der, where cryptos-switchroot reads it and hands it to
//     init (see internal/release). Signing again appends another archive and
//     the last one wins. The .initrd is measured into PCR 11 and covered by
//     the Authenticode signature, so the anchor is as protected as the
//     kernel; a new PE section would be neither.
//  2. It moves the sections after .initrd up to make room. Every section
//     before .initrd, which is all of systemd-stub's own code and data, keeps
//     its bytes, RVA and file offset.
//  3. It Authenticode-signs the result (SHA-256 PE image hash,
//     SpcIndirectDataContent, PKCS #7 SignedData in a WIN_CERTIFICATE), the
//     same form sbsign writes, replacing any earlier signature.
//  4. It makes the detached release signature `image stage` sends: RSA
//     PKCS#1 v1.5 over the SHA-256 of the final file.
//
// Before returning, Sign checks its own output with Check.
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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/CryptOS-PKI/cryptos-node/internal/imageupgrade"
)

var (
	// ErrNotUKI is wrapped by every refusal of the input image: not a PE, not
	// a single-profile UKI with one .linux and one .initrd, or laid out in a
	// way the sections after .initrd cannot safely be moved.
	ErrNotUKI = errors.New("ukisign: not a UKI this tool can sign")
	// ErrSelfCheck is wrapped when a signed image fails Check.
	ErrSelfCheck = errors.New("ukisign: the signed image failed its self-check")
)

// Result is a signed image and its detached release signature.
type Result struct {
	// Image is the signed UKI.
	Image []byte
	// Signature is the detached release signature over Image, written
	// beside it as <image>.sig.
	Signature []byte
}

// Sign adds cert as the upgrade anchor to image, Authenticode-signs it with
// key, and makes the detached release signature. key must be the RSA key of
// cert.
func Sign(image []byte, key crypto.Signer, cert *x509.Certificate) (Result, error) {
	if key == nil || cert == nil {
		return Result{}, errors.New("ukisign: a key and a certificate are required")
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return Result{}, fmt.Errorf("ukisign: the certificate holds a %T key, want RSA (release signatures are PKCS#1 v1.5)", cert.PublicKey)
	}
	if !pub.Equal(key.Public()) {
		return Result{}, errors.New("ukisign: the key does not match the certificate")
	}

	in, err := parsePE(image)
	if err != nil {
		return Result{}, err
	}
	idx, err := in.uki()
	if err != nil {
		return Result{}, err
	}
	laid, err := relayout(in, idx, anchorArchive(cert.Raw))
	if err != nil {
		return Result{}, err
	}
	unsigned, err := parsePE(laid)
	if err != nil {
		return Result{}, fmt.Errorf("ukisign: re-parse the laid out image: %w", err)
	}
	cms, err := authenticode(imageHash(unsigned), key, cert)
	if err != nil {
		return Result{}, fmt.Errorf("ukisign: Authenticode: %w", err)
	}
	signed := appendCertificate(unsigned, cms)

	sum := sha256.Sum256(signed)
	detached, err := key.Sign(rand.Reader, sum[:], crypto.SHA256)
	if err != nil {
		return Result{}, fmt.Errorf("ukisign: detached signature: %w", err)
	}

	if err := Check(signed, detached, cert); err != nil {
		return Result{}, err
	}

	return Result{Image: signed, Signature: detached}, nil
}

// Check verifies a signed image the way Sign leaves it: it parses as a UKI,
// its .initrd ends with the anchor archive for cert, its Authenticode
// signature verifies against cert over a freshly computed image hash, and the
// detached signature verifies as `image stage` will check it.
func Check(image, signature []byte, cert *x509.Certificate) error {
	p, err := parsePE(image)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSelfCheck, err)
	}
	idx, err := p.uki()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSelfCheck, err)
	}
	initrd := p.sections[idx]
	if uint64(initrd.extent()) > uint64(len(image)) {
		return fmt.Errorf("%w: .initrd claims %d bytes in memory", ErrSelfCheck, initrd.extent())
	}
	if !bytes.HasSuffix(p.loaded(initrd), anchorArchive(cert.Raw)) {
		return fmt.Errorf("%w: .initrd does not end with the anchor for this certificate", ErrSelfCheck)
	}

	blob, err := p.certificateBlob()
	if err != nil {
		return err
	}
	signed, err := verifyAuthenticode(blob, cert)
	if err != nil {
		return fmt.Errorf("%w: Authenticode: %w", ErrSelfCheck, err)
	}
	if !bytes.Equal(signed, imageHash(p)) {
		return fmt.Errorf("%w: the signed image hash does not match the image", ErrSelfCheck)
	}

	if err := imageupgrade.Verify(image, signature, cert); err != nil {
		return fmt.Errorf("%w: %w", ErrSelfCheck, err)
	}

	return nil
}

// ParseKey reads an RSA private key from PEM, PKCS#1 ("RSA PRIVATE KEY") or
// PKCS#8 ("PRIVATE KEY"). Encrypted keys are refused: decrypt the key to a
// file only you can read, or wait for hardware token support.
func ParseKey(pemBytes []byte) (crypto.Signer, error) {
	for rest := pemBytes; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, errors.New("ukisign: no PEM private key found")
		}
		switch block.Type {
		case "RSA PRIVATE KEY":
			if _, encrypted := block.Headers["DEK-Info"]; encrypted {
				return nil, errors.New("ukisign: the private key is encrypted; decrypt it first")
			}
			key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("ukisign: parse the PKCS#1 private key: %w", err)
			}
			return key, nil
		case "PRIVATE KEY":
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("ukisign: parse the PKCS#8 private key: %w", err)
			}
			rsaKey, ok := key.(*rsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("ukisign: the private key is %T, want RSA", key)
			}
			return rsaKey, nil
		case "ENCRYPTED PRIVATE KEY":
			return nil, errors.New("ukisign: the private key is encrypted; decrypt it first")
		}
	}
}

// ParseCertificate reads a certificate from PEM or DER.
func ParseCertificate(b []byte) (*x509.Certificate, error) {
	der := b
	if block, _ := pem.Decode(b); block != nil {
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("ukisign: PEM block is %q, want CERTIFICATE", block.Type)
		}
		der = block.Bytes
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("ukisign: parse the certificate: %w", err)
	}

	return cert, nil
}

// DefaultOut is where the signed image goes when no output path is given:
// the input without its ".unsigned" suffix (the name cryptos-appliance's
// build gives an unsigned UKI), or otherwise the input with ".uki" replaced
// by, or followed by, ".signed.uki".
func DefaultOut(image string) string {
	if out, ok := strings.CutSuffix(image, ".unsigned"); ok && out != "" {
		return out
	}

	return strings.TrimSuffix(image, ".uki") + ".signed.uki"
}
