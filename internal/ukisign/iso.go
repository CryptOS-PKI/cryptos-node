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
	"crypto/x509"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/CryptOS-PKI/cryptos-node/internal/isoimage"
)

// ISOResult is a signed ISO, the signed UKI inside it and that UKI's
// detached release signature (cryptos-appliance#83).
type ISOResult struct {
	// ISO is the signed ISO.
	ISO []byte
	// Image is the signed UKI every copy in the ISO now holds, for staging
	// onto nodes that already trust the key.
	Image []byte
	// Signature is the detached release signature over Image.
	Signature []byte
	// Copies names each place in the ISO the UKI was replaced.
	Copies []string
}

// SignISO signs the UKI an unsigned CryptOS ISO carries, exactly as Sign
// does, and writes the signed UKI back over every copy of it in the ISO: the
// El Torito EFI boot image's EFI/BOOT/BOOTX64.EFI, which the firmware boots,
// and the ISO 9660 file the installer copies to disk. Before returning, it
// re-reads the new ISO with CheckISO.
func SignISO(iso []byte, key crypto.Signer, cert *x509.Certificate) (ISOResult, error) {
	in, err := isoimage.Open(iso)
	if err != nil {
		return ISOResult{}, err
	}
	res, err := Sign(in.UKI(), key, cert)
	if err != nil {
		return ISOResult{}, err
	}
	out, err := in.ReplaceUKI(res.Image)
	if err != nil {
		return ISOResult{}, err
	}
	copies := in.Copies()
	if err := CheckISO(out, res.Image, res.Signature, cert, len(copies)); err != nil {
		return ISOResult{}, err
	}

	return ISOResult{ISO: out, Image: res.Image, Signature: res.Signature, Copies: copies}, nil
}

// CheckISO verifies an ISO the way SignISO leaves it: it parses, its El
// Torito boot image holds image, it carries image in as many places as the
// input carried the UKI (so no copy kept the old one), and image passes
// Check against signature and cert.
func CheckISO(iso, image, signature []byte, cert *x509.Certificate, copies int) error {
	got, err := isoimage.Open(iso)
	if err != nil {
		return fmt.Errorf("%w: re-read the ISO: %w", ErrSelfCheck, err)
	}
	if !bytes.Equal(got.UKI(), image) {
		return fmt.Errorf("%w: the ISO's EFI boot image does not hold the signed UKI", ErrSelfCheck)
	}
	if n := len(got.Copies()); n != copies {
		return fmt.Errorf("%w: the ISO holds the signed UKI in %d places, want %d", ErrSelfCheck, n, copies)
	}

	return Check(image, signature, cert)
}

// DefaultISOOut is where the signed ISO goes when no output path is given:
// the input with its "-unsigned" marker removed (the name cryptos-appliance's
// release gives an unsigned ISO), or otherwise the input with ".iso"
// replaced by, or followed by, ".signed.iso".
func DefaultISOOut(iso string) string {
	dir, base := filepath.Split(iso)
	if i := strings.LastIndex(base, "-unsigned"); i > 0 {
		return dir + base[:i] + base[i+len("-unsigned"):]
	}

	return strings.TrimSuffix(iso, ".iso") + ".signed.iso"
}

// ISOUKIPath is where the signed UKI from an ISO is written beside the
// signed ISO at out: out with ".iso" replaced by, or followed by, ".uki".
// Its detached signature goes beside it as <uki>.sig.
func ISOUKIPath(out string) string {
	return strings.TrimSuffix(out, ".iso") + ".uki"
}
