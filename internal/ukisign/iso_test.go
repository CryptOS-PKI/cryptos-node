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
	"errors"
	"testing"

	"github.com/CryptOS-PKI/cryptos-node/internal/imageupgrade"
	"github.com/CryptOS-PKI/cryptos-node/internal/isoimage"
	"github.com/CryptOS-PKI/cryptos-node/internal/isoimage/isotest"
)

func TestSignISO_SignsEveryCopy(t *testing.T) {
	key, cert := testSigner(t, "Example Release Signing")
	for name, o := range map[string]isotest.Options{
		"FAT16 GPT": {FAT: 16, GPT: true},
		"FAT32":     {FAT: 32},
	} {
		t.Run(name, func(t *testing.T) {
			unsigned := testUKI(t)
			iso := isotest.Build(t, unsigned, o).Image

			res, err := SignISO(iso, key, cert)
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Copies) != 2 {
				t.Errorf("Copies = %q, want the boot image and /cryptos.uki", res.Copies)
			}

			got, err := isoimage.Open(res.ISO)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got.UKI(), res.Image) || len(got.Copies()) != 2 {
				t.Fatalf("the signed ISO carries the signed UKI in %q", got.Copies())
			}
			if err := Check(res.Image, res.Signature, cert); err != nil {
				t.Errorf("Check: %v", err)
			}
			if err := imageupgrade.Verify(res.Image, res.Signature, cert); err != nil {
				t.Errorf("the detached signature does not verify: %v", err)
			}
		})
	}
}

func TestSignISO_Refusals(t *testing.T) {
	key, cert := testSigner(t, "Example Release Signing")

	if _, err := SignISO(testUKI(t), key, cert); !errors.Is(err, isoimage.ErrNotISO) {
		t.Errorf("a UKI: err = %v, want ErrNotISO", err)
	}

	// An ISO whose boot image holds something that is not a UKI.
	iso := isotest.Build(t, bytes.Repeat([]byte("not a PE "), 1000), isotest.Options{}).Image
	if _, err := SignISO(iso, key, cert); !errors.Is(err, ErrNotUKI) {
		t.Errorf("a non-UKI boot image: err = %v, want ErrNotUKI", err)
	}
}

func TestCheckISO(t *testing.T) {
	key, cert := testSigner(t, "Example Release Signing")
	res, err := SignISO(isotest.Build(t, testUKI(t), isotest.Options{GPT: true}).Image, key, cert)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckISO(res.ISO, res.Image, res.Signature, cert, 2); err != nil {
		t.Errorf("CheckISO on SignISO's output: %v", err)
	}
	if err := CheckISO(res.ISO, res.Image, res.Signature, cert, 3); !errors.Is(err, ErrSelfCheck) {
		t.Errorf("a missing copy: err = %v, want ErrSelfCheck", err)
	}
	other := mustSign(t, testUKI(t), key, cert)
	other.Image[len(other.Image)-1] ^= 0xFF
	if err := CheckISO(res.ISO, other.Image, other.Signature, cert, 2); !errors.Is(err, ErrSelfCheck) {
		t.Errorf("a different UKI: err = %v, want ErrSelfCheck", err)
	}
	// An ISO signed for one key does not check against another.
	_, otherCert := testSigner(t, "Another Release Signing")
	if err := CheckISO(res.ISO, res.Image, res.Signature, otherCert, 2); !errors.Is(err, ErrSelfCheck) {
		t.Errorf("another certificate: err = %v, want ErrSelfCheck", err)
	}
}

func TestDefaultISOOut(t *testing.T) {
	for in, want := range map[string]string{
		"cryptos-amd64-vmware-nodeid-unsigned-v0.1.0-rc.2.iso": "cryptos-amd64-vmware-nodeid-v0.1.0-rc.2.iso",
		"dl/cryptos-amd64-vmware-unsigned-abc1234.iso":         "dl/cryptos-amd64-vmware-abc1234.iso",
		"image.iso":     "image.signed.iso",
		"image":         "image.signed.iso",
		"-unsigned.iso": "-unsigned.signed.iso",
	} {
		if got := DefaultISOOut(in); got != want {
			t.Errorf("DefaultISOOut(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{
		"cryptos-amd64-vmware-v0.1.0.iso": "cryptos-amd64-vmware-v0.1.0.uki",
		"signed":                          "signed.uki",
	} {
		if got := ISOUKIPath(in); got != want {
			t.Errorf("ISOUKIPath(%q) = %q, want %q", in, got, want)
		}
	}
}
