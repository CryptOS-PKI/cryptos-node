package tpm

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
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// DefaultSealPCRs is the Phase 1 PCR set the state-partition key is
// sealed to: PCR 7 (Secure Boot policy) and PCR 11 (UKI measurement).
// PCRs 0/2/4 are intentionally excluded so firmware updates don't break
// unseal.
var DefaultSealPCRs = []int{7, 11}

// sealNameAlg is the hash algorithm used for the sealed object's name and
// for the PolicyPCR session.
const sealNameAlg = tpm2.TPMAlgSHA256

// SealToPCR seals data into the TPM under a PolicyPCR over the given
// PCRs, so it can only be unsealed while those PCRs hold their current
// values. It returns the wrapped private and public blobs, which the
// caller persists (e.g. in the LUKS2 token) and later passes to
// UnsealWithPCR.
//
// The SRK must already be provisioned (ProvisionSRK). The plaintext
// never leaves the TPM except as the caller's input here and the
// recovered output of UnsealWithPCR.
func (t *TPM) SealToPCR(data []byte, pcrs []int) (private, public []byte, err error) {
	rwc, err := t.transport()
	if err != nil {
		return nil, nil, err
	}
	if len(data) == 0 {
		return nil, nil, errors.New("tpm: SealToPCR: data is empty")
	}
	if len(pcrs) == 0 {
		return nil, nil, errors.New("tpm: SealToPCR: no PCRs selected")
	}

	sel := pcrSelection(pcrs)
	pcrDigest, err := readPCRDigest(rwc, sel)
	if err != nil {
		return nil, nil, err
	}

	return seal(rwc, data, sel, pcrDigest)
}

// SealToPCRValues seals data like SealToPCR, but against the given expected
// PCR values instead of the ones the TPM holds now. It is how a key is made
// available to a boot that has not happened yet: an in-place upgrade seals the
// state key to the PCR 11 value the incoming image will measure, while the
// running image can still unseal it.
//
// Every value must be a SHA-256 digest. The TPM is not asked whether the
// values are reachable; a wrong prediction simply produces a blob no boot can
// unseal, which is why callers check their prediction first.
func (t *TPM) SealToPCRValues(data []byte, values map[int][]byte) (private, public []byte, err error) {
	rwc, err := t.transport()
	if err != nil {
		return nil, nil, err
	}
	if len(data) == 0 {
		return nil, nil, errors.New("tpm: SealToPCRValues: data is empty")
	}
	if len(values) == 0 {
		return nil, nil, errors.New("tpm: SealToPCRValues: no PCRs selected")
	}

	pcrs := sortedPCRs(values)
	h := sha256.New()
	for _, p := range pcrs {
		if len(values[p]) != sha256.Size {
			return nil, nil, fmt.Errorf("tpm: SealToPCRValues: PCR %d value is %d bytes, want %d", p, len(values[p]), sha256.Size)
		}
		// PolicyPCR hashes the selected values in ascending PCR order, the
		// same order PCRRead returns them in for readPCRDigest.
		h.Write(values[p])
	}

	return seal(rwc, data, pcrSelection(pcrs), h.Sum(nil))
}

// ReadPCRs returns the current SHA-256 bank values of the given PCRs.
func (t *TPM) ReadPCRs(pcrs []int) (map[int][]byte, error) {
	rwc, err := t.transport()
	if err != nil {
		return nil, err
	}
	if len(pcrs) == 0 {
		return nil, errors.New("tpm: ReadPCRs: no PCRs selected")
	}

	sorted := append([]int(nil), pcrs...)
	sort.Ints(sorted)
	resp, err := (tpm2.PCRRead{PCRSelectionIn: pcrSelection(sorted)}).Execute(rwc)
	if err != nil {
		return nil, fmt.Errorf("tpm: ReadPCRs: PCRRead: %w", err)
	}
	if len(resp.PCRValues.Digests) != len(sorted) {
		// A TPM may answer a large selection in parts; the seal sets used
		// here are two PCRs, so a short answer is a fault, not paging.
		return nil, fmt.Errorf("tpm: ReadPCRs: asked for %d PCRs, got %d", len(sorted), len(resp.PCRValues.Digests))
	}
	out := make(map[int][]byte, len(sorted))
	for i, p := range sorted {
		out[p] = append([]byte(nil), resp.PCRValues.Digests[i].Buffer...)
	}

	return out, nil
}

// sortedPCRs returns the PCR indices of values in ascending order.
func sortedPCRs(values map[int][]byte) []int {
	pcrs := make([]int, 0, len(values))
	for p := range values {
		pcrs = append(pcrs, p)
	}
	sort.Ints(pcrs)

	return pcrs
}

// seal creates the sealed object under the SRK with a PolicyPCR over sel at
// the expected pcrDigest.
func seal(rwc transport.TPM, data []byte, sel tpm2.TPMLPCRSelection, pcrDigest []byte) (private, public []byte, err error) {
	authPolicy, err := pcrPolicyDigest(rwc, sel, pcrDigest)
	if err != nil {
		return nil, nil, err
	}
	srkName, err := readSRKName(rwc)
	if err != nil {
		return nil, nil, err
	}

	resp, err := (tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(SRKPersistentHandle),
			Name:   srkName,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{Buffer: data}),
			},
		},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgKeyedHash,
			NameAlg: sealNameAlg,
			// No UserWithAuth: the only way to access the data is to
			// satisfy AuthPolicy (the PCR policy). FixedTPM/FixedParent
			// bind it to this TPM and this SRK.
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:    true,
				FixedParent: true,
			},
			AuthPolicy: tpm2.TPM2BDigest{Buffer: authPolicy},
		}),
	}).Execute(rwc)
	if err != nil {
		return nil, nil, fmt.Errorf("tpm: seal: Create: %w", err)
	}

	return tpm2.Marshal(resp.OutPrivate), tpm2.Marshal(resp.OutPublic), nil
}

// UnsealWithPCR loads a previously sealed object and unseals it,
// satisfying its PolicyPCR with the current values of the given PCRs.
// It returns the recovered data, or an error if any selected PCR has
// drifted from its seal-time value.
func (t *TPM) UnsealWithPCR(private, public []byte, pcrs []int) ([]byte, error) {
	rwc, err := t.transport()
	if err != nil {
		return nil, err
	}
	if len(pcrs) == 0 {
		return nil, errors.New("tpm: UnsealWithPCR: no PCRs selected")
	}

	priv, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](private)
	if err != nil {
		return nil, fmt.Errorf("tpm: UnsealWithPCR: unmarshal private: %w", err)
	}
	pub, err := tpm2.Unmarshal[tpm2.TPM2BPublic](public)
	if err != nil {
		return nil, fmt.Errorf("tpm: UnsealWithPCR: unmarshal public: %w", err)
	}

	srkName, err := readSRKName(rwc)
	if err != nil {
		return nil, err
	}
	loaded, err := (tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(SRKPersistentHandle),
			Name:   srkName,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPrivate: *priv,
		InPublic:  *pub,
	}).Execute(rwc)
	if err != nil {
		return nil, fmt.Errorf("tpm: UnsealWithPCR: Load: %w", err)
	}
	defer func() {
		_, _ = (tpm2.FlushContext{FlushHandle: loaded.ObjectHandle}).Execute(rwc)
	}()

	sess, closeSession, err := tpm2.PolicySession(rwc, sealNameAlg, 16)
	if err != nil {
		return nil, fmt.Errorf("tpm: UnsealWithPCR: policy session: %w", err)
	}
	defer func() { _ = closeSession() }()

	if _, err := (tpm2.PolicyPCR{
		PolicySession: sess.Handle(),
		Pcrs:          pcrSelection(pcrs),
	}).Execute(rwc); err != nil {
		return nil, fmt.Errorf("tpm: UnsealWithPCR: PolicyPCR: %w", err)
	}

	resp, err := (tpm2.Unseal{
		ItemHandle: tpm2.AuthHandle{
			Handle: loaded.ObjectHandle,
			Name:   loaded.Name,
			Auth:   sess,
		},
	}).Execute(rwc)
	if err != nil {
		return nil, fmt.Errorf("tpm: UnsealWithPCR: Unseal (PCR policy not satisfied?): %w", err)
	}
	return resp.OutData.Buffer, nil
}

// ExtendPCR extends the named PCR (SHA-256 bank) with data. It is a
// standard measurement primitive; the boot chain normally extends PCRs,
// and CryptOS uses it for extension measurement (PCR 14) and in tests to
// simulate drift.
func (t *TPM) ExtendPCR(pcr int, data []byte) error {
	rwc, err := t.transport()
	if err != nil {
		return err
	}
	digest := sha256.Sum256(data)
	_, err = (tpm2.PCRExtend{
		PCRHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(pcr), //nolint:gosec // G115: a PCR index is 0 to 23
			Auth:   tpm2.PasswordAuth(nil),
		},
		Digests: tpm2.TPMLDigestValues{
			Digests: []tpm2.TPMTHA{{
				HashAlg: sealNameAlg,
				Digest:  digest[:],
			}},
		},
	}).Execute(rwc)
	if err != nil {
		return fmt.Errorf("tpm: ExtendPCR(%d): %w", pcr, err)
	}
	return nil
}

// pcrSelection builds a SHA-256-bank PCR selection for the given PCRs.
func pcrSelection(pcrs []int) tpm2.TPMLPCRSelection {
	idx := make([]uint, len(pcrs))
	for i, p := range pcrs {
		idx[i] = uint(p)
	}
	return tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{{
			Hash:      sealNameAlg,
			PCRSelect: tpm2.PCClientCompatible.PCRs(idx...),
		}},
	}
}

// readPCRDigest reads the selected PCRs and returns the SHA-256 over the
// concatenation of their values — the expected PolicyPCR digest.
func readPCRDigest(rwc transport.TPM, sel tpm2.TPMLPCRSelection) ([]byte, error) {
	resp, err := (tpm2.PCRRead{PCRSelectionIn: sel}).Execute(rwc)
	if err != nil {
		return nil, fmt.Errorf("tpm: PCRRead: %w", err)
	}
	h := sha256.New()
	for _, d := range resp.PCRValues.Digests {
		h.Write(d.Buffer)
	}
	return h.Sum(nil), nil
}

// pcrPolicyDigest computes the PolicyPCR authorization digest for the
// selection at the given expected PCR digest, using a trial policy
// session (no TPM state is changed).
func pcrPolicyDigest(rwc transport.TPM, sel tpm2.TPMLPCRSelection, pcrDigest []byte) ([]byte, error) {
	sess, closeSession, err := tpm2.PolicySession(rwc, sealNameAlg, 16, tpm2.Trial())
	if err != nil {
		return nil, fmt.Errorf("tpm: trial policy session: %w", err)
	}
	defer func() { _ = closeSession() }()

	if _, err := (tpm2.PolicyPCR{
		PolicySession: sess.Handle(),
		PcrDigest:     tpm2.TPM2BDigest{Buffer: pcrDigest},
		Pcrs:          sel,
	}).Execute(rwc); err != nil {
		return nil, fmt.Errorf("tpm: trial PolicyPCR: %w", err)
	}
	pgd, err := (tpm2.PolicyGetDigest{PolicySession: sess.Handle()}).Execute(rwc)
	if err != nil {
		return nil, fmt.Errorf("tpm: PolicyGetDigest: %w", err)
	}
	return pgd.PolicyDigest.Buffer, nil
}
