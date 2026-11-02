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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/CryptOS-PKI/cryptos-node/internal/keyalg"
)

// KeyAlgorithm selects the algorithm and parameters for a created signing key.
type KeyAlgorithm = keyalg.Algorithm

const (
	// AlgorithmECDSAP384 pairs ECDSA on NIST P-384 with SHA-384.
	AlgorithmECDSAP384 = keyalg.ECDSAP384

	// AlgorithmRSA2048, AlgorithmRSA3072 and AlgorithmRSA4096 are RSA CA keys
	// at the named modulus size. RSA-3072 and RSA-4096 can be created inside
	// the TPM when the part implements that size; CreateKey checks first and
	// fails with ErrKeyAlgorithmUnsupported rather than creating anything
	// else. RSA-2048 is below MinRSAKeyBits and is refused here; it remains
	// only for the software key backend.
	AlgorithmRSA2048 = keyalg.RSA2048
	AlgorithmRSA3072 = keyalg.RSA3072
	AlgorithmRSA4096 = keyalg.RSA4096
)

// MinRSAKeyBits is the smallest RSA key CreateKey will make in the TPM. It
// matches the 3072-bit floor the CA enforces on every subject key it
// certifies, because a CA key is itself the subject of its own certificate.
const MinRSAKeyBits = 3072

// ErrKeyAlgorithmUnsupported is returned by CreateKey when the TPM does not
// implement the requested algorithm or key size. Many TPM 2.0 parts implement
// only RSA-2048, so this is the expected outcome for RSA-3072 on them.
var ErrKeyAlgorithmUnsupported = errors.New("tpm: key algorithm not supported by this TPM")

// RSAKeyBits returns the modulus size for an RSA KeyAlgorithm, and false when
// alg is not an RSA algorithm.
func RSAKeyBits(alg KeyAlgorithm) (int, bool) {
	switch alg {
	case AlgorithmRSA2048:
		return 2048, true
	case AlgorithmRSA3072:
		return 3072, true
	case AlgorithmRSA4096:
		return 4096, true
	default:
		return 0, false
	}
}

// Key is a signing key resident in the TPM and currently loaded under
// the SRK. Implements crypto.Signer.
//
// Key is not safe for concurrent use. Callers must Close exactly once
// to release the transient handle inside the TPM.
type Key struct {
	tpm    *TPM
	handle tpm2.TPMHandle
	name   tpm2.TPM2BName
	pub    crypto.PublicKey
	alg    KeyAlgorithm
}

// CreatedKey holds the artifacts returned by CreateKey. Private and
// Public are the TPM-wrapped key blobs the caller persists and later
// restores with LoadKey. CreationData and CreationTicket are the TPM
// creation evidence recorded in the Ceremony Manifest's
// key_creation_attestation (RFC-agnostic TPM 2.0 structures, marshaled).
type CreatedKey struct {
	// Private is the marshaled TPM2B_PRIVATE blob (wrapped private key).
	Private []byte
	// Public is the marshaled TPM2B_PUBLIC blob.
	Public []byte
	// CreationData is the marshaled TPM2B_CREATION_DATA.
	CreationData []byte
	// CreationTicket is the marshaled TPMT_TK_CREATION ticket.
	CreationTicket []byte
}

// CreateKey creates a new signing key under the persisted SRK and
// returns the wrapped key blobs plus the TPM creation evidence. The
// plaintext private key never leaves the TPM. Callers persist
// Private/Public (typically to the encrypted state partition) and later
// restore them with LoadKey.
//
// For an RSA algorithm the TPM is first asked, with TPM2_TestParms, whether
// it implements that modulus size. If it does not, CreateKey returns
// ErrKeyAlgorithmUnsupported and creates nothing; it never falls back to a
// smaller size or to a software key.
//
// ProvisionSRK must have run successfully (in this boot or a previous
// one) before calling CreateKey.
func (t *TPM) CreateKey(alg KeyAlgorithm) (*CreatedKey, error) {
	rwc, err := t.transport()
	if err != nil {
		return nil, err
	}
	template, err := publicTemplate(alg)
	if err != nil {
		return nil, err
	}
	if _, isRSA := RSAKeyBits(alg); isRSA {
		if err := testParms(rwc, template); err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrKeyAlgorithmUnsupported, algName(alg), err)
		}
	}
	return t.createFromTemplate(template)
}

// createFromTemplate creates a key from template under the SRK. CreateKey is
// the only production caller; tests also use it to exercise the RSA path at a
// size the in-process simulator implements.
func (t *TPM) createFromTemplate(template tpm2.TPMTPublic) (*CreatedKey, error) {
	rwc, err := t.transport()
	if err != nil {
		return nil, err
	}
	srkName, err := readSRKName(rwc)
	if err != nil {
		return nil, err
	}

	resp, err := (tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(SRKPersistentHandle),
			Name:   srkName,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2B(template),
	}).Execute(rwc)
	if err != nil {
		return nil, fmt.Errorf("tpm: CreateKey: Create: %w", err)
	}

	return &CreatedKey{
		Private:        tpm2.Marshal(resp.OutPrivate),
		Public:         tpm2.Marshal(resp.OutPublic),
		CreationData:   tpm2.Marshal(resp.CreationData),
		CreationTicket: tpm2.Marshal(resp.CreationTicket),
	}, nil
}

// LoadKey loads a previously-created signing key into the TPM as a
// transient object under the SRK and returns a Key implementing
// crypto.Signer. An RSA key below MinRSAKeyBits is refused. The caller is
// responsible for Close().
func (t *TPM) LoadKey(private, public []byte) (*Key, error) {
	key, err := t.loadKey(private, public)
	if err != nil {
		return nil, err
	}
	if bits, isRSA := RSAKeyBits(key.alg); isRSA && bits < MinRSAKeyBits {
		_ = key.Close()
		return nil, fmt.Errorf("tpm: LoadKey: RSA-%d is below the %d-bit floor for a CA key", bits, MinRSAKeyBits)
	}
	return key, nil
}

func (t *TPM) loadKey(private, public []byte) (*Key, error) {
	rwc, err := t.transport()
	if err != nil {
		return nil, err
	}

	priv, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](private)
	if err != nil {
		return nil, fmt.Errorf("tpm: LoadKey: unmarshal private: %w", err)
	}
	pub, err := tpm2.Unmarshal[tpm2.TPM2BPublic](public)
	if err != nil {
		return nil, fmt.Errorf("tpm: LoadKey: unmarshal public: %w", err)
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
		return nil, fmt.Errorf("tpm: LoadKey: Load: %w", err)
	}

	publicTemplate, err := pub.Contents()
	if err != nil {
		_, _ = (tpm2.FlushContext{FlushHandle: loaded.ObjectHandle}.Execute(rwc))
		return nil, fmt.Errorf("tpm: LoadKey: public contents: %w", err)
	}
	parsedPub, alg, err := parsePublic(publicTemplate)
	if err != nil {
		_, _ = (tpm2.FlushContext{FlushHandle: loaded.ObjectHandle}.Execute(rwc))
		return nil, err
	}

	return &Key{
		tpm:    t,
		handle: loaded.ObjectHandle,
		name:   loaded.Name,
		pub:    parsedPub,
		alg:    alg,
	}, nil
}

// Close flushes the loaded key from the TPM. Calling Close twice or
// after the parent TPM has closed is a safe no-op.
func (k *Key) Close() error {
	if k == nil || k.tpm == nil || k.tpm.rwc == nil {
		return nil
	}
	if _, err := (tpm2.FlushContext{FlushHandle: k.handle}.Execute(k.tpm.rwc)); err != nil {
		return fmt.Errorf("tpm: Key.Close: FlushContext: %w", err)
	}
	k.tpm = nil
	return nil
}

// keyAttributes are the object attributes of every signing key this package
// creates: generated inside the TPM (sensitiveDataOrigin), never duplicable off
// it (fixedTPM) or re-parented (fixedParent), and usable with a password auth
// session.
var keyAttributes = tpm2.TPMAObject{
	SignEncrypt:         true,
	FixedTPM:            true,
	FixedParent:         true,
	SensitiveDataOrigin: true,
	UserWithAuth:        true,
}

// publicTemplate builds the TPMTPublic template for the requested algorithm.
func publicTemplate(alg KeyAlgorithm) (tpm2.TPMTPublic, error) {
	if bits, isRSA := RSAKeyBits(alg); isRSA {
		if bits < MinRSAKeyBits {
			return tpm2.TPMTPublic{}, fmt.Errorf("tpm: RSA-%d is below the %d-bit floor for a CA key", bits, MinRSAKeyBits)
		}
		return rsaTemplate(bits), nil
	}
	if alg != AlgorithmECDSAP384 {
		return tpm2.TPMTPublic{}, fmt.Errorf("tpm: unsupported KeyAlgorithm %d", alg)
	}
	return tpm2.TPMTPublic{
		Type:             tpm2.TPMAlgECC,
		NameAlg:          tpm2.TPMAlgSHA256,
		ObjectAttributes: keyAttributes,
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Symmetric: tpm2.TPMTSymDefObject{Algorithm: tpm2.TPMAlgNull},
			Scheme: tpm2.TPMTECCScheme{
				Scheme: tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{
					HashAlg: tpm2.TPMAlgSHA384,
				}),
			},
			CurveID: tpm2.TPMECCNistP384,
		}),
	}, nil
}

// rsaTemplate is the public template of an RSA signing key of the given size.
func rsaTemplate(bits int) tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:             tpm2.TPMAlgRSA,
		NameAlg:          tpm2.TPMAlgSHA256,
		ObjectAttributes: keyAttributes,
		Parameters:       tpm2.NewTPMUPublicParms(tpm2.TPMAlgRSA, rsaParms(bits)),
	}
}

// rsaParms are the RSA key parameters for a signing key of the given size.
// The scheme is left null so the key carries no fixed padding or hash: each
// Sign call names both from the caller's crypto.SignerOpts. A zero exponent is
// the TPM's encoding of the default, 65537.
func rsaParms(bits int) *tpm2.TPMSRSAParms {
	return &tpm2.TPMSRSAParms{
		Symmetric: tpm2.TPMTSymDefObject{Algorithm: tpm2.TPMAlgNull},
		Scheme:    tpm2.TPMTRSAScheme{Scheme: tpm2.TPMAlgNull},
		KeyBits:   tpm2.TPMIRSAKeyBits(bits),
	}
}

// testParms asks the TPM, with TPM2_TestParms, whether it implements the
// algorithm and parameters of template. It creates nothing.
func testParms(rwc transport.TPM, template tpm2.TPMTPublic) error {
	_, err := (tpm2.TestParms{
		Parameters: tpm2.TPMTPublicParms{Type: template.Type, Parameters: template.Parameters},
	}).Execute(rwc)
	return err
}

// algName is the machine-config spelling of alg, for error messages.
func algName(alg KeyAlgorithm) string {
	if bits, isRSA := RSAKeyBits(alg); isRSA {
		return fmt.Sprintf("RSA-%d", bits)
	}
	if alg == AlgorithmECDSAP384 {
		return "ECDSA-P384"
	}
	return fmt.Sprintf("KeyAlgorithm(%d)", alg)
}

// parsePublic extracts the crypto public key and KeyAlgorithm from the
// TPM-returned public area of a loaded key.
func parsePublic(t *tpm2.TPMTPublic) (crypto.PublicKey, KeyAlgorithm, error) {
	switch t.Type {
	case tpm2.TPMAlgECC:
		return parseECDSAPublic(t)
	case tpm2.TPMAlgRSA:
		return parseRSAPublic(t)
	default:
		return nil, 0, fmt.Errorf("tpm: parsePublic: unsupported key type 0x%x", t.Type)
	}
}

// parseRSAPublic extracts a crypto/rsa.PublicKey from the TPM-returned public
// area. It maps every size a KeyAlgorithm names; LoadKey applies the floor.
func parseRSAPublic(t *tpm2.TPMTPublic) (crypto.PublicKey, KeyAlgorithm, error) {
	parms, err := t.Parameters.RSADetail()
	if err != nil {
		return nil, 0, fmt.Errorf("tpm: parseRSAPublic: RSA parameters: %w", err)
	}
	var alg KeyAlgorithm
	switch parms.KeyBits {
	case 2048:
		alg = AlgorithmRSA2048
	case 3072:
		alg = AlgorithmRSA3072
	case 4096:
		alg = AlgorithmRSA4096
	default:
		return nil, 0, fmt.Errorf("tpm: parseRSAPublic: unexpected RSA key size %d", parms.KeyBits)
	}
	modulus, err := t.Unique.RSA()
	if err != nil {
		return nil, 0, fmt.Errorf("tpm: parseRSAPublic: RSA modulus: %w", err)
	}
	pub, err := tpm2.RSAPub(parms, modulus)
	if err != nil {
		return nil, 0, fmt.Errorf("tpm: parseRSAPublic: %w", err)
	}
	return pub, alg, nil
}

// parseECDSAPublic extracts a crypto/ecdsa.PublicKey from the TPM-returned
// public template.
func parseECDSAPublic(t *tpm2.TPMTPublic) (crypto.PublicKey, KeyAlgorithm, error) {
	if t.Type != tpm2.TPMAlgECC {
		return nil, 0, fmt.Errorf("tpm: parseECDSAPublic: not an ECC key (type=0x%x)", t.Type)
	}
	parms, err := t.Parameters.ECCDetail()
	if err != nil {
		return nil, 0, fmt.Errorf("tpm: parseECDSAPublic: ECC parameters: %w", err)
	}
	if parms.CurveID != tpm2.TPMECCNistP384 {
		return nil, 0, fmt.Errorf("tpm: parseECDSAPublic: unexpected curve 0x%x", parms.CurveID)
	}
	point, err := t.Unique.ECC()
	if err != nil {
		return nil, 0, fmt.Errorf("tpm: parseECDSAPublic: ECC point: %w", err)
	}
	pub := &ecdsa.PublicKey{
		Curve: elliptic.P384(),
		X:     new(big.Int).SetBytes(point.X.Buffer),
		Y:     new(big.Int).SetBytes(point.Y.Buffer),
	}
	// The TPM generated this point and the curve check it ran is
	// authoritative; the stdlib IsOnCurve API is deprecated, so we
	// don't re-validate on this side.
	return pub, AlgorithmECDSAP384, nil
}

// readSRKName reads the public Name of the persistent SRK so that it
// can be used in AuthHandle for subsequent commands.
func readSRKName(rwc transport.TPM) (tpm2.TPM2BName, error) {
	pub, err := (tpm2.ReadPublic{
		ObjectHandle: tpm2.TPMHandle(SRKPersistentHandle),
	}).Execute(rwc)
	if err != nil {
		return tpm2.TPM2BName{}, fmt.Errorf("tpm: readSRKName: %w", err)
	}
	return pub.Name, nil
}
