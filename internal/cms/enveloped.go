package cms

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
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
)

var (
	// ErrNoRecipient means the message has no key-transport recipient
	// matching the certificate. During an RA key rollover the caller tries
	// the next certificate on this error.
	ErrNoRecipient = errors.New("cms: no matching recipient")
	// ErrDecrypt is the single error for every failure after the recipient
	// is found: the key transport, the key length, the ciphertext length and
	// the padding. Distinguishing them would hand an attacker a padding
	// oracle.
	ErrDecrypt = errors.New("cms: decryption failed")
)

// ContentEncryption selects the content-encryption algorithm.
type ContentEncryption int

// The content-encryption algorithms behind the SCEP "AES" capability (RFC
// 8894): AES-CBC with a 128- or 256-bit key (RFC 3565).
const (
	AES128CBC ContentEncryption = iota + 1
	AES256CBC
)

func (c ContentEncryption) params() (asn1.ObjectIdentifier, int, error) {
	switch c {
	case AES128CBC:
		return oidAES128CBC, 16, nil
	case AES256CBC:
		return oidAES256CBC, 32, nil
	}
	return nil, 0, fmt.Errorf("%w: content encryption %d", ErrUnsupportedAlgorithm, int(c))
}

func contentEncryptionKeyLen(oid asn1.ObjectIdentifier) (int, error) {
	switch {
	case oid.Equal(oidAES128CBC):
		return 16, nil
	case oid.Equal(oidAES256CBC):
		return 32, nil
	}
	return 0, fmt.Errorf("%w: content encryption %s", ErrUnsupportedAlgorithm, oid)
}

// KeyTransRecipient is a parsed RFC 5652 section 6.2.1 KeyTransRecipientInfo.
// Exactly one of IssuerAndSerial and SubjectKeyID is set.
type KeyTransRecipient struct {
	Version                int
	IssuerAndSerial        *IssuerAndSerial
	SubjectKeyID           []byte
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedKey           []byte
}

func (r *KeyTransRecipient) matches(c *x509.Certificate) bool {
	if r.IssuerAndSerial != nil {
		return r.IssuerAndSerial.matches(c)
	}
	return len(c.SubjectKeyId) > 0 && bytes.Equal(r.SubjectKeyID, c.SubjectKeyId)
}

// EnvelopedData is a parsed RFC 5652 section 6.1 EnvelopedData.
type EnvelopedData struct {
	Version int
	// Recipients are the key-transport recipients. Other RecipientInfo
	// kinds (key agreement, KEK, password) are skipped: nothing this
	// package serves sends them.
	Recipients []KeyTransRecipient
	// ContentType is the type of the encrypted content.
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           []byte
}

type (
	rawEnvelopedData struct {
		Version              int
		OriginatorInfo       rawTagged       `asn1:"optional,tag:0"`
		RecipientInfos       []asn1.RawValue `asn1:"set"`
		EncryptedContentInfo rawEncryptedContentInfo
		UnprotectedAttrs     rawTagged `asn1:"optional,tag:1"`
	}
	rawEncryptedContentInfo struct {
		ContentType                asn1.ObjectIdentifier
		ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
		EncryptedContent           asn1.RawValue `asn1:"optional,tag:0"`
	}
	rawKeyTransRecipientInfo struct {
		Version                int
		RID                    asn1.RawValue
		KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
		EncryptedKey           []byte
	}
)

// ParseEnvelopedData parses a ContentInfo carrying an EnvelopedData. BER
// input is accepted, including a chunked encryptedContent.
func ParseEnvelopedData(in []byte) (*EnvelopedData, error) {
	inner, err := parseContentInfo(in, OIDEnvelopedData, "EnvelopedData")
	if err != nil {
		return nil, err
	}
	var raw rawEnvelopedData
	rest, err := asn1.Unmarshal(inner, &raw)
	if err != nil {
		return nil, fmt.Errorf("cms: EnvelopedData: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("cms: EnvelopedData: trailing bytes")
	}
	if len(raw.RecipientInfos) == 0 {
		return nil, errors.New("cms: EnvelopedData: no recipients")
	}

	ed := &EnvelopedData{
		Version:                    raw.Version,
		ContentType:                raw.EncryptedContentInfo.ContentType,
		ContentEncryptionAlgorithm: raw.EncryptedContentInfo.ContentEncryptionAlgorithm,
	}
	for i, ri := range raw.RecipientInfos {
		if ri.Class != asn1.ClassUniversal || ri.Tag != asn1.TagSequence {
			continue
		}
		r, err := parseKeyTrans(ri.FullBytes)
		if err != nil {
			return nil, fmt.Errorf("cms: EnvelopedData: recipient %d: %w", i, err)
		}
		ed.Recipients = append(ed.Recipients, r)
	}

	ec := raw.EncryptedContentInfo.EncryptedContent
	switch {
	case ec.FullBytes == nil:
		return nil, errors.New("cms: EnvelopedData: encryptedContent is absent")
	case ec.Class != asn1.ClassContextSpecific || ec.Tag != 0:
		return nil, errors.New("cms: EnvelopedData: encryptedContent is not [0]")
	case ec.IsCompound:
		// The constructed BER form of the [0] IMPLICIT OCTET STRING: a run
		// of primitive OCTET STRING segments.
		segs, err := splitElements(ec.Bytes)
		if err != nil {
			return nil, fmt.Errorf("cms: EnvelopedData: encryptedContent: %w", err)
		}
		ed.EncryptedContent = []byte{}
		for _, s := range segs {
			if s.Class != asn1.ClassUniversal || s.Tag != asn1.TagOctetString || s.IsCompound {
				return nil, errors.New("cms: EnvelopedData: encryptedContent segment is not an OCTET STRING")
			}
			ed.EncryptedContent = append(ed.EncryptedContent, s.Bytes...)
		}
	default:
		ed.EncryptedContent = ec.Bytes
	}
	return ed, nil
}

func parseKeyTrans(der []byte) (KeyTransRecipient, error) {
	var raw rawKeyTransRecipientInfo
	if rest, err := asn1.Unmarshal(der, &raw); err != nil || len(rest) != 0 {
		return KeyTransRecipient{}, errors.New("malformed KeyTransRecipientInfo")
	}
	r := KeyTransRecipient{
		Version:                raw.Version,
		KeyEncryptionAlgorithm: raw.KeyEncryptionAlgorithm,
		EncryptedKey:           raw.EncryptedKey,
	}
	switch {
	case raw.RID.Class == asn1.ClassUniversal && raw.RID.Tag == asn1.TagSequence:
		var ias IssuerAndSerial
		if rest, err := asn1.Unmarshal(raw.RID.FullBytes, &ias); err != nil || len(rest) != 0 {
			return KeyTransRecipient{}, errors.New("malformed issuerAndSerialNumber")
		}
		r.IssuerAndSerial = &ias
	case raw.RID.Class == asn1.ClassContextSpecific && raw.RID.Tag == 0 && !raw.RID.IsCompound:
		if len(raw.RID.Bytes) == 0 {
			return KeyTransRecipient{}, errors.New("empty subjectKeyIdentifier")
		}
		r.SubjectKeyID = raw.RID.Bytes
	default:
		return KeyTransRecipient{}, errors.New("unknown recipient identifier")
	}
	return r, nil
}

// Decrypt recovers the content for the recipient identified by cert. Only
// the crypto.Decrypter interface of key is used, so the key can stay in the
// TPM; it is asked for an RSA PKCS#1 v1.5 decryption with
// rsa.PKCS1v15DecryptOptions.SessionKeyLen set, which makes a
// software RSA key answer a bad padding with a random key in constant time
// instead of an error (the RFC 3218 countermeasure).
//
// CBC is unauthenticated: a tampered ciphertext can decrypt to garbage
// without an error. SCEP and every other use here wrap the EnvelopedData in
// a SignedData, and the outer signature is what proves integrity; verify it
// before decrypting.
func (ed *EnvelopedData) Decrypt(cert *x509.Certificate, key crypto.Decrypter) ([]byte, error) {
	if cert == nil || key == nil {
		return nil, errors.New("cms: Decrypt: certificate and key are both required")
	}
	if !publicKeysEqual(key.Public(), cert.PublicKey) {
		return nil, errors.New("cms: Decrypt: key does not match the certificate")
	}
	var r *KeyTransRecipient
	for i := range ed.Recipients {
		if ed.Recipients[i].matches(cert) {
			r = &ed.Recipients[i]
			break
		}
	}
	if r == nil {
		return nil, ErrNoRecipient
	}
	if !r.KeyEncryptionAlgorithm.Algorithm.Equal(oidRSAEncryption) {
		return nil, fmt.Errorf("%w: key transport %s", ErrUnsupportedAlgorithm, r.KeyEncryptionAlgorithm.Algorithm)
	}
	if _, ok := cert.PublicKey.(*rsa.PublicKey); !ok {
		return nil, fmt.Errorf("%w: key transport needs an RSA recipient", ErrUnsupportedAlgorithm)
	}
	keyLen, err := contentEncryptionKeyLen(ed.ContentEncryptionAlgorithm.Algorithm)
	if err != nil {
		return nil, err
	}
	var iv []byte
	if rest, err := asn1.Unmarshal(ed.ContentEncryptionAlgorithm.Parameters.FullBytes, &iv); err != nil || len(rest) != 0 || len(iv) != aes.BlockSize {
		return nil, errors.New("cms: Decrypt: AES-CBC parameters are not a 16-byte IV")
	}

	// SCEP clients such as sscep wrap the content key with rsaEncryption
	// (PKCS #1 v1.5) key transport, so interoperability needs it.
	cek, err := key.Decrypt(rand.Reader, r.EncryptedKey, &rsa.PKCS1v15DecryptOptions{SessionKeyLen: keyLen}) //nolint:staticcheck // SA1019: rsaEncryption key transport
	if err != nil || len(cek) != keyLen {
		return nil, ErrDecrypt
	}
	ct := ed.EncryptedContent
	if len(ct) == 0 || len(ct)%aes.BlockSize != 0 {
		return nil, ErrDecrypt
	}
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, ErrDecrypt
	}
	plain := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ct)
	n, ok := pkcs7Unpad(plain)
	if !ok {
		clear(plain)
		return nil, ErrDecrypt
	}
	return plain[:n], nil
}

// pkcs7Unpad checks RFC 5652 section 6.3 padding without branching on the
// padding bytes, and returns the unpadded length.
func pkcs7Unpad(b []byte) (int, bool) {
	n := len(b)
	pad := int(b[n-1])
	good := subtle.ConstantTimeLessOrEq(1, pad) & subtle.ConstantTimeLessOrEq(pad, aes.BlockSize)
	for i := 0; i < aes.BlockSize; i++ {
		inPad := subtle.ConstantTimeLessOrEq(i+1, pad)
		match := subtle.ConstantTimeByteEq(b[n-1-i], byte(pad)) //nolint:gosec // G115: pad was read from a byte, so it is at most 255
		good &= subtle.ConstantTimeSelect(inPad, match, 1)
	}
	if good != 1 {
		return 0, false
	}
	return n - pad, true
}

// EncryptOptions tunes Encrypt.
type EncryptOptions struct {
	// IdentifyBySKI writes each recipient identifier as the certificate's
	// subjectKeyIdentifier (KeyTransRecipientInfo version 2) instead of
	// issuer and serial number (version 0).
	IdentifyBySKI bool
}

// Encrypt builds a ContentInfo carrying an EnvelopedData of id-data content,
// with a fresh content-encryption key transported to each recipient's RSA
// key with PKCS#1 v1.5 (RFC 3370 section 4.2.1), the key transport SCEP
// clients use.
func Encrypt(content []byte, recipients []*x509.Certificate, alg ContentEncryption, opts EncryptOptions) ([]byte, error) {
	if len(recipients) == 0 {
		return nil, errors.New("cms: Encrypt: at least one recipient is required")
	}
	oid, keyLen, err := alg.params()
	if err != nil {
		return nil, err
	}

	cek := make([]byte, keyLen)
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(cek); err != nil {
		return nil, fmt.Errorf("cms: Encrypt: %w", err)
	}
	defer clear(cek)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("cms: Encrypt: %w", err)
	}

	recipientInfos := make([][]byte, 0, len(recipients))
	for i, c := range recipients {
		ri, err := keyTransRecipient(c, cek, opts.IdentifyBySKI)
		if err != nil {
			return nil, fmt.Errorf("cms: Encrypt: recipient %d: %w", i, err)
		}
		recipientInfos = append(recipientInfos, ri)
	}

	padLen := aes.BlockSize - len(content)%aes.BlockSize
	padded := make([]byte, len(content)+padLen)
	copy(padded, content)
	for i := len(content); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}
	defer clear(padded)
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, fmt.Errorf("cms: Encrypt: %w", err)
	}
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)

	ivOctets, err := asn1.Marshal(iv)
	if err != nil {
		return nil, err
	}
	algID, err := asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: oid, Parameters: asn1.RawValue{FullBytes: ivOctets}})
	if err != nil {
		return nil, err
	}
	dataOID, err := asn1.Marshal(OIDData)
	if err != nil {
		return nil, err
	}
	eci := tlv(0x30, dataOID, algID, tlv(0x80, ct))

	// RFC 5652 section 6.1: version 0 when every RecipientInfo is version 0
	// and there is no originatorInfo or unprotectedAttrs; version 2 here
	// otherwise.
	version := 0
	if opts.IdentifyBySKI {
		version = 2
	}
	v, err := asn1.Marshal(version)
	if err != nil {
		return nil, err
	}
	envOID, err := asn1.Marshal(OIDEnvelopedData)
	if err != nil {
		return nil, err
	}
	return tlv(0x30, envOID, tlv(0xa0, tlv(0x30, v, derSetOf(recipientInfos), eci))), nil
}

func keyTransRecipient(c *x509.Certificate, cek []byte, bySKI bool) ([]byte, error) {
	if c == nil {
		return nil, errors.New("nil certificate")
	}
	pub, ok := c.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: key transport needs an RSA recipient, have %T", ErrUnsupportedAlgorithm, c.PublicKey)
	}
	var rid []byte
	version := 0
	if bySKI {
		if len(c.SubjectKeyId) == 0 {
			return nil, errors.New("IdentifyBySKI set but the certificate has no subjectKeyIdentifier")
		}
		rid = tlv(0x80, c.SubjectKeyId)
		version = 2
	} else {
		serial, err := asn1.Marshal(c.SerialNumber)
		if err != nil {
			return nil, err
		}
		rid = tlv(0x30, c.RawIssuer, serial)
	}
	encKey, err := rsa.EncryptPKCS1v15(rand.Reader, pub, cek) //nolint:staticcheck // SA1019: rsaEncryption key transport, see Decrypt
	if err != nil {
		return nil, fmt.Errorf("key transport: %w", err)
	}
	v, err := asn1.Marshal(version)
	if err != nil {
		return nil, err
	}
	keyAlg, err := asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: oidRSAEncryption, Parameters: asn1.NullRawValue})
	if err != nil {
		return nil, err
	}
	encKeyOctets, err := asn1.Marshal(encKey)
	if err != nil {
		return nil, err
	}
	return tlv(0x30, v, rid, keyAlg, encKeyOctets), nil
}
