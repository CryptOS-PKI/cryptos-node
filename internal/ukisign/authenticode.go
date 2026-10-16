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
	"encoding/asn1"
	"errors"
	"fmt"
	"slices"
	"unicode/utf16"

	"golang.org/x/crypto/cryptobyte"
	casn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// Object identifiers for Authenticode (Microsoft's "Windows Authenticode
// Portable Executable Signature Format") and the PKCS #7 / CMS pieces it uses.
var (
	oidSignedData        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidAttrContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidAttrMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSHA256            = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidRSAEncryption     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidSpcIndirectData   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 4}
	oidSpcSpOpusInfo     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 12}
	oidSpcPeImageData    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 15}
)

// imageHash is the Authenticode PE image hash (SHA-256): the headers without
// the CheckSum field and the certificate table directory entry, then every
// section's raw data in file order, then whatever follows the sections up to
// the certificate table. The certificate table itself is never hashed, which
// is what lets the signature live inside the file it signs.
func imageHash(p *peImage) []byte {
	b := p.data
	h := sha256.New()
	h.Write(b[:p.checksumOff])
	h.Write(b[p.checksumOff+4 : p.secDirOff()])
	h.Write(b[p.secDirOff()+8 : p.sizeOfHeaders])

	sections := slices.Clone(p.sections)
	slices.SortStableFunc(sections, func(x, y peSection) int { return int(int64(x.rawPtr) - int64(y.rawPtr)) })
	hashed := uint64(p.sizeOfHeaders)
	for _, s := range sections {
		if s.rawSize == 0 {
			continue
		}
		h.Write(b[s.rawPtr : s.rawPtr+s.rawSize])
		hashed += uint64(s.rawSize)
	}

	end := uint64(len(b))
	if off, size := p.certTable(); size > 0 {
		end = uint64(off)
	}
	if hashed < end {
		h.Write(b[hashed:end])
	}

	return h.Sum(nil)
}

// obsolete is the "<<<Obsolete>>>" file link, UTF-16BE, that SpcPeImageData
// carries by convention (signtool, sbsign and osslsigncode all write it).
func obsolete() []byte {
	var b []byte
	for _, r := range utf16.Encode([]rune("<<<Obsolete>>>")) {
		b = append(b, byte(r>>8), byte(r))
	}

	return b
}

func addSHA256Alg(b *cryptobyte.Builder) {
	b.AddASN1(casn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(oidSHA256)
		b.AddASN1NULL()
	})
}

// spcIndirectData is the SpcIndirectDataContent that carries the image hash:
//
//	SpcIndirectDataContent ::= SEQUENCE {
//	    data          SpcAttributeTypeAndOptionalValue, -- SpcPeImageData
//	    messageDigest DigestInfo }
func spcIndirectData(digest []byte) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(casn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(casn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oidSpcPeImageData)
			// SpcPeImageData ::= SEQUENCE { flags BIT STRING, file [0] EXPLICIT SpcLink }
			b.AddASN1(casn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1BitString(nil)
				b.AddASN1(casn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
					// SpcLink file [2] EXPLICIT SpcString, unicode [0] IMPLICIT BMPString.
					b.AddASN1(casn1.Tag(2).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
						b.AddASN1(casn1.Tag(0).ContextSpecific(), func(b *cryptobyte.Builder) {
							b.AddBytes(obsolete())
						})
					})
				})
			})
		})
		b.AddASN1(casn1.SEQUENCE, func(b *cryptobyte.Builder) {
			addSHA256Alg(b)
			b.AddASN1OctetString(digest)
		})
	})

	return b.Bytes()
}

// contentOctets returns the contents of a DER element, without its tag and
// length. Authenticode follows PKCS #7 v1.5 here: the messageDigest attribute
// is over the contents octets of SpcIndirectDataContent, not over the whole
// encoding.
func contentOctets(der []byte) ([]byte, error) {
	s := cryptobyte.String(der)
	var inner cryptobyte.String
	var tag casn1.Tag
	if !s.ReadAnyASN1(&inner, &tag) || !s.Empty() {
		return nil, errors.New("malformed DER element")
	}

	return inner, nil
}

func attribute(oid asn1.ObjectIdentifier, value func(*cryptobyte.Builder)) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(casn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(oid)
		b.AddASN1(casn1.SET, value)
	})

	return b.Bytes()
}

// signedAttributes is the DER SET OF the signed attributes (contentType,
// messageDigest and an empty SpcSpOpusInfo, the set sbsign writes), its
// members sorted as DER requires. The signature is over exactly these bytes.
func signedAttributes(spcContents []byte) ([]byte, error) {
	md := sha256.Sum256(spcContents)
	var attrs [][]byte
	for _, a := range []struct {
		oid   asn1.ObjectIdentifier
		value func(*cryptobyte.Builder)
	}{
		{oidAttrContentType, func(b *cryptobyte.Builder) { b.AddASN1ObjectIdentifier(oidSpcIndirectData) }},
		{oidAttrMessageDigest, func(b *cryptobyte.Builder) { b.AddASN1OctetString(md[:]) }},
		{oidSpcSpOpusInfo, func(b *cryptobyte.Builder) { b.AddASN1(casn1.SEQUENCE, func(*cryptobyte.Builder) {}) }},
	} {
		enc, err := attribute(a.oid, a.value)
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, enc)
	}
	slices.SortFunc(attrs, bytes.Compare)

	var b cryptobyte.Builder
	b.AddASN1(casn1.SET, func(b *cryptobyte.Builder) {
		for _, a := range attrs {
			b.AddBytes(a)
		}
	})

	return b.Bytes()
}

// authenticode builds the PKCS #7 SignedData ContentInfo over the image hash,
// signed by key with RSA PKCS#1 v1.5 and carrying cert.
//
// internal/cms is not used: it writes CMS, where eContent is an OCTET STRING
// and the message digest is over its contents. Authenticode is PKCS #7 v1.5:
// the SpcIndirectDataContent goes in as itself and is digested without its
// outer tag and length. Firmware and sbverify expect exactly that.
func authenticode(digest []byte, key crypto.Signer, cert *x509.Certificate) ([]byte, error) {
	spc, err := spcIndirectData(digest)
	if err != nil {
		return nil, err
	}
	spcContents, err := contentOctets(spc)
	if err != nil {
		return nil, err
	}
	attrs, err := signedAttributes(spcContents)
	if err != nil {
		return nil, err
	}
	attrsDigest := sha256.Sum256(attrs)
	sig, err := key.Sign(rand.Reader, attrsDigest[:], crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("sign the signed attributes: %w", err)
	}

	var b cryptobyte.Builder
	b.AddASN1(casn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(oidSignedData)
		b.AddASN1(casn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
			b.AddASN1(casn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1Int64(1)
				b.AddASN1(casn1.SET, addSHA256Alg)
				b.AddASN1(casn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1ObjectIdentifier(oidSpcIndirectData)
					b.AddASN1(casn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
						b.AddBytes(spc)
					})
				})
				b.AddASN1(casn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
					b.AddBytes(cert.Raw)
				})
				b.AddASN1(casn1.SET, func(b *cryptobyte.Builder) {
					b.AddASN1(casn1.SEQUENCE, func(b *cryptobyte.Builder) {
						b.AddASN1Int64(1)
						b.AddASN1(casn1.SEQUENCE, func(b *cryptobyte.Builder) {
							b.AddBytes(cert.RawIssuer)
							b.AddASN1BigInt(cert.SerialNumber)
						})
						addSHA256Alg(b)
						// The signed attributes again, as [0] IMPLICIT.
						b.AddASN1(casn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
							inner, _ := contentOctets(attrs)
							b.AddBytes(inner)
						})
						b.AddASN1(casn1.SEQUENCE, func(b *cryptobyte.Builder) {
							b.AddASN1ObjectIdentifier(oidRSAEncryption)
							b.AddASN1NULL()
						})
						b.AddASN1OctetString(sig)
					})
				})
			})
		})
	})

	return b.Bytes()
}

// verifyAuthenticode checks a SignedData built by authenticode: the single
// signer's signature over the signed attributes verifies against cert, the
// content type is SpcIndirectDataContent, and the messageDigest attribute
// matches the content. It returns the image hash the signature covers.
func verifyAuthenticode(der []byte, cert *x509.Certificate) ([]byte, error) {
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("the certificate holds a %T key, want RSA", cert.PublicKey)
	}

	in := cryptobyte.String(der)
	var ci, ciBody, sd, encap, encapBody, spc, signerInfos, si, attrsElem cryptobyte.String
	var ctype, econtentType asn1.ObjectIdentifier
	var version int64
	var sig []byte
	explicit0 := casn1.Tag(0).Constructed().ContextSpecific()
	if !in.ReadASN1(&ci, casn1.SEQUENCE) ||
		!ci.ReadASN1ObjectIdentifier(&ctype) || !ctype.Equal(oidSignedData) ||
		!ci.ReadASN1(&ciBody, explicit0) ||
		!ciBody.ReadASN1(&sd, casn1.SEQUENCE) ||
		!sd.ReadASN1Int64WithTag(&version, casn1.INTEGER) || version != 1 ||
		!sd.SkipASN1(casn1.SET) ||
		!sd.ReadASN1(&encap, casn1.SEQUENCE) ||
		!encap.ReadASN1ObjectIdentifier(&econtentType) || !econtentType.Equal(oidSpcIndirectData) ||
		!encap.ReadASN1(&encapBody, explicit0) ||
		!encapBody.ReadASN1Element(&spc, casn1.SEQUENCE) ||
		!sd.SkipOptionalASN1(explicit0) ||
		!sd.SkipOptionalASN1(casn1.Tag(1).Constructed().ContextSpecific()) ||
		!sd.ReadASN1(&signerInfos, casn1.SET) ||
		!signerInfos.ReadASN1(&si, casn1.SEQUENCE) || !signerInfos.Empty() ||
		!si.SkipASN1(casn1.INTEGER) ||
		!si.SkipASN1(casn1.SEQUENCE) ||
		!si.SkipASN1(casn1.SEQUENCE) ||
		!si.ReadASN1Element(&attrsElem, explicit0) ||
		!si.SkipASN1(casn1.SEQUENCE) ||
		!si.ReadASN1Bytes(&sig, casn1.OCTET_STRING) {
		return nil, errors.New("the SignedData is not the shape this tool writes")
	}

	// The signature covers the attributes as a SET, not as the [0] IMPLICIT
	// encoding they travel in.
	signed := bytes.Clone(attrsElem)
	signed[0] = 0x31
	attrsDigest := sha256.Sum256(signed)
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, attrsDigest[:], sig); err != nil {
		return nil, fmt.Errorf("the signature does not verify against the certificate: %w", err)
	}

	spcContents, err := contentOctets(spc)
	if err != nil {
		return nil, err
	}
	want := sha256.Sum256(spcContents)
	var attrs cryptobyte.String
	if attrsIn := attrsElem; !attrsIn.ReadASN1(&attrs, explicit0) {
		return nil, errors.New("malformed signed attributes")
	}
	var gotType, gotDigest bool
	for !attrs.Empty() {
		var attr, values cryptobyte.String
		var oid asn1.ObjectIdentifier
		if !attrs.ReadASN1(&attr, casn1.SEQUENCE) || !attr.ReadASN1ObjectIdentifier(&oid) || !attr.ReadASN1(&values, casn1.SET) {
			return nil, errors.New("malformed signed attribute")
		}
		switch {
		case oid.Equal(oidAttrContentType):
			var v asn1.ObjectIdentifier
			if !values.ReadASN1ObjectIdentifier(&v) || !v.Equal(oidSpcIndirectData) {
				return nil, errors.New("the contentType attribute is not SpcIndirectDataContent")
			}
			gotType = true
		case oid.Equal(oidAttrMessageDigest):
			var v []byte
			if !values.ReadASN1Bytes(&v, casn1.OCTET_STRING) || !bytes.Equal(v, want[:]) {
				return nil, errors.New("the messageDigest attribute does not match the content")
			}
			gotDigest = true
		}
	}
	if !gotType || !gotDigest {
		return nil, errors.New("the contentType or messageDigest attribute is missing")
	}

	var body, digestInfo cryptobyte.String
	var alg asn1.ObjectIdentifier
	var digest []byte
	if spcIn := spc; !spcIn.ReadASN1(&body, casn1.SEQUENCE) ||
		!body.SkipASN1(casn1.SEQUENCE) ||
		!body.ReadASN1(&digestInfo, casn1.SEQUENCE) ||
		!digestInfo.ReadASN1(&body, casn1.SEQUENCE) ||
		!body.ReadASN1ObjectIdentifier(&alg) || !alg.Equal(oidSHA256) ||
		!digestInfo.ReadASN1Bytes(&digest, casn1.OCTET_STRING) {
		return nil, errors.New("malformed SpcIndirectDataContent")
	}

	return digest, nil
}
