package acme

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
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
)

// minJWSRSABits is the smallest RSA key accepted for a JWS signature. An
// account key is never certified, so ca.MinRSASubjectKeyBits does not apply;
// 2048 is the floor every ACME client defaults to or exceeds.
const minJWSRSABits = 2048

// flattenedJWS is the RFC 7515 section 7.2.2 flattened JSON serialization.
// RFC 8555 section 6.2 mandates this form: compact serialization and the
// general (multi-signature) form are both refused.
type flattenedJWS struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`

	// Header is the unprotected header. RFC 8555 section 6.2 forbids it; it
	// is decoded only so its presence can be detected and rejected.
	Header json.RawMessage `json:"header,omitempty"`
}

// protectedHeader is the decoded JWS protected header. Every ACME request
// carries alg, nonce, url, and exactly one of jwk or kid (RFC 8555 section
// 6.2). Unknown members are ignored, but "crit" is rejected: honouring an
// extension we do not understand is exactly what crit exists to prevent.
type protectedHeader struct {
	Alg   string   `json:"alg"`
	Nonce string   `json:"nonce"`
	URL   string   `json:"url"`
	JWK   *JWK     `json:"jwk,omitempty"`
	KID   string   `json:"kid,omitempty"`
	Crit  []string `json:"crit,omitempty"`
}

// JWK is the subset of RFC 7517 this server understands: EC keys on P-256 or
// P-384, and RSA keys. Private members (d, p, q, ...) are absent by
// construction, so a stored JWK can never hold key material.
type JWK struct {
	Kty string `json:"kty"`

	// EC members (RFC 7518 section 6.2).
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`

	// RSA members (RFC 7518 section 6.3).
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`
}

// b64 is the base64url encoding without padding used throughout JOSE.
var b64 = base64.RawURLEncoding

// signatureAlg describes one entry in the algorithm allowlist. Binding the
// hash and the expected key shape to the alg name here is what makes
// algorithm confusion structurally impossible: a header claiming ES256 can
// only ever be checked as ECDSA on P-256, and one claiming RS256 can only
// ever be checked as RSA.
type signatureAlg struct {
	hash crypto.Hash
	// curve is the required curve for an EC alg, nil for an RSA alg.
	curve elliptic.Curve
	// pss selects RSASSA-PSS over RSASSA-PKCS1-v1_5.
	pss bool
}

// jwsAlgs is the complete set of signature algorithms this server accepts.
// "none" is absent, as is every MAC alg: a MAC on the outer JWS would let a
// caller sign as an account whose key it does not hold. MAC algs are accepted
// only inside an external account binding, which has its own table.
var jwsAlgs = map[string]signatureAlg{
	"RS256": {hash: crypto.SHA256},
	"RS384": {hash: crypto.SHA384},
	"RS512": {hash: crypto.SHA512},
	"PS256": {hash: crypto.SHA256, pss: true},
	"PS384": {hash: crypto.SHA384, pss: true},
	"PS512": {hash: crypto.SHA512, pss: true},
	"ES256": {hash: crypto.SHA256, curve: elliptic.P256()},
	"ES384": {hash: crypto.SHA384, curve: elliptic.P384()},
}

// macAlgs is the allowlist for the external account binding (RFC 8555 section
// 7.3.4), which is MAC-protected with a key the operator provisioned.
var macAlgs = map[string]crypto.Hash{
	"HS256": crypto.SHA256,
	"HS384": crypto.SHA384,
	"HS512": crypto.SHA512,
}

// parseJWS decodes body as a flattened JSON JWS and returns the envelope, the
// decoded protected header, and the decoded payload. It enforces the RFC 8555
// section 6.2 structural rules but verifies no signature; see verifyJWS.
func parseJWS(body []byte) (*flattenedJWS, *protectedHeader, []byte, error) {
	var jws flattenedJWS
	if err := json.Unmarshal(body, &jws); err != nil {
		return nil, nil, nil, malformed("request body is not a flattened JSON JWS: %v", err)
	}
	if len(jws.Header) != 0 {
		return nil, nil, nil, malformed("JWS carries an unprotected header, which RFC 8555 section 6.2 forbids")
	}
	if jws.Protected == "" {
		return nil, nil, nil, malformed("JWS protected header is empty")
	}

	hdr, err := decodeProtected(jws.Protected)
	if err != nil {
		return nil, nil, nil, err
	}

	// An empty payload is legal and meaningful: it is the POST-as-GET form
	// (RFC 8555 section 6.3), distinct from a payload of "{}".
	var payload []byte
	if jws.Payload != "" {
		payload, err = b64.DecodeString(jws.Payload)
		if err != nil {
			return nil, nil, nil, malformed("JWS payload is not valid base64url: %v", err)
		}
	}
	return &jws, hdr, payload, nil
}

// decodeProtected base64url-decodes and validates the protected header.
func decodeProtected(encoded string) (*protectedHeader, error) {
	raw, err := b64.DecodeString(encoded)
	if err != nil {
		return nil, malformed("JWS protected header is not valid base64url: %v", err)
	}
	var hdr protectedHeader
	if err := json.Unmarshal(raw, &hdr); err != nil {
		return nil, malformed("JWS protected header is not valid JSON: %v", err)
	}
	if len(hdr.Crit) != 0 {
		return nil, malformed("JWS protected header sets crit, which this server does not support")
	}
	if hdr.Alg == "" {
		return nil, malformed("JWS protected header omits alg")
	}
	if hdr.URL == "" {
		return nil, malformed("JWS protected header omits url")
	}
	if (hdr.JWK == nil) == (hdr.KID == "") {
		return nil, malformed("JWS protected header must carry exactly one of jwk or kid")
	}
	return &hdr, nil
}

// verifyJWS checks the signature over protected||"."||payload using pub, with
// the algorithm named by alg. alg must be in the allowlist and must match the
// concrete type and curve of pub.
func verifyJWS(jws *flattenedJWS, alg string, pub crypto.PublicKey) error {
	spec, ok := jwsAlgs[alg]
	if !ok {
		return problemf(ErrBadSignatureAlgorithm, http.StatusBadRequest, "unsupported JWS algorithm %q", alg)
	}
	sig, err := b64.DecodeString(jws.Signature)
	if err != nil {
		return malformed("JWS signature is not valid base64url: %v", err)
	}

	signingInput := []byte(jws.Protected + "." + jws.Payload)
	digest := hashBytes(spec.hash, signingInput)

	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		if spec.curve == nil {
			return problemf(ErrBadSignatureAlgorithm, http.StatusBadRequest, "algorithm %q is an RSA algorithm but the key is ECDSA", alg)
		}
		if key.Curve != spec.curve {
			return problemf(ErrBadSignatureAlgorithm, http.StatusBadRequest,
				"algorithm %q requires curve %s but the key is on %s", alg, spec.curve.Params().Name, key.Curve.Params().Name)
		}
		// JOSE ECDSA signatures are the fixed-width R||S concatenation
		// (RFC 7518 section 3.4), not the ASN.1 form crypto/x509 uses.
		byteLen := (key.Curve.Params().BitSize + 7) / 8
		if len(sig) != 2*byteLen {
			return malformed("ECDSA JWS signature must be %d bytes, got %d", 2*byteLen, len(sig))
		}
		r := new(big.Int).SetBytes(sig[:byteLen])
		s := new(big.Int).SetBytes(sig[byteLen:])
		if !ecdsa.Verify(key, digest, r, s) {
			return unauthorized("JWS signature verification failed")
		}
		return nil

	case *rsa.PublicKey:
		if spec.curve != nil {
			return problemf(ErrBadSignatureAlgorithm, http.StatusBadRequest, "algorithm %q is an ECDSA algorithm but the key is RSA", alg)
		}
		if bits := key.N.BitLen(); bits < minJWSRSABits {
			return problemf(ErrBadPublicKey, http.StatusBadRequest, "RSA account key must be at least %d bits, got %d", minJWSRSABits, bits)
		}
		if spec.pss {
			// SaltLengthEqualsHash is what RFC 7518 section 3.5 specifies.
			opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: spec.hash}
			if err := rsa.VerifyPSS(key, spec.hash, digest, sig, opts); err != nil {
				return unauthorized("JWS signature verification failed")
			}
			return nil
		}
		if err := rsa.VerifyPKCS1v15(key, spec.hash, digest, sig); err != nil {
			return unauthorized("JWS signature verification failed")
		}
		return nil

	default:
		return problemf(ErrBadPublicKey, http.StatusBadRequest, "unsupported account key type %T", pub)
	}
}

// hashBytes returns h(data). Only SHA-256/384/512 reach this, all of which are
// linked into the binary by the imports above.
func hashBytes(h crypto.Hash, data []byte) []byte {
	switch h {
	case crypto.SHA256:
		sum := sha256.Sum256(data)
		return sum[:]
	case crypto.SHA384:
		sum := sha512.Sum384(data)
		return sum[:]
	default:
		sum := sha512.Sum512(data)
		return sum[:]
	}
}

// PublicKey converts the JWK to a crypto.PublicKey. It refuses anything
// outside the supported set rather than returning a partially-populated key.
func (j *JWK) PublicKey() (crypto.PublicKey, error) {
	if j == nil {
		return nil, malformed("JWK is absent")
	}
	switch j.Kty {
	case "EC":
		var curve elliptic.Curve
		switch j.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		default:
			return nil, problemf(ErrBadPublicKey, http.StatusBadRequest, "unsupported EC curve %q", j.Crv)
		}
		byteLen := (curve.Params().BitSize + 7) / 8
		xb, err := decodeCoordinate(j.X, byteLen)
		if err != nil {
			return nil, err
		}
		yb, err := decodeCoordinate(j.Y, byteLen)
		if err != nil {
			return nil, err
		}
		// The on-curve check has to happen before the point is used: a point
		// off the curve is a classic invalid-curve attack input.
		// ParseUncompressedPublicKey does that check and takes the
		// uncompressed SEC 1 encoding, 0x04 || X || Y. It returns the same
		// curve and coordinates the struct literal did (#412).
		point := make([]byte, 0, 1+2*byteLen)
		point = append(point, 4)
		point = append(point, xb...)
		point = append(point, yb...)
		pub, err := ecdsa.ParseUncompressedPublicKey(curve, point)
		if err != nil {
			return nil, problemf(ErrBadPublicKey, http.StatusBadRequest, "EC JWK point is not on curve %s", j.Crv)
		}
		return pub, nil

	case "RSA":
		nBytes, err := b64.DecodeString(j.N)
		if err != nil || len(nBytes) == 0 {
			return nil, problemf(ErrBadPublicKey, http.StatusBadRequest, "RSA JWK modulus is not valid base64url")
		}
		eBytes, err := b64.DecodeString(j.E)
		if err != nil || len(eBytes) == 0 || len(eBytes) > 8 {
			return nil, problemf(ErrBadPublicKey, http.StatusBadRequest, "RSA JWK exponent is not valid base64url")
		}
		e := new(big.Int).SetBytes(eBytes)
		if !e.IsInt64() || e.Int64() < 3 || e.Bit(0) == 0 {
			return nil, problemf(ErrBadPublicKey, http.StatusBadRequest, "RSA JWK exponent must be an odd integer of at least 3")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(e.Int64())}, nil

	default:
		return nil, problemf(ErrBadPublicKey, http.StatusBadRequest, "unsupported JWK key type %q", j.Kty)
	}
}

// decodeCoordinate decodes one EC coordinate, requiring the fixed width RFC
// 7518 section 6.2.1.2 mandates. A short or long encoding is a malformed key,
// not something to pad around: two encodings of one point would otherwise
// produce two thumbprints, and the thumbprint is the account identity.
func decodeCoordinate(encoded string, byteLen int) ([]byte, error) {
	raw, err := b64.DecodeString(encoded)
	if err != nil {
		return nil, problemf(ErrBadPublicKey, http.StatusBadRequest, "EC JWK coordinate is not valid base64url")
	}
	if len(raw) != byteLen {
		return nil, problemf(ErrBadPublicKey, http.StatusBadRequest, "EC JWK coordinate must be %d bytes, got %d", byteLen, len(raw))
	}
	return raw, nil
}

// Thumbprint returns the RFC 7638 SHA-256 JWK thumbprint, base64url-encoded.
// This is the account's stable identity: it is what a key authorization binds
// a challenge to, and what indexes an account for a JWS that carries a kid.
//
// The canonical form is a JSON object with no whitespace holding only the
// required members, in lexicographic order. The members are written literally
// rather than via encoding/json so the ordering is guaranteed by the code
// rather than by a map iteration.
func (j *JWK) Thumbprint() (string, error) {
	if j == nil {
		return "", malformed("JWK is absent")
	}
	// Round-tripping through PublicKey first rejects a malformed key, so a
	// thumbprint is only ever computed over members we have validated.
	if _, err := j.PublicKey(); err != nil {
		return "", err
	}
	var canonical string
	switch j.Kty {
	case "EC":
		canonical = fmt.Sprintf(`{"crv":%q,"kty":"EC","x":%q,"y":%q}`, j.Crv, j.X, j.Y)
	case "RSA":
		canonical = fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, j.E, j.N)
	default:
		return "", problemf(ErrBadPublicKey, http.StatusBadRequest, "unsupported JWK key type %q", j.Kty)
	}
	sum := sha256.Sum256([]byte(canonical))
	return b64.EncodeToString(sum[:]), nil
}

// JWKFromPublic builds a JWK from a public key, used to compare a certificate
// key against an account key by thumbprint during revocation.
func JWKFromPublic(pub crypto.PublicKey) (*JWK, error) {
	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		var crv string
		switch key.Curve {
		case elliptic.P256():
			crv = "P-256"
		case elliptic.P384():
			crv = "P-384"
		default:
			return nil, fmt.Errorf("acme: unsupported EC curve %s", key.Curve.Params().Name)
		}
		// Bytes is the uncompressed SEC 1 encoding, 0x04 || X || Y, with each
		// coordinate already at the curve's fixed width.
		point, err := key.Bytes()
		if err != nil {
			return nil, fmt.Errorf("acme: encode EC public key: %w", err)
		}
		byteLen := (len(point) - 1) / 2
		return &JWK{
			Kty: "EC",
			Crv: crv,
			X:   b64.EncodeToString(point[1 : 1+byteLen]),
			Y:   b64.EncodeToString(point[1+byteLen:]),
		}, nil
	case *rsa.PublicKey:
		e := big.NewInt(int64(key.E)).Bytes()
		return &JWK{
			Kty: "RSA",
			N:   b64.EncodeToString(key.N.Bytes()),
			E:   b64.EncodeToString(e),
		}, nil
	default:
		return nil, fmt.Errorf("acme: unsupported public key type %T", pub)
	}
}

// KeyAuthorization returns the RFC 8555 section 8.1 key authorization for a
// token and an account key thumbprint.
func KeyAuthorization(token, thumbprint string) string {
	return token + "." + thumbprint
}

// errUnknownEABKey is returned by an EABKeyFunc when the key ID is not
// provisioned. It is mapped to an unauthorized problem by the caller so an
// unknown key ID and a bad MAC are indistinguishable to a probing client.
var errUnknownEABKey = errors.New("acme: unknown external account key id")

// verifyExternalAccountBinding checks the nested MAC-protected JWS that ties a
// new account to an operator-provisioned key (RFC 8555 section 7.3.4).
//
// Three things must hold, and all three matter: the MAC must verify under the
// key named by kid, the inner url must equal the outer request url (so a
// binding cannot be replayed against a different endpoint), and the inner
// payload must be exactly the account key being registered (so a captured
// binding cannot be attached to an attacker's key).
func verifyExternalAccountBinding(eab *flattenedJWS, requestURL string, accountKey *JWK, lookup func(keyID string) ([]byte, error)) (string, error) {
	if eab == nil {
		return "", problemf(ErrExternalAccountRequired, http.StatusBadRequest, "this server requires an external account binding")
	}
	hdr, err := decodeEABHeader(eab.Protected)
	if err != nil {
		return "", err
	}
	hash, ok := macAlgs[hdr.Alg]
	if !ok {
		return "", problemf(ErrBadSignatureAlgorithm, http.StatusBadRequest,
			"external account binding must use a MAC algorithm, got %q", hdr.Alg)
	}
	if hdr.URL != requestURL {
		return "", unauthorized("external account binding url does not match the request url")
	}

	macKey, err := lookup(hdr.KID)
	if err != nil {
		// Deliberately the same problem a bad MAC produces.
		return "", unauthorized("external account binding is not valid")
	}

	mac := hmac.New(hash.New, macKey)
	mac.Write([]byte(eab.Protected + "." + eab.Payload))
	want := mac.Sum(nil)
	got, err := b64.DecodeString(eab.Signature)
	if err != nil {
		return "", malformed("external account binding signature is not valid base64url: %v", err)
	}
	if subtle.ConstantTimeCompare(want, got) != 1 {
		return "", unauthorized("external account binding is not valid")
	}

	// The bound payload must be the account key itself.
	payload, err := b64.DecodeString(eab.Payload)
	if err != nil {
		return "", malformed("external account binding payload is not valid base64url: %v", err)
	}
	var boundKey JWK
	if err := json.Unmarshal(payload, &boundKey); err != nil {
		return "", malformed("external account binding payload is not a JWK: %v", err)
	}
	boundThumb, err := boundKey.Thumbprint()
	if err != nil {
		return "", err
	}
	accountThumb, err := accountKey.Thumbprint()
	if err != nil {
		return "", err
	}
	if boundThumb != accountThumb {
		return "", unauthorized("external account binding is bound to a different key than the account key")
	}
	return hdr.KID, nil
}

// decodeEABHeader decodes the inner binding's protected header, which carries
// alg, kid and url but never a jwk or a nonce (RFC 8555 section 7.3.4).
func decodeEABHeader(encoded string) (*protectedHeader, error) {
	raw, err := b64.DecodeString(encoded)
	if err != nil {
		return nil, malformed("external account binding header is not valid base64url: %v", err)
	}
	var hdr protectedHeader
	if err := json.Unmarshal(raw, &hdr); err != nil {
		return nil, malformed("external account binding header is not valid JSON: %v", err)
	}
	if len(hdr.Crit) != 0 {
		return nil, malformed("external account binding sets crit, which this server does not support")
	}
	if hdr.KID == "" {
		return nil, malformed("external account binding header omits kid")
	}
	if hdr.JWK != nil {
		return nil, malformed("external account binding header must not carry a jwk")
	}
	return &hdr, nil
}
