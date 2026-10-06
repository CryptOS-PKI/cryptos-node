package tsa

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
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
)

// FailureInfo is a PKIFailureInfo bit (RFC 3161 section 2.4.2).
type FailureInfo int

// The PKIFailureInfo bits a TSA answers with.
const (
	// FailBadAlg is an unrecognized or unsupported message imprint
	// algorithm.
	FailBadAlg FailureInfo = 0
	// FailBadRequest is a transaction not permitted or supported.
	FailBadRequest FailureInfo = 2
	// FailBadDataFormat is a request with the wrong format.
	FailBadDataFormat FailureInfo = 5
	// FailTimeNotAvailable means the TSA's time source is not available.
	FailTimeNotAvailable FailureInfo = 14
	// FailUnacceptedPolicy is a requested policy the TSA does not support.
	FailUnacceptedPolicy FailureInfo = 15
	// FailUnacceptedExtension is a requested extension the TSA does not
	// support.
	FailUnacceptedExtension FailureInfo = 16
	// FailSystemFailure is a request that cannot be handled because of a
	// system failure.
	FailSystemFailure FailureInfo = 25
)

func (f FailureInfo) String() string {
	switch f {
	case FailBadAlg:
		return "badAlg"
	case FailBadRequest:
		return "badRequest"
	case FailBadDataFormat:
		return "badDataFormat"
	case FailTimeNotAvailable:
		return "timeNotAvailable"
	case FailUnacceptedPolicy:
		return "unacceptedPolicy"
	case FailUnacceptedExtension:
		return "unacceptedExtension"
	case FailSystemFailure:
		return "systemFailure"
	default:
		return fmt.Sprintf("failInfo(%d)", int(f))
	}
}

// RequestError is a request the TSA refuses, with the failure bit it answers
// with and a reason for the log.
type RequestError struct {
	Fail   FailureInfo
	Reason string
}

func (e *RequestError) Error() string {
	return fmt.Sprintf("tsa: %s: %s", e.Fail, e.Reason)
}

func refuse(f FailureInfo, format string, args ...any) *RequestError {
	return &RequestError{Fail: f, Reason: fmt.Sprintf(format, args...)}
}

// Request is a parsed TimeStampReq (RFC 3161 section 2.4.1).
type Request struct {
	// Hash is the message imprint's algorithm: SHA-256, SHA-384 or SHA-512.
	Hash crypto.Hash
	// HashedMessage is the message imprint's hash value.
	HashedMessage []byte
	// ReqPolicy is the policy the requester asks for, or nil.
	ReqPolicy asn1.ObjectIdentifier
	// Nonce is the requester's nonce, or nil when it sent none.
	Nonce *big.Int
	// CertReq asks for the TSA certificate in the token.
	CertReq bool

	// rawImprint is the MessageImprint exactly as received; the token
	// echoes it unchanged.
	rawImprint []byte
}

type rawTimeStampReq struct {
	Version        int
	MessageImprint asn1.RawValue
	ReqPolicy      asn1.ObjectIdentifier `asn1:"optional"`
	Nonce          *big.Int              `asn1:"optional"`
	CertReq        bool                  `asn1:"optional,default:false"`
	Extensions     rawTagged             `asn1:"optional,tag:0"`
}

// rawTagged holds an optional implicitly tagged field. A bare RawValue would
// not have its tag checked by encoding/asn1 and would swallow any element.
type rawTagged struct {
	Raw asn1.RawContent
}

type rawMessageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

// imprintHashes are the accepted message imprint algorithms. SHA-1, MD5 and
// everything else are refused with badAlg.
var imprintHashes = []struct {
	oid  asn1.ObjectIdentifier
	hash crypto.Hash
}{
	{asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}, crypto.SHA256},
	{asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}, crypto.SHA384},
	{asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}, crypto.SHA512},
}

// ParseRequest parses a DER TimeStampReq. A request the TSA refuses comes
// back as a *RequestError naming the failure bit to answer with.
func ParseRequest(der []byte) (*Request, error) {
	var raw rawTimeStampReq
	rest, err := asn1.Unmarshal(der, &raw)
	if err != nil {
		return nil, refuse(FailBadDataFormat, "the request is not a DER TimeStampReq: %v", err)
	}
	if len(rest) != 0 {
		return nil, refuse(FailBadDataFormat, "%d trailing bytes after the TimeStampReq", len(rest))
	}
	if raw.Version != 1 {
		return nil, refuse(FailBadDataFormat, "version %d, want 1", raw.Version)
	}
	if raw.Extensions.Raw != nil {
		// Section 2.4.1: an extension the server does not recognize,
		// critical or not, gets unacceptedExtension. This TSA recognizes
		// none.
		return nil, refuse(FailUnacceptedExtension, "the request carries extensions and this TSA supports none")
	}

	var mi rawMessageImprint
	rest, err = asn1.Unmarshal(raw.MessageImprint.FullBytes, &mi)
	if err != nil || len(rest) != 0 {
		return nil, refuse(FailBadDataFormat, "the messageImprint is not a MessageImprint")
	}
	var h crypto.Hash
	for _, ih := range imprintHashes {
		if ih.oid.Equal(mi.HashAlgorithm.Algorithm) {
			h = ih.hash
			break
		}
	}
	if h == 0 {
		return nil, refuse(FailBadAlg, "message imprint algorithm %s is not accepted (SHA-256, SHA-384 or SHA-512)", mi.HashAlgorithm.Algorithm)
	}
	// RFC 5754 section 2: the parameters are absent, though NULL is
	// accepted as many encoders write it.
	if p := mi.HashAlgorithm.Parameters.FullBytes; len(p) != 0 && !bytes.Equal(p, asn1.NullBytes) {
		return nil, refuse(FailBadAlg, "message imprint algorithm %s carries parameters", mi.HashAlgorithm.Algorithm)
	}
	if len(mi.HashedMessage) != h.Size() {
		return nil, refuse(FailBadDataFormat, "the %s message imprint is %d bytes, want %d", h, len(mi.HashedMessage), h.Size())
	}

	return &Request{
		Hash:          h,
		HashedMessage: mi.HashedMessage,
		ReqPolicy:     raw.ReqPolicy,
		Nonce:         raw.Nonce,
		CertReq:       raw.CertReq,
		rawImprint:    raw.MessageImprint.FullBytes,
	}, nil
}
