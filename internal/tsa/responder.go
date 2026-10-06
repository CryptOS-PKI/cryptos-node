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
	"context"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// TokenSigner hands out the TSA certificate and key for one signature.
// *CertManager implements it.
type TokenSigner interface {
	WithSigner(ctx context.Context, fn func(cert *x509.Certificate, key crypto.Signer) error) error
}

// ResponderOptions configures a Responder.
type ResponderOptions struct {
	// Policy is the TSA policy every token names. Required.
	Policy asn1.ObjectIdentifier
	// Accuracy is the accuracy every token claims, at least a millisecond.
	Accuracy time.Duration
	// Now and Logf default to time.Now and discarding.
	Now  func() time.Time
	Logf func(string, ...any)
}

// Responder answers RFC 3161 requests: it parses a TimeStampReq and returns
// the DER TimeStampResp, granted with a token or rejected with a failure bit.
type Responder struct {
	signer TokenSigner
	opts   ResponderOptions
	serial func() (*big.Int, error)
}

// NewResponder returns a Responder signing through signer.
func NewResponder(signer TokenSigner, opts ResponderOptions) (*Responder, error) {
	if signer == nil {
		return nil, errors.New("tsa: NewResponder: a signer is required")
	}
	if len(opts.Policy) < 2 {
		return nil, errors.New("tsa: NewResponder: a policy OID is required")
	}
	if opts.Accuracy < time.Millisecond {
		return nil, fmt.Errorf("tsa: NewResponder: the accuracy (%s) must be at least a millisecond", opts.Accuracy)
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	return &Responder{signer: signer, opts: opts, serial: newSerial}, nil
}

// Outcome describes how a request was answered, for the caller's log.
type Outcome struct {
	Granted bool
	// Serial is the token's serial number when granted.
	Serial *big.Int
	// Fail and Reason say why a request was rejected.
	Fail   FailureInfo
	Reason string
}

// Respond answers one DER TimeStampReq with a DER TimeStampResp. The reply
// is a TimeStampResp whatever happens; err is set only when not even a
// rejection could be encoded.
func (r *Responder) Respond(ctx context.Context, der []byte) ([]byte, Outcome, error) {
	req, err := ParseRequest(der)
	if err != nil {
		var re *RequestError
		if !errors.As(err, &re) {
			re = refuse(FailBadDataFormat, "%v", err)
		}
		return r.reject(re.Fail, re.Reason)
	}
	if req.ReqPolicy != nil && !req.ReqPolicy.Equal(r.opts.Policy) {
		return r.reject(FailUnacceptedPolicy, fmt.Sprintf("the request asks for policy %s; this TSA serves %s", req.ReqPolicy, r.opts.Policy))
	}

	serial, err := r.serial()
	if err != nil {
		return r.reject(FailSystemFailure, err.Error())
	}
	var token []byte
	err = r.signer.WithSigner(ctx, func(cert *x509.Certificate, key crypto.Signer) error {
		// genTime is read once the key is in hand, as close to the
		// signature as possible.
		info, err := tstInfo(req, tokenParams{policy: r.opts.Policy, accuracy: r.opts.Accuracy, serial: serial, genTime: r.opts.Now()})
		if err != nil {
			return err
		}
		token, err = signToken(info, cert, key, req.CertReq)
		return err
	})
	if err != nil {
		return r.reject(FailSystemFailure, fmt.Sprintf("signing the token failed: %v", err))
	}
	resp, err := grantedResponse(token)
	if err != nil {
		return r.reject(FailSystemFailure, fmt.Sprintf("encoding the response failed: %v", err))
	}
	r.opts.Logf("tsa: granted token %s (%s imprint, nonce=%t, certReq=%t)", serial.Text(16), req.Hash, req.Nonce != nil, req.CertReq)
	return resp, Outcome{Granted: true, Serial: serial}, nil
}

// rejectionText is the statusString a rejection carries: what the failure
// bit means, never internal detail, which goes to the log instead.
var rejectionText = map[FailureInfo]string{
	FailBadAlg:              "unsupported message imprint algorithm; use SHA-256, SHA-384 or SHA-512",
	FailBadRequest:          "request not supported",
	FailBadDataFormat:       "malformed TimeStampReq",
	FailTimeNotAvailable:    "the TSA time source is not available",
	FailUnacceptedPolicy:    "requested policy not served",
	FailUnacceptedExtension: "request extensions are not supported",
	FailSystemFailure:       "system failure",
}

func (r *Responder) reject(fail FailureInfo, reason string) ([]byte, Outcome, error) {
	r.opts.Logf("tsa: rejected with %s: %s", fail, reason)
	resp, err := rejectionResponse(fail, rejectionText[fail])
	return resp, Outcome{Fail: fail, Reason: reason}, err
}
