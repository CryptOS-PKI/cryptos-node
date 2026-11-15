package grpc

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
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strconv"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// AttestationContext is the fixed, versioned label every Attest signature is
// bound to. See AttestationMessage.
const AttestationContext = "CryptOS-PKI attestation v1"

// AttestationMessage returns the exact bytes an Attest signature covers:
//
//	AttestationContext || 0x00 || uint32 big-endian len(nonce) || nonce
//
// The node signs SHA-384 of this message, never SHA-384 of the nonce alone.
// The message starts with the ASCII 'C' (0x43), not the DER SEQUENCE tag
// (0x30) that opens every TBSCertificate, TBSCertList, OCSP ResponseData and
// CertificationRequestInfo, so no caller-chosen nonce can turn an Attest
// signature into a valid CA signature over one of those structures. The
// length prefix keeps the nonce boundary unambiguous if the label ever gains
// a successor version. A verifier rebuilds the message from the nonce it sent.
func AttestationMessage(nonce []byte) []byte {
	msg := make([]byte, 0, len(AttestationContext)+1+4+len(nonce))
	msg = append(msg, AttestationContext...)
	msg = append(msg, 0x00)
	msg = binary.BigEndian.AppendUint32(msg, uint32(len(nonce))) //nolint:gosec // G115: a nonce is a few dozen bytes; gRPC caps a message far below 4 GiB
	return append(msg, nonce...)
}

// Attest handles cryptos.node.v1.NodeService/Attest: the Fleet Manager sends a
// random challenge nonce and the node signs AttestationMessage(nonce) with its
// CA identity key, returning the signature plus the identity public key so the
// manager can verify possession of the private key it pinned during
// enrollment. The maintenance servers leave Attester nil, so the RPC returns
// Unimplemented there. On a running node the caller is authorized against the
// bootstrap admin trust before the CA key is touched. The audit entry names
// the attestation context and identifies the nonce by length and SHA-256. This
// handler is thin: the signing lives in the attester.
func (s *Server) Attest(ctx context.Context, req *nodev1.AttestRequest) (*nodev1.AttestResponse, error) {
	if s.cfg.Attester == nil {
		return nil, status.Error(codes.Unimplemented, "attestation not available in maintenance mode")
	}
	if err := AuthorizeAdmin(ctx, s.cfg.Trust); err != nil {
		return nil, err
	}
	if len(req.GetNonce()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "Attest: nonce is required")
	}
	nonceSum := sha256.Sum256(req.GetNonce())
	setAuditDetail(ctx, "attest_context", AttestationContext)
	setAuditDetail(ctx, "nonce_bytes", strconv.Itoa(len(req.GetNonce())))
	setAuditDetail(ctx, "nonce_sha256", hex.EncodeToString(nonceSum[:]))
	sig, pub, err := s.cfg.Attester.SignNonce(ctx, req.GetNonce())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Attest: %v", err)
	}
	return &nodev1.AttestResponse{Signature: sig, IdentityPubDer: pub}, nil
}
