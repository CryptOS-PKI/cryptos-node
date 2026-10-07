// Package tsa is the node's RFC 3161 time-stamp authority: the TSA
// certificate and key it signs tokens with, and the responder that turns a
// TimeStampReq into a TimeStampResp.
//
// # Tokens
//
// Responder accepts version 1 requests with a SHA-256, SHA-384 or SHA-512
// message imprint; SHA-1, MD5 and anything else get badAlg. A request for a
// policy other than the configured one gets unacceptedPolicy, and a request
// with extensions gets unacceptedExtension, since none is supported. A
// granted token echoes the message imprint and the nonce, names the
// configured policy, carries a random 159-bit serial number, a genTime in
// UTC to the millisecond and the configured accuracy, and claims no ordering.
// It is a SignedData built by internal/cms, signed by the TSA key with the
// digest the node pairs with that key (SHA-384 for P-384 and RSA 3072 or
// larger), with a signing-certificate-v2 attribute (RFC 5816) naming the TSA
// certificate by SHA-256 hash, issuer and serial number. The TSA certificate
// is carried only when the request asks for it (certReq).
//
// # Listener
//
// The handler answers POST requests of type application/timestamp-query on
// the root path with application/timestamp-reply, in plain HTTP (RFC 3161
// section 3.4). A client outside the allowed networks gets 403, and one over
// its rate limit (a token bucket per IPv4 address or IPv6 /64) gets 429 with
// Retry-After, both before the request is read. While the clock is not
// trustworthy every request is refused with timeNotAvailable, the
// statusString names the limit that was exceeded and its value, and the full
// reason is logged. ClockGate trusts the clock for a grace window after the
// last good time sync, so a single failed poll does not stop the TSA: it
// refuses before the first good sync of the boot, after a round the servers
// answered but that was not applied (adjustment_refused), once the last good
// sync is older than ClockLimits.MaxSyncAge, and once the estimated clock
// error (EstimatedClockError: the offset at the last good sync plus
// MaxDriftPPM of the time since) is above MaxClockError, which is never
// larger than the accuracy tokens claim.
//
// # Keys and certificates
//
// The CA key never signs a token. Tokens are signed by a separate TSA
// certificate the node issues from its own CA: an end-entity certificate with
// key usage digitalSignature and exactly one extended key usage,
// id-kp-timeStamping, marked critical as RFC 3161 section 2.3 requires. The
// TSA key has the CA key's algorithm and is created through the same key
// backend as the CA key, so it lives in the TPM where the node has one and in
// software otherwise. Its blobs (TPM-wrapped, or PKCS#8/SEC1 in software)
// are stored in the node's etcd on the encrypted state partition, and the key
// is loaded for each signature and released straight after.
//
// CertManager keeps the certificates. It issues the first one, issues a
// successor with a new key when the current one enters its rotation overlap,
// is revoked, or no longer chains to the CA certificate, and from then on
// signs with the successor. Every certificate the node has signed with stays
// published (Store.Published) after it is replaced or expires, so a token
// signed before a rotation still verifies; only the key of a replaced
// certificate is deleted, because nothing signs with it again.
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
