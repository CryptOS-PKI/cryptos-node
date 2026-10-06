// Package tsa is the node's RFC 3161 time-stamp authority: the TSA
// certificate and key it signs tokens with.
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
