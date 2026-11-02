// Package keyalg names the CA key algorithms. It sits apart from internal/tpm
// so that internal/config, and through it cryptosctl, can use the vocabulary
// without linking the Linux-only TPM transport.
package keyalg

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

// Algorithm selects the algorithm and parameters for a created signing key.
type Algorithm int

const (
	// ECDSAP384 pairs ECDSA on NIST P-384 with SHA-384.
	ECDSAP384 Algorithm = iota + 1

	// RSA2048, RSA3072 and RSA4096 are RSA CA keys at the named modulus size.
	RSA2048
	RSA3072
	RSA4096
)
