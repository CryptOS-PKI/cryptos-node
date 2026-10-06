// Package release carries the certificate whose key a CryptOS image must be
// signed by to be installed on a node (#208).
//
// The certificate is stamped into the binary at build time rather than read
// from configuration or from disk. Configuration is writable by the same
// administrator who would be installing an image, so trusting it would make
// the check circular: a caller who could set the anchor could authorise their
// own image. Building it in means the anchor for the next image is fixed by
// whoever built the one now running.
//
// This is the same certificate that is enrolled in the machine's Secure Boot
// db and whose key sbsign uses on the UKI, supplied by whoever builds the
// image (SB_CERT, see cryptos-appliance's build/squashfs/build.sh). Reusing it
// keeps one release anchor instead of two, and it keeps builds apart for
// free: a CI build signed with the per-run ephemeral key is not signed by an
// operator's certificate, so it cannot be staged onto that operator's nodes
// by accident.
//
// The project publishes no certificate. Tagged release assets are built
// unsigned and with CertificateDER empty, so a node installed from one serves
// the upgrade RPCs as Unimplemented; moving it onto an operator's key means
// reinstalling it from an image built with that key.
package release

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
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
)

// CertificateDER is the release certificate, base64 (standard encoding) of its
// DER, stamped in at link time:
//
//	go build -ldflags "-X github.com/CryptOS-PKI/cryptos-node/internal/release.CertificateDER=$(base64 -w0 < release.der)"
//
// A link-time variable rather than an embedded file so a signed build needs no
// edit to a tracked file, the same way STATEKEY already selects the key mode
// (see cryptos-appliance's build/squashfs/build.sh). It is empty in a
// development build.
var CertificateDER string

// ErrNoCertificate reports that this build carries no release certificate,
// which is the normal state of a development build.
//
// It is a distinct condition rather than a parse error on purpose: the node
// turns the image upgrade RPCs off when it sees this, and an operator reading
// "Unimplemented" should not have to wonder whether the build is broken.
var ErrNoCertificate = errors.New("release: this build carries no release certificate")

// Certificate returns the release certificate this image was built with.
//
// Validity dates are deliberately not enforced. The certificate is used to
// attribute an image, not to authenticate a live peer, and an expired one
// would block precisely the upgrade an operator needs to replace it -- on the
// node's only management surface, where there is no other way in.
var Certificate = sync.OnceValues(func() (*x509.Certificate, error) {
	return parse(CertificateDER)
})

func parse(b64 string) (*x509.Certificate, error) {
	b64 = strings.TrimSpace(b64)
	if b64 == "" {
		return nil, ErrNoCertificate
	}

	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("release: decode the release certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("release: parse the release certificate: %w", err)
	}
	// Detached release signatures are RSA PKCS#1 v1.5, the scheme UEFI itself
	// specifies for image authentication. Catching the wrong key type here
	// turns a build mistake into a build failure instead of a surprise at the
	// first upgrade attempt on a node.
	if _, ok := cert.PublicKey.(*rsa.PublicKey); !ok {
		return nil, fmt.Errorf("release: the release certificate holds a %T key, want RSA", cert.PublicKey)
	}

	return cert, nil
}
