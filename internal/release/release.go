// Package release carries the certificate whose key a CryptOS image must be
// signed by to be installed on a node (#208).
//
// The certificate is fixed by the image itself rather than read from
// configuration or from disk. Configuration is writable by the same
// administrator who would be installing an image, so trusting it would make
// the check circular: a caller who could set the anchor could authorise their
// own image. Fixing it in the image means the anchor for the next image is
// set by whoever built or signed the one now running.
//
// # Where the anchor comes from
//
// There are two places, and a sign-time anchor wins over a build-time one:
//
//  1. The sign-time anchor. `cryptosctl image sign` appends a small
//     uncompressed cpio archive holding /upgrade-anchor.der (the signing
//     certificate, DER) to the UKI's .initrd before it Authenticode-signs the
//     image. The .initrd is measured into PCR 11 and covered by the
//     Authenticode signature, so the anchor cannot change without the image
//     changing. cryptos-switchroot, the /init of the initramfs, reads the
//     file and hands it to the real init in the CRYPTOS_UPGRADE_ANCHOR
//     environment variable (base64 of the DER), after dropping any inherited
//     value: the kernel turns command-line key=value words into init's
//     environment, and the command line is not trusted.
//  2. The build-time anchor, CertificateDER, an -X ldflag stamped in by the
//     image build (SB_CERT, see cryptos-appliance's build/squashfs/build.sh).
//
// The sign-time anchor wins because the signing step is the last word on whose
// image this is. Either way it is the certificate enrolled in the machine's
// Secure Boot db and whose key signed the UKI, which keeps one release anchor
// instead of two, and keeps builds apart for free: a CI build signed with a
// per-run ephemeral key cannot be staged onto an operator's nodes by accident.
//
// The project publishes no certificate. Tagged release assets are built
// unsigned and carry neither anchor, so a node installed from one as-is serves
// the upgrade RPCs as Unimplemented. Signing the asset with `cryptosctl image
// sign` before installing it gives the node a sign-time anchor, and from then
// on it takes in-place upgrades signed by the same key.
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
	"os"
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

// EnvAnchor is the environment variable cryptos-switchroot passes the
// sign-time anchor to init in: base64 (standard encoding) of the certificate
// DER, the same form as CertificateDER.
const EnvAnchor = "CRYPTOS_UPGRADE_ANCHOR"

// ErrNoCertificate reports that this image carries no release certificate,
// neither signed in nor built in, which is the normal state of a development
// build.
//
// It is a distinct condition rather than a parse error on purpose: the node
// turns the image upgrade RPCs off when it sees this, and an operator reading
// "Unimplemented" should not have to wonder whether the build is broken.
var ErrNoCertificate = errors.New("release: this build carries no release certificate")

// Certificate returns the release certificate this image carries: the
// sign-time anchor from EnvAnchor when it is set, otherwise the build-time
// CertificateDER. It is read once, at the first call, which init makes at
// startup.
//
// Validity dates are deliberately not enforced. The certificate is used to
// attribute an image, not to authenticate a live peer, and an expired one
// would block precisely the upgrade an operator needs to replace it -- on the
// node's only management surface, where there is no other way in.
var Certificate = sync.OnceValues(func() (*x509.Certificate, error) {
	return resolve(os.Getenv(EnvAnchor), CertificateDER)
})

// resolve picks the anchor: signTime when it is non-empty, buildTime
// otherwise. A sign-time anchor that does not parse is an error, never a
// reason to fall back to the build-time one: the image was signed to carry
// it, and quietly trusting a different key would hide that.
func resolve(signTime, buildTime string) (*x509.Certificate, error) {
	if strings.TrimSpace(signTime) == "" {
		return parse(buildTime)
	}
	cert, err := parse(signTime)
	if err != nil {
		return nil, fmt.Errorf("release: the sign-time anchor in %s: %w", EnvAnchor, err)
	}

	return cert, nil
}

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
