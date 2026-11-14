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
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
	"testing"
)

// legacyECPublicKey is the construction JWK.PublicKey used before #412:
// the struct literal with the raw coordinates. It stays here as the
// reference the supported conversion has to match.
func legacyECPublicKey(curve elliptic.Curve, point []byte) *ecdsa.PublicKey {
	n := (len(point) - 1) / 2
	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(point[1 : 1+n]), //nolint:staticcheck // SA1019: the legacy reference
		Y:     new(big.Int).SetBytes(point[1+n:]),    //nolint:staticcheck // SA1019: the legacy reference
	}
}

// TestJWKPublicKeyMatchesLegacyConstruction proves, over fixed private
// scalars, that JWK.PublicKey returns the same curve and coordinates the
// raw struct literal produced.
func TestJWKPublicKeyMatchesLegacyConstruction(t *testing.T) {
	curves := []elliptic.Curve{elliptic.P256(), elliptic.P384()}
	scalars := []byte{0x01, 0x02, 0x7f, 0xa5, 0xff}
	for _, curve := range curves {
		size := (curve.Params().BitSize + 7) / 8
		for _, fill := range scalars {
			d := make([]byte, size)
			d[size-1] = fill
			d[size/2] = fill
			priv, err := ecdsa.ParseRawPrivateKey(curve, d)
			if err != nil {
				t.Fatalf("%s scalar %#x: %v", curve.Params().Name, fill, err)
			}
			point, err := priv.PublicKey.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			jwk, err := JWKFromPublic(&priv.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			got, err := jwk.PublicKey()
			if err != nil {
				t.Fatalf("%s scalar %#x: PublicKey: %v", curve.Params().Name, fill, err)
			}
			gotKey, ok := got.(*ecdsa.PublicKey)
			if !ok {
				t.Fatalf("got %T, want *ecdsa.PublicKey", got)
			}
			want := legacyECPublicKey(curve, point)
			if gotKey.Curve != want.Curve || !gotKey.Equal(want) {
				t.Errorf("%s scalar %#x: key differs from the legacy construction", curve.Params().Name, fill)
			}
		}
	}
}
