package cms

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
	"errors"
	"fmt"
)

// maxBERDepth bounds nesting so a hostile message cannot drive the
// normalizer's recursion arbitrarily deep. Real CMS messages, certificates
// included, stay well under twenty levels.
const maxBERDepth = 64

// errBER is the one error the normalizer returns, wrapped with the offset
// detail. The input is attacker-supplied, so the message carries only
// structure, never content bytes.
var errBER = errors.New("cms: malformed BER")

// normalizeBER rewrites a BER encoding as DER where the two differ in ways
// real encoders produce: indefinite lengths become definite, non-minimal
// lengths become minimal, and a constructed OCTET STRING becomes the
// primitive one holding its concatenated chunks.
//
// RFC 5652 lets a sender use BER for everything except the signed
// attributes (section 5.4), and streaming encoders -- OpenSSL with -stream,
// and a number of SCEP clients -- do. encoding/asn1 reads only DER, so
// every parse goes through here first. A DER input comes back
// byte-for-byte unchanged, which matters: the signature over the signed
// attributes is checked against these bytes.
//
// It does not sort SET OF members or canonicalize primitive contents; that
// would change bytes a signature may cover, and nothing here needs it.
func normalizeBER(in []byte) ([]byte, error) {
	out, rest, err := convertBER(in, 0)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("%w: %d trailing bytes", errBER, len(rest))
	}
	return out, nil
}

// convertBER converts the single element at the front of b and returns it
// along with whatever follows.
func convertBER(b []byte, depth int) (out, rest []byte, err error) {
	if depth > maxBERDepth {
		return nil, nil, fmt.Errorf("%w: nested deeper than %d", errBER, maxBERDepth)
	}
	idLen, constructed, tagNumber, class, err := readIdentifier(b)
	if err != nil {
		return nil, nil, err
	}
	id := b[:idLen]
	b = b[idLen:]
	if len(b) == 0 {
		return nil, nil, fmt.Errorf("%w: missing length", errBER)
	}

	var children [][]byte
	var body []byte
	if b[0] == 0x80 {
		if !constructed {
			return nil, nil, fmt.Errorf("%w: indefinite length on a primitive element", errBER)
		}
		b = b[1:]
		for {
			if len(b) >= 2 && b[0] == 0x00 && b[1] == 0x00 {
				b = b[2:]
				break
			}
			if len(b) == 0 {
				return nil, nil, fmt.Errorf("%w: indefinite length without end-of-contents", errBER)
			}
			var child []byte
			child, b, err = convertBER(b, depth+1)
			if err != nil {
				return nil, nil, err
			}
			children = append(children, child)
		}
		rest = b
	} else {
		n, lenLen, err := readDefiniteLength(b)
		if err != nil {
			return nil, nil, err
		}
		b = b[lenLen:]
		if n > len(b) {
			return nil, nil, fmt.Errorf("%w: length %d exceeds the %d bytes remaining", errBER, n, len(b))
		}
		body, rest = b[:n], b[n:]
		if !constructed {
			return encodeElement(id, body), rest, nil
		}
		for len(body) > 0 {
			var child []byte
			child, body, err = convertBER(body, depth+1)
			if err != nil {
				return nil, nil, err
			}
			children = append(children, child)
		}
	}

	if class == 0 && tagNumber == 4 {
		// A constructed OCTET STRING: X.690 section 8.7.3 makes its value
		// the concatenation of its primitive OCTET STRING segments, and DER
		// allows only the primitive form.
		var joined []byte
		for _, c := range children {
			if c[0] != 0x04 {
				return nil, nil, fmt.Errorf("%w: constructed OCTET STRING segment is not an OCTET STRING", errBER)
			}
			_, hdr, err := readDefiniteLength(c[1:])
			if err != nil {
				return nil, nil, err
			}
			joined = append(joined, c[1+hdr:]...)
		}
		return encodeElement([]byte{0x04}, joined), rest, nil
	}

	var joined []byte
	for _, c := range children {
		joined = append(joined, c...)
	}
	return encodeElement(id, joined), rest, nil
}

// readIdentifier parses the identifier octets (X.690 section 8.1.2),
// including the high-tag-number form.
func readIdentifier(b []byte) (n int, constructed bool, tag int, class int, err error) {
	if len(b) == 0 {
		return 0, false, 0, 0, fmt.Errorf("%w: missing identifier", errBER)
	}
	class = int(b[0] >> 6)
	constructed = b[0]&0x20 != 0
	tag = int(b[0] & 0x1f)
	n = 1
	if tag == 0x1f {
		tag = 0
		for {
			if n >= len(b) || n > 4 {
				return 0, false, 0, 0, fmt.Errorf("%w: bad high tag number", errBER)
			}
			c := b[n]
			n++
			tag = tag<<7 | int(c&0x7f)
			if c&0x80 == 0 {
				break
			}
		}
	}
	return n, constructed, tag, class, nil
}

// readDefiniteLength parses a definite length. Four length octets cover any
// message this package will ever be handed; anything longer is refused
// rather than risk an int overflow.
func readDefiniteLength(b []byte) (n int, lenLen int, err error) {
	if len(b) == 0 {
		return 0, 0, fmt.Errorf("%w: missing length", errBER)
	}
	if b[0] < 0x80 {
		return int(b[0]), 1, nil
	}
	count := int(b[0] & 0x7f)
	if count == 0 || count > 4 {
		return 0, 0, fmt.Errorf("%w: unsupported length of %d octets", errBER, count)
	}
	if len(b) < 1+count {
		return 0, 0, fmt.Errorf("%w: truncated length", errBER)
	}
	for _, c := range b[1 : 1+count] {
		n = n<<8 | int(c)
	}
	if n < 0 || n > 1<<30 {
		return 0, 0, fmt.Errorf("%w: length out of range", errBER)
	}
	return n, 1 + count, nil
}

// encodeElement writes identifier octets, a minimal definite length, and the
// contents.
func encodeElement(id, body []byte) []byte {
	out := make([]byte, 0, len(id)+5+len(body))
	out = append(out, id...)
	out = appendLength(out, len(body))
	return append(out, body...)
}

func appendLength(out []byte, n int) []byte {
	if n < 0x80 {
		return append(out, byte(n)) //nolint:gosec // G115: n is below 0x80 on this branch
	}
	var tmp [4]byte
	i := len(tmp)
	for n > 0 {
		i--
		tmp[i] = byte(n)
		n >>= 8
	}
	out = append(out, 0x80|byte(len(tmp)-i))
	return append(out, tmp[i:]...)
}

// tlv builds a DER element with a single-octet identifier.
func tlv(tag byte, parts ...[]byte) []byte {
	var body []byte
	for _, p := range parts {
		body = append(body, p...)
	}
	return encodeElement([]byte{tag}, body)
}
