package timesync

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
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"slices"
	"time"
)

// Wire constants from RFC 5905 (NTPv4) and RFC 4330 (SNTPv4).
const (
	// PacketLen is the NTP header without extension fields or a MAC.
	PacketLen = 48
	// Port is the NTP server port.
	Port = 123

	ModeClient = 3
	ModeServer = 4

	version = 4
	// leapUnsynchronized is LI=3: the server's clock is not synchronised.
	leapUnsynchronized = 3
	// maxStratum is the highest usable stratum; 16 means unsynchronised.
	maxStratum = 15
	// MaxRootDistance is NTP's MAXDIST: a server whose root distance exceeds
	// it is too far from a reference clock to trust.
	MaxRootDistance = time.Second
	// AgreementWindow is the widest spread of offsets from different servers
	// in one round that still counts as agreement.
	AgreementWindow = time.Second
)

// eraSeconds is one NTP era: the 32-bit seconds field wraps every 2^32 s.
const eraSeconds = int64(1) << 32

// ntpToUnix is the number of seconds from the NTP prime epoch (1900-01-01) to
// the Unix epoch (1970-01-01).
const ntpToUnix = int64(2208988800)

// Timestamp is the 64-bit NTP timestamp format: 32 bits of seconds since the
// start of the era and 32 bits of fraction (RFC 5905 section 6).
type Timestamp uint64

// TimestampFromTime encodes t, dropping the era, as RFC 5905 does on the wire.
func TimestampFromTime(t time.Time) Timestamp {
	secs := t.Unix() + ntpToUnix
	frac := (uint64(t.Nanosecond()) << 32) / uint64(time.Second) //nolint:gosec // G115: Nanosecond is 0 to 999999999
	return Timestamp(uint64(uint32(secs))<<32 | frac)            //nolint:gosec // G115: the era is dropped on purpose: RFC 5905 carries seconds modulo 2^32
}

// Time decodes ts into the era nearest pivot. The wire format carries no era,
// so a client that assumed era 0 would jump back 136 years on 2036-02-07; the
// nearest-era rule is correct whenever the pivot is within 68 years of the
// true time, which the clock floor guarantees.
func (ts Timestamp) Time(pivot time.Time) time.Time {
	p := pivot.Unix() + ntpToUnix
	secs := int64(uint64(ts) >> 32)
	era := p >> 32
	best := era*eraSeconds + secs
	for _, c := range []int64{best - eraSeconds, best + eraSeconds} {
		if abs64(c-p) < abs64(best-p) {
			best = c
		}
	}
	hi, lo := bits.Mul64(uint64(uint32(ts)), uint64(time.Second)) //nolint:gosec // G115: the low 32 bits are the fraction field of an NTP timestamp, taken on purpose
	nsec := int64(hi<<32 | lo>>32)                                //nolint:gosec // G115: the product of a 32-bit fraction and 1e9, shifted right by 32, is below 1e9
	return time.Unix(best-ntpToUnix, nsec).UTC()
}

// Short is the 32-bit NTP short format: 16 bits of seconds and 16 bits of
// fraction, used for root delay and root dispersion.
type Short uint32

// Duration converts s to a time.Duration.
func (s Short) Duration() time.Duration {
	return time.Duration((uint64(s) * uint64(time.Second)) >> 16)
}

// Header is the fixed 48-octet NTP packet header (RFC 5905 figure 8).
type Header struct {
	Leap           uint8
	Version        uint8
	Mode           uint8
	Stratum        uint8
	Poll           int8
	Precision      int8
	RootDelay      Short
	RootDispersion Short
	ReferenceID    [4]byte
	Reference      Timestamp
	Origin         Timestamp
	Receive        Timestamp
	Transmit       Timestamp
}

// NewRequest builds a client request. Every field but Transmit Timestamp is
// zero (RFC 4330 section 5). The transmit field carries nonce, a random value
// rather than the send time: the server echoes it as Origin, which lets the
// client drop replies that do not answer this request, and keeps the local
// clock off the wire. The real send time is kept by the caller.
func NewRequest(nonce Timestamp) Header {
	return Header{Version: version, Mode: ModeClient, Transmit: nonce}
}

// Marshal encodes h as a 48-octet packet.
func (h Header) Marshal() []byte {
	b := make([]byte, PacketLen)
	b[0] = h.Leap<<6 | (h.Version&0x7)<<3 | h.Mode&0x7
	b[1] = h.Stratum
	b[2] = byte(h.Poll)      //nolint:gosec // G115: Poll is a signed exponent; the wire byte holds its two's complement bits (RFC 5905)
	b[3] = byte(h.Precision) //nolint:gosec // G115: Precision is a signed exponent; the wire byte holds its two's complement bits (RFC 5905)
	binary.BigEndian.PutUint32(b[4:], uint32(h.RootDelay))
	binary.BigEndian.PutUint32(b[8:], uint32(h.RootDispersion))
	copy(b[12:16], h.ReferenceID[:])
	binary.BigEndian.PutUint64(b[16:], uint64(h.Reference))
	binary.BigEndian.PutUint64(b[24:], uint64(h.Origin))
	binary.BigEndian.PutUint64(b[32:], uint64(h.Receive))
	binary.BigEndian.PutUint64(b[40:], uint64(h.Transmit))
	return b
}

// ParseHeader decodes the header from b. Anything after the first 48 octets
// (extension fields, a MAC) is ignored, as RFC 4330 allows a client to do.
func ParseHeader(b []byte) (Header, error) {
	if len(b) < PacketLen {
		return Header{}, fmt.Errorf("timesync: short packet: %d octets, want at least %d", len(b), PacketLen)
	}
	var h Header
	h.Leap = b[0] >> 6
	h.Version = (b[0] >> 3) & 0x7
	h.Mode = b[0] & 0x7
	h.Stratum = b[1]
	h.Poll = int8(b[2])      //nolint:gosec // G115: Poll is a signed exponent; reinterpret the wire byte (RFC 5905)
	h.Precision = int8(b[3]) //nolint:gosec // G115: Precision is a signed exponent; reinterpret the wire byte (RFC 5905)
	h.RootDelay = Short(binary.BigEndian.Uint32(b[4:]))
	h.RootDispersion = Short(binary.BigEndian.Uint32(b[8:]))
	copy(h.ReferenceID[:], b[12:16])
	h.Reference = Timestamp(binary.BigEndian.Uint64(b[16:]))
	h.Origin = Timestamp(binary.BigEndian.Uint64(b[24:]))
	h.Receive = Timestamp(binary.BigEndian.Uint64(b[32:]))
	h.Transmit = Timestamp(binary.BigEndian.Uint64(b[40:]))
	return h, nil
}

// Kiss-o'-Death codes the client must act on (RFC 5905 section 7.4).
const (
	KissDeny = "DENY"
	KissRstr = "RSTR"
	KissRate = "RATE"
)

// KissError is a Kiss-o'-Death reply: stratum 0 with a four-character code
// in the Reference ID.
type KissError struct {
	Code string
}

func (e *KissError) Error() string {
	return fmt.Sprintf("timesync: kiss-o'-death %q", e.Code)
}

// ValidateReply applies the RFC 4330 section 5 and RFC 5905 checks to a reply
// to the request that carried nonce. A reply that fails any of them must not
// be used to set the clock.
func ValidateReply(h Header, nonce Timestamp) error {
	if h.Mode != ModeServer {
		return fmt.Errorf("timesync: reply mode %d, want %d (server)", h.Mode, ModeServer)
	}
	// RFC 4330 section 5: a server may answer an NTPv4 request as NTPv3.
	if h.Version != 3 && h.Version != 4 {
		return fmt.Errorf("timesync: reply version %d, want 3 or 4", h.Version)
	}
	if h.Origin != nonce {
		return errors.New("timesync: reply origin timestamp does not match the request (bogus or replayed reply)")
	}
	// A kiss is checked before the leap indicator because a kiss carries LI=3
	// too, and the code decides what the client must do next.
	if h.Stratum == 0 {
		return &KissError{Code: kissCode(h.ReferenceID)}
	}
	if h.Transmit == 0 {
		return errors.New("timesync: reply transmit timestamp is zero")
	}
	if h.Leap == leapUnsynchronized {
		return errors.New("timesync: server clock is not synchronised (leap indicator 3)")
	}
	if h.Stratum > maxStratum {
		return fmt.Errorf("timesync: server stratum %d is unsynchronised", h.Stratum)
	}
	if d := RootDistance(h); d > MaxRootDistance {
		return fmt.Errorf("timesync: server root distance %v exceeds %v", d, MaxRootDistance)
	}
	return nil
}

// RootDistance is half the root delay plus the root dispersion: how far the
// server may be from its reference clock (RFC 5905 section 11.2.1, without
// the terms a stateless client cannot know).
func RootDistance(h Header) time.Duration {
	return h.RootDelay.Duration()/2 + h.RootDispersion.Duration()
}

func kissCode(id [4]byte) string {
	n := len(id)
	for n > 0 && id[n-1] == 0 {
		n--
	}
	return string(id[:n])
}

// Compute returns the clock offset and round-trip delay for one exchange
// (RFC 5905 section 8): t1 is the local send time, t4 the local receive time,
// and the reply's Receive and Transmit are the server's t2 and t3, decoded
// into the era nearest pivot. The offset is the server's time minus ours.
func Compute(t1, t4 time.Time, h Header, pivot time.Time) (offset, delay time.Duration, err error) {
	t2 := h.Receive.Time(pivot)
	t3 := h.Transmit.Time(pivot)
	offset = (t2.Sub(t1) + t3.Sub(t4)) / 2
	delay = t4.Sub(t1) - t3.Sub(t2)
	if delay < 0 {
		return 0, 0, fmt.Errorf("timesync: negative round-trip delay %v", delay)
	}
	return offset, delay, nil
}

// Sample is one usable reply.
type Sample struct {
	// Server is the server as queried: the hostname or the IPv4 literal.
	Server       string
	Addr         string
	Offset       time.Duration
	Delay        time.Duration
	Stratum      uint8
	RootDistance time.Duration
}

// ErrDisagree reports that the servers answering one round disagree by more
// than AgreementWindow, so none of them is trusted.
var ErrDisagree = errors.New("timesync: sources disagree")

// Combine picks the offset to apply from one round of samples: the median.
// With an even count it is the mean of the middle two, reported against the
// lower of them. If two or more servers answered and their offsets spread
// wider than AgreementWindow the round is refused: this is the cheap defence
// against one bad or spoofed source, in place of NTP's selection algorithms.
func Combine(samples []Sample) (Sample, error) {
	if len(samples) == 0 {
		return Sample{}, errors.New("timesync: no usable replies")
	}
	s := slices.Clone(samples)
	slices.SortStableFunc(s, func(a, b Sample) int {
		switch {
		case a.Offset < b.Offset:
			return -1
		case a.Offset > b.Offset:
			return 1
		}
		return 0
	})
	if spread := s[len(s)-1].Offset - s[0].Offset; spread > AgreementWindow {
		return Sample{}, fmt.Errorf("%w: offsets spread %v across %d servers (more than %v)", ErrDisagree, spread, len(s), AgreementWindow)
	}
	n := len(s)
	if n%2 == 1 {
		return s[n/2], nil
	}
	lo, hi := s[n/2-1], s[n/2]
	out := lo
	out.Offset = lo.Offset + (hi.Offset-lo.Offset)/2
	return out, nil
}

func abs64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}
