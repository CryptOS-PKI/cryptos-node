package config

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
	"encoding/asn1"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
)

// TSA configures the node's RFC 3161 time-stamp authority (pki.tsa). Nil is
// off, the default. It follows the protocol-block rules in protocols.go: an
// explicit enabled flag, a Root refuses it, and every change takes effect at
// the next boot.
type TSA struct {
	// HTTPPort is the TCP port the TSA listener binds. Zero means the node
	// default.
	HTTPPort uint32 `yaml:"http_port"`
	// PolicyOID is the TSA policy every token names, in dotted form. Required:
	// there is no default, so no two deployments share one by accident.
	PolicyOID string `yaml:"policy_oid"`
	// AccuracyMS is the accuracy every token claims, in milliseconds either
	// side of genTime. Zero means 1000; at most 60000.
	AccuracyMS uint32 `yaml:"accuracy_ms"`
	// RateLimit bounds how often one client may ask for a token.
	RateLimit TSARateLimit `yaml:"rate_limit"`
	// AllowedNetworks, when non-empty, are the only client networks
	// answered: CIDR prefixes, or bare addresses for one host.
	AllowedNetworks []string `yaml:"allowed_networks"`
	// Certificate tunes the TSA certificate's lifetime and rotation.
	Certificate TSACertificate `yaml:"certificate"`
}

// TSARateLimit is a per-client token bucket.
type TSARateLimit struct {
	// RequestsPerMinute is the steady rate. Zero means 60.
	RequestsPerMinute uint32 `yaml:"requests_per_minute"`
	// Burst is how many requests a client may make at once. Zero means
	// RequestsPerMinute.
	Burst uint32 `yaml:"burst"`
}

// TSACertificate tunes the TSA certificate.
type TSACertificate struct {
	// ValidityDays is the certificate lifetime. Zero means 365, which is
	// also the most.
	ValidityDays uint32 `yaml:"validity_days"`
	// RotationOverlapDays is how long before expiry the successor takes
	// over. Zero means 30.
	RotationOverlapDays uint32 `yaml:"rotation_overlap_days"`
}

const (
	tsaDefaultAccuracyMS  = 1000
	tsaMaxAccuracyMS      = 60000
	tsaDefaultRate        = 60
	tsaDefaultValidity    = 365
	tsaMaxValidity        = 365
	tsaDefaultOverlap     = 30
	tsaPolicyField        = "config: pki.tsa.policy_oid"
	tsaAllowedNetworksFld = "config: pki.tsa.allowed_networks"
)

// Accuracy is the effective claimed accuracy.
func (s *TSA) Accuracy() time.Duration {
	ms := s.AccuracyMS
	if ms == 0 {
		ms = tsaDefaultAccuracyMS
	}
	return time.Duration(ms) * time.Millisecond
}

// RequestsPerMinute is the effective steady rate per client.
func (s *TSA) RequestsPerMinute() int {
	if s.RateLimit.RequestsPerMinute == 0 {
		return tsaDefaultRate
	}
	return int(s.RateLimit.RequestsPerMinute)
}

// Burst is the effective burst per client.
func (s *TSA) Burst() int {
	if s.RateLimit.Burst == 0 {
		return s.RequestsPerMinute()
	}
	return int(s.RateLimit.Burst)
}

// Validity is the effective TSA certificate lifetime.
func (c TSACertificate) Validity() time.Duration {
	d := c.ValidityDays
	if d == 0 {
		d = tsaDefaultValidity
	}
	return time.Duration(d) * 24 * time.Hour
}

// Overlap is the effective rotation overlap.
func (c TSACertificate) Overlap() time.Duration {
	d := c.RotationOverlapDays
	if d == 0 {
		d = tsaDefaultOverlap
	}
	return time.Duration(d) * 24 * time.Hour
}

// Policy is the parsed policy OID.
func (s *TSA) Policy() (asn1.ObjectIdentifier, error) {
	return parsePolicyOID(s.PolicyOID)
}

// Networks are the parsed allowed networks; a bare address is a one-host
// prefix.
func (s *TSA) Networks() ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(s.AllowedNetworks))
	for i, n := range s.AllowedNetworks {
		p, err := parseNetwork(n)
		if err != nil {
			return nil, fmt.Errorf("%s[%d]: %w", tsaAllowedNetworksFld, i, err)
		}
		out = append(out, p)
	}
	return out, nil
}

func parseNetwork(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("%q is not a CIDR prefix", s)
		}
		return p, nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("%q is not an IPv4 or IPv6 address or prefix", s)
	}
	return netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()), nil
}

// parsePolicyOID parses a dotted object identifier under the rules of
// X.660: at least two arcs, each decimal with no leading zeros, a first arc
// of 0, 1 or 2, and a second arc below 40 when the first is 0 or 1.
func parsePolicyOID(s string) (asn1.ObjectIdentifier, error) {
	if s == "" {
		return nil, errors.New("required")
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("%q has fewer than two arcs", s)
	}
	oid := make(asn1.ObjectIdentifier, len(parts))
	for i, p := range parts {
		if p == "" || strings.Trim(p, "0123456789") != "" || (len(p) > 1 && p[0] == '0') {
			return nil, fmt.Errorf("%q: arc %d (%q) is not a decimal number without leading zeros", s, i+1, p)
		}
		n, err := strconv.ParseInt(p, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("%q: arc %d is too large", s, i+1)
		}
		oid[i] = int(n)
	}
	if oid[0] > 2 {
		return nil, fmt.Errorf("%q: the first arc must be 0, 1 or 2", s)
	}
	if oid[0] < 2 && oid[1] >= 40 {
		return nil, fmt.Errorf("%q: the second arc must be below 40 under %d", s, oid[0])
	}
	return oid, nil
}

// validateTSA enforces the pki.tsa rules on an enabled block. A nil block is
// off and passes; a Root is refused in validateProtocolRole.
func validateTSA(s *TSA) error {
	if s == nil {
		return nil
	}
	if s.HTTPPort > maxTCPPort {
		return fmt.Errorf("config: pki.tsa.http_port: %d is not a TCP port", s.HTTPPort)
	}
	if _, err := s.Policy(); err != nil {
		return fmt.Errorf("%s: %w; the TSA stays off until you set your own policy, for example an arc under "+
			"your IANA Private Enterprise Number (1.3.6.1.4.1.<PEN>.<arc>)", tsaPolicyField, err)
	}
	if s.AccuracyMS > tsaMaxAccuracyMS {
		return fmt.Errorf("config: pki.tsa.accuracy_ms: %d is more than the %d maximum", s.AccuracyMS, tsaMaxAccuracyMS)
	}
	if _, err := s.Networks(); err != nil {
		return err
	}
	if s.Certificate.ValidityDays > tsaMaxValidity {
		return fmt.Errorf("config: pki.tsa.certificate.validity_days: %d is more than the %d-day maximum",
			s.Certificate.ValidityDays, tsaMaxValidity)
	}
	if s.Certificate.Overlap() >= s.Certificate.Validity() {
		return fmt.Errorf("config: pki.tsa.certificate.rotation_overlap_days: the overlap (%s) must be shorter than the certificate validity (%s)",
			s.Certificate.Overlap(), s.Certificate.Validity())
	}
	return nil
}

// tsaToProto renders the TSA block: on's settings with enabled=true, else
// off's with enabled=false.
func tsaToProto(on, off *TSA) *nodev1.Tsa {
	s := firstNonNil(on, off)
	if s == nil {
		return &nodev1.Tsa{Enabled: false}
	}
	pb := &nodev1.Tsa{
		Enabled:         on != nil,
		HttpPort:        s.HTTPPort,
		PolicyOid:       s.PolicyOID,
		AccuracyMs:      s.AccuracyMS,
		AllowedNetworks: s.AllowedNetworks,
	}
	if s.RateLimit != (TSARateLimit{}) {
		pb.RateLimit = &nodev1.TsaRateLimit{RequestsPerMinute: s.RateLimit.RequestsPerMinute, Burst: s.RateLimit.Burst}
	}
	if s.Certificate != (TSACertificate{}) {
		pb.Certificate = &nodev1.TsaCertificateSettings{
			ValidityDays:        s.Certificate.ValidityDays,
			RotationOverlapDays: s.Certificate.RotationOverlapDays,
		}
	}
	return pb
}

// tsaFromProto returns the block as on (enabled=true) or off settings
// (enabled=false); a missing or empty off block is neither.
func tsaFromProto(pb *nodev1.Tsa) (on, off *TSA) {
	if pb == nil {
		return nil, nil
	}
	s := &TSA{
		HTTPPort:        pb.GetHttpPort(),
		PolicyOID:       pb.GetPolicyOid(),
		AccuracyMS:      pb.GetAccuracyMs(),
		AllowedNetworks: pb.GetAllowedNetworks(),
		RateLimit: TSARateLimit{
			RequestsPerMinute: pb.GetRateLimit().GetRequestsPerMinute(),
			Burst:             pb.GetRateLimit().GetBurst(),
		},
		Certificate: TSACertificate{
			ValidityDays:        pb.GetCertificate().GetValidityDays(),
			RotationOverlapDays: pb.GetCertificate().GetRotationOverlapDays(),
		},
	}
	if pb.GetEnabled() {
		return s, nil
	}
	return nil, offBlock(s)
}
