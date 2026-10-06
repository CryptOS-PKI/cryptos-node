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
	"errors"
	"fmt"
	"reflect"

	"gopkg.in/yaml.v3"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
)

// The enrolment protocol blocks (pki.acme, pki.est, pki.scep, pki.tsa) travel in MachineConfig
// under one set of rules, shared by every protocol that gains a block:
//
//   - In the proto, a block carries an explicit enabled flag. ToProto always
//     sends one, so a whole config is explicit about every protocol, and an off
//     protocol goes out as enabled=false. FromProto turns enabled=false, or a
//     missing block, into a nil ACME or EST, which is how this package spells
//     "off".
//   - An off block keeps its settings. FromProto stores the fields of an
//     enabled=false block in DisabledACME or DisabledEST, and ToProto sends
//     them back with enabled=false, so a reader can switch the protocol back
//     on by flipping enabled alone. An empty enabled=false block stores
//     nothing. In YAML the same block carries enabled: false.
//   - Applied over a stored config (FromProtoOver), a missing block keeps the
//     stored one, on or off. A client that predates a block therefore cannot
//     switch a protocol off by leaving it out.
//   - Secrets are write-only, in an off block too. ToProtoRedacted blanks
//     them for GetConfig, and FromProtoOver fills an empty secret from the
//     stored entry with the same identifier, on or off, so a read, edit, apply
//     cycle keeps them. An empty secret for an identifier the node does not
//     know is refused.
//   - A Root serves no enrolment protocol (Root Mode closes the service-plane
//     listeners), so Validate refuses a Root with either protocol on. An off
//     block is inert and allowed.
//   - Every field of an on block is read at boot, so NeedsReboot classifies
//     any change to one, including the switch itself, as reboot-required. An
//     off block's settings are read by nothing, so changing only them is live.

// validateProtocolRole refuses an enrolment protocol on a Root.
func validateProtocolRole(role RoleKind, p PKI) error {
	if role != RoleRoot {
		return nil
	}
	if p.ACME != nil {
		return errors.New("config: pki.acme: must not be set on a root node; a root serves no " +
			"enrolment protocol, so serve ACME from an intermediate or issuing node")
	}
	if p.EST != nil {
		return errors.New("config: pki.est: must not be set on a root node; a root serves no " +
			"enrolment protocol, so serve EST from an intermediate or issuing node")
	}
	if p.TSA != nil {
		return errors.New("config: pki.tsa: must not be enabled on a root node; Root Mode closes the " +
			"service-plane listeners, so serve the TSA from an intermediate or issuing node")
	}
	return nil
}

// ToProtoRedacted is ToProto with the protocol secrets blanked, for handing a
// config to a reader. The credential identifiers stay, so a caller can see
// which credentials exist and send the config back unchanged.
func (c *Config) ToProtoRedacted() *nodev1.MachineConfig {
	pb := c.ToProto()
	for _, k := range pb.GetPki().GetAcme().GetExternalAccountKeys() {
		k.HmacKeyBase64 = ""
	}
	for _, cred := range pb.GetPki().GetEst().GetEnrollCredentials() {
		cred.PasswordSha256 = ""
	}
	return pb
}

// FromProtoOver converts an applied proto into the config to store over prev,
// the config the node holds now (nil when it holds none, as in a maintenance
// install). It is FromProto plus the protocol-block rules above: a missing
// block keeps prev's, and an empty secret is taken from prev's entry with the
// same identifier. The result still has to pass Validate.
func FromProtoOver(pb *nodev1.MachineConfig, prev *Config) (*Config, error) {
	c, err := FromProto(pb)
	if err != nil {
		return nil, err
	}
	var prevPKI PKI
	if prev != nil {
		prevPKI = prev.PKI
	}

	if pb.GetPki().GetAcme() == nil {
		c.PKI.ACME, c.PKI.DisabledACME = prevPKI.ACME, prevPKI.DisabledACME
	} else if next := firstNonNil(c.PKI.ACME, c.PKI.DisabledACME); next != nil {
		if err := keepACMESecrets(next, firstNonNil(prevPKI.ACME, prevPKI.DisabledACME)); err != nil {
			return nil, err
		}
	}
	if pb.GetPki().GetEst() == nil {
		c.PKI.EST, c.PKI.DisabledEST = prevPKI.EST, prevPKI.DisabledEST
	} else if next := firstNonNil(c.PKI.EST, c.PKI.DisabledEST); next != nil {
		if err := keepESTSecrets(next, firstNonNil(prevPKI.EST, prevPKI.DisabledEST)); err != nil {
			return nil, err
		}
	}
	c.KeepStoredSCEPWhenAbsent(pb, prev)
	if pb.GetPki().GetTsa() == nil {
		c.PKI.TSA, c.PKI.DisabledTSA = prevPKI.TSA, prevPKI.DisabledTSA
	}
	return c, nil
}

// firstNonNil returns on when the protocol is on, else its off block.
func firstNonNil[T any](on, off *T) *T {
	if on != nil {
		return on
	}
	return off
}

// offBlock returns b as a stored off block, or nil when it holds no settings.
func offBlock[T any](b *T) *T {
	if b == nil || reflect.ValueOf(*b).IsZero() {
		return nil
	}
	return b
}

func keepACMESecrets(next, prev *ACME) error {
	stored := map[string]string{}
	if prev != nil {
		for _, k := range prev.ExternalAccountKeys {
			stored[k.KeyID] = k.HMACKeyBase64
		}
	}
	for i := range next.ExternalAccountKeys {
		k := &next.ExternalAccountKeys[i]
		if k.HMACKeyBase64 != "" {
			continue
		}
		secret, ok := stored[k.KeyID]
		if !ok {
			return fmt.Errorf("config: pki.acme.external_account_keys[%d].hmac_key_base64: empty, and the node "+
				"has no stored key for key_id %q to keep; send the secret for a new key", i, k.KeyID)
		}
		k.HMACKeyBase64 = secret
	}
	return nil
}

func keepESTSecrets(next, prev *EST) error {
	stored := map[string]string{}
	if prev != nil {
		for _, cred := range prev.EnrollCredentials {
			stored[cred.Username] = cred.PasswordSHA256
		}
	}
	for i := range next.EnrollCredentials {
		cred := &next.EnrollCredentials[i]
		if cred.PasswordSHA256 != "" {
			continue
		}
		digest, ok := stored[cred.Username]
		if !ok {
			return fmt.Errorf("config: pki.est.enroll_credentials[%d].password_sha256: empty, and the node "+
				"has no stored credential for username %q to keep; send the digest for a new credential", i, cred.Username)
		}
		cred.PasswordSHA256 = digest
	}
	return nil
}

// acmeToProto renders the ACME block: on's settings with enabled=true, else
// off's with enabled=false.
func acmeToProto(on, off *ACME) *nodev1.Acme {
	a := firstNonNil(on, off)
	if a == nil {
		return &nodev1.Acme{Enabled: false}
	}
	pb := &nodev1.Acme{
		Enabled:                   on != nil,
		BaseUrl:                   a.BaseURL,
		HttpPort:                  a.HTTPPort,
		Profile:                   a.Profile,
		TermsOfService:            a.TermsOfService,
		Website:                   a.Website,
		AllowAnonymousAccounts:    a.AllowAnonymousAccounts,
		AllowedIdentifierSuffixes: a.AllowedIdentifierSuffixes,
		OrderTtlHours:             a.OrderTTLHours,
	}
	for _, k := range a.ExternalAccountKeys {
		pb.ExternalAccountKeys = append(pb.ExternalAccountKeys, &nodev1.AcmeExternalAccountKey{
			KeyId:         k.KeyID,
			HmacKeyBase64: k.HMACKeyBase64,
		})
	}
	return pb
}

// acmeFromProto returns the block as on (enabled=true) or off settings
// (enabled=false); a missing or empty off block is neither.
func acmeFromProto(pb *nodev1.Acme) (on, off *ACME) {
	if pb == nil {
		return nil, nil
	}
	a := &ACME{
		BaseURL:                   pb.GetBaseUrl(),
		HTTPPort:                  pb.GetHttpPort(),
		Profile:                   pb.GetProfile(),
		TermsOfService:            pb.GetTermsOfService(),
		Website:                   pb.GetWebsite(),
		AllowAnonymousAccounts:    pb.GetAllowAnonymousAccounts(),
		AllowedIdentifierSuffixes: pb.GetAllowedIdentifierSuffixes(),
		OrderTTLHours:             pb.GetOrderTtlHours(),
	}
	for _, k := range pb.GetExternalAccountKeys() {
		a.ExternalAccountKeys = append(a.ExternalAccountKeys, ExternalAccountKey{
			KeyID:         k.GetKeyId(),
			HMACKeyBase64: k.GetHmacKeyBase64(),
		})
	}
	if pb.GetEnabled() {
		return a, nil
	}
	return nil, offBlock(a)
}

// estToProto renders the EST block: on's settings with enabled=true, else
// off's with enabled=false.
func estToProto(on, off *EST) *nodev1.Est {
	e := firstNonNil(on, off)
	if e == nil {
		return &nodev1.Est{Enabled: false}
	}
	pb := &nodev1.Est{
		Enabled:                   on != nil,
		Hostnames:                 e.Hostnames,
		HttpPort:                  e.HTTPPort,
		Profile:                   e.Profile,
		Label:                     e.Label,
		Realm:                     e.Realm,
		AllowedIdentifierSuffixes: e.AllowedIdentifierSuffixes,
		AllowAnyIdentifier:        e.AllowAnyIdentifier,
	}
	for _, cred := range e.EnrollCredentials {
		pb.EnrollCredentials = append(pb.EnrollCredentials, &nodev1.EstEnrollCredential{
			Username:       cred.Username,
			PasswordSha256: cred.PasswordSHA256,
		})
	}
	return pb
}

// estFromProto returns the block as on (enabled=true) or off settings
// (enabled=false); a missing or empty off block is neither.
func estFromProto(pb *nodev1.Est) (on, off *EST) {
	if pb == nil {
		return nil, nil
	}
	e := &EST{
		Hostnames:                 pb.GetHostnames(),
		HTTPPort:                  pb.GetHttpPort(),
		Profile:                   pb.GetProfile(),
		Label:                     pb.GetLabel(),
		Realm:                     pb.GetRealm(),
		AllowedIdentifierSuffixes: pb.GetAllowedIdentifierSuffixes(),
		AllowAnyIdentifier:        pb.GetAllowAnyIdentifier(),
	}
	for _, cred := range pb.GetEnrollCredentials() {
		e.EnrollCredentials = append(e.EnrollCredentials, ESTEnrollCredential{
			Username:       cred.GetUsername(),
			PasswordSHA256: cred.GetPasswordSha256(),
		})
	}
	if pb.GetEnabled() {
		return e, nil
	}
	return nil, offBlock(e)
}

// protocolKeys are the pki keys whose blocks carry an enabled flag in YAML.
var protocolKeys = []string{"acme", "est", "tsa"}

// popProtocolFlags removes the enabled flag from the pki.acme, pki.est and
// pki.tsa blocks of a YAML document, which the Config structs do not carry, and
// returns the document without them plus the flags it found. A document with
// no flag comes back unchanged.
func popProtocolFlags(raw []byte) ([]byte, map[string]bool, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, nil, fmt.Errorf("config: parse YAML: %w", err)
	}
	pki := mappingValue(&doc, "pki")
	flags := map[string]bool{}
	for _, key := range protocolKeys {
		block := mappingValue(pki, key)
		if block == nil || block.Kind != yaml.MappingNode {
			continue
		}
		for i := 0; i+1 < len(block.Content); i += 2 {
			if block.Content[i].Value != "enabled" {
				continue
			}
			var on bool
			if err := block.Content[i+1].Decode(&on); err != nil {
				return nil, nil, fmt.Errorf("config: pki.%s.enabled: must be true or false: %w", key, err)
			}
			flags[key] = on
			block.Content = append(block.Content[:i], block.Content[i+2:]...)
			break
		}
	}
	if len(flags) == 0 {
		return raw, flags, nil
	}
	out, err := yaml.Marshal(&doc)
	if err != nil {
		return nil, nil, fmt.Errorf("config: parse YAML: %w", err)
	}
	return out, flags, nil
}

// applyProtocolFlags moves a block decoded with enabled: false to its off
// field. A block without the flag is on.
func (c *Config) applyProtocolFlags(flags map[string]bool) {
	if on, ok := flags["acme"]; ok && !on {
		c.PKI.ACME, c.PKI.DisabledACME = nil, offBlock(c.PKI.ACME)
	}
	if on, ok := flags["est"]; ok && !on {
		c.PKI.EST, c.PKI.DisabledEST = nil, offBlock(c.PKI.EST)
	}
	if on, ok := flags["tsa"]; ok && !on {
		c.PKI.TSA, c.PKI.DisabledTSA = nil, offBlock(c.PKI.TSA)
	}
}

// marshalWithDisabledBlocks renders c with each off block written in its
// protocol's place under enabled: false.
func marshalWithDisabledBlocks(c *Config) ([]byte, error) {
	out := *c
	var off []string
	if out.PKI.ACME == nil && out.PKI.DisabledACME != nil {
		out.PKI.ACME = out.PKI.DisabledACME
		off = append(off, "acme")
	}
	if out.PKI.EST == nil && out.PKI.DisabledEST != nil {
		out.PKI.EST = out.PKI.DisabledEST
		off = append(off, "est")
	}
	if out.PKI.TSA == nil && out.PKI.DisabledTSA != nil {
		out.PKI.TSA = out.PKI.DisabledTSA
		off = append(off, "tsa")
	}
	var doc yaml.Node
	if err := doc.Encode(&out); err != nil {
		return nil, fmt.Errorf("config: marshal: %w", err)
	}
	pki := mappingValue(&doc, "pki")
	for _, key := range off {
		block := mappingValue(pki, key)
		if block == nil || block.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("config: marshal: pki.%s did not render as a block", key)
		}
		flag := []*yaml.Node{
			{Kind: yaml.ScalarNode, Tag: "!!str", Value: "enabled"},
			{Kind: yaml.ScalarNode, Tag: "!!bool", Value: "false"},
		}
		block.Content = append(flag, block.Content...)
	}
	return yaml.Marshal(&doc)
}

// mappingValue returns the value under key in the mapping n (or in the
// document n wraps), or nil.
func mappingValue(n *yaml.Node, key string) *yaml.Node {
	if n == nil {
		return nil
	}
	if n.Kind == yaml.DocumentNode && len(n.Content) == 1 {
		n = n.Content[0]
	}
	if n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}
