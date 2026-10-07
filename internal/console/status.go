package console

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
	"crypto/x509"
	"encoding/pem"
	"time"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
)

// RootCN parses the leaf certificate of id.ChainPem (PEM, leaf-first) and
// returns its Subject CommonName. It returns "" when id is nil or the first
// PEM block cannot be parsed.
func RootCN(id *nodev1.Identity) string {
	if id == nil || id.ChainPem == "" {
		return ""
	}
	block, _ := pem.Decode([]byte(id.ChainPem))
	if block == nil {
		return ""
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	return cert.Subject.CommonName
}

// IssuerCN parses id.ChainPem (PEM, leaf-first) and returns the parent CA's
// Subject CommonName: the second certificate's CN when the chain holds two or
// more certs, or "self-signed" when it holds exactly one (a self-signed root).
// It returns "" when id is nil, the chain is empty, or the first block cannot
// be parsed.
func IssuerCN(id *nodev1.Identity) string {
	if id == nil || id.ChainPem == "" {
		return ""
	}
	rest := []byte(id.ChainPem)
	block, rest := pem.Decode(rest)
	if block == nil {
		return ""
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return ""
	}
	second, _ := pem.Decode(rest)
	if second == nil {
		return "self-signed"
	}
	cert, err := x509.ParseCertificate(second.Bytes)
	if err != nil {
		return ""
	}
	return cert.Subject.CommonName
}

// caIdentityLabel maps a NodeRole enum to its CA identity display label. The
// labels fit the 15-column label column with a space to spare, which is why
// the intermediate's label drops "CA".
func caIdentityLabel(role nodev1.NodeRole) string {
	switch role {
	case nodev1.NodeRole_NODE_ROLE_ROOT:
		return "Root CA"
	case nodev1.NodeRole_NODE_ROLE_INTERMEDIATE:
		return "Intermediate"
	case nodev1.NodeRole_NODE_ROLE_ISSUING:
		return "Issuing CA"
	default:
		return "CA"
	}
}

// caLabelFromRole maps a View.Role display string back to its CA identity
// label, so the render can label the identity line without carrying the enum.
func caLabelFromRole(role string) string {
	switch role {
	case "ROOT":
		return caIdentityLabel(nodev1.NodeRole_NODE_ROLE_ROOT)
	case "INTERMEDIATE":
		return caIdentityLabel(nodev1.NodeRole_NODE_ROLE_INTERMEDIATE)
	case "ISSUING":
		return caIdentityLabel(nodev1.NodeRole_NODE_ROLE_ISSUING)
	default:
		return caIdentityLabel(nodev1.NodeRole_NODE_ROLE_UNSPECIFIED)
	}
}

// roleLabel maps a NodeRole enum to its short display string.
func roleLabel(r nodev1.NodeRole) string {
	switch r {
	case nodev1.NodeRole_NODE_ROLE_ROOT:
		return "ROOT"
	case nodev1.NodeRole_NODE_ROLE_INTERMEDIATE:
		return "INTERMEDIATE"
	case nodev1.NodeRole_NODE_ROLE_ISSUING:
		return "ISSUING"
	default:
		return "UNKNOWN"
	}
}

// identityLabel maps an IdentityState enum to its short display string.
func identityLabel(s nodev1.IdentityState) string {
	switch s {
	case nodev1.IdentityState_IDENTITY_STATE_ESTABLISHED:
		return "ESTABLISHED"
	case nodev1.IdentityState_IDENTITY_STATE_CEREMONY_IN_PROGRESS:
		return "establishing"
	default:
		return "maintenance"
	}
}

// tpmLabel maps a TpmState enum to its short display string. Only the OK state
// reports a sealed identity; every other state is surfaced as UNAVAILABLE.
func tpmLabel(s nodev1.TpmState) string {
	if s == nodev1.TpmState_TPM_STATE_OK {
		return "SEALED"
	}
	return "UNAVAILABLE"
}

// fleetFromAPI maps the API FleetManagerState to the dashboard FleetState. An
// unset/unspecified state reads as not-enrolled (the thin M4 default: no Fleet
// Manager endpoint is configured yet; real connected/disconnected arrives with
// the future Fleet Manager enrollment spec).
func fleetFromAPI(s nodev1.FleetManagerState) FleetState {
	switch s {
	case nodev1.FleetManagerState_FLEET_MANAGER_STATE_CONNECTED:
		return FleetConnected
	case nodev1.FleetManagerState_FLEET_MANAGER_STATE_DISCONNECTED:
		return FleetDisconnected
	default:
		return FleetNotEnrolled
	}
}

// ViewFromAPI maps the node status, identity, and a measured uptime into the
// dashboard View. Maintenance is set whenever the identity is not established,
// and AwaitingCeremony, AwaitingParentCert or CeremonyInProgress when the node
// is installed and on its way to one. The maintenance installer leaves the
// identity state unset, which keeps an uninstalled node on the plain
// maintenance screen.
func ViewFromAPI(st *nodev1.NodeStatus, id *nodev1.Identity, uptime time.Duration) View {
	v := View{
		RootCN: RootCN(id),
		Issuer: IssuerCN(id),
		Uptime: uptime,
		Fleet:  FleetNotEnrolled,
	}
	if st != nil {
		v.Role = roleLabel(st.Role)
		v.NodeStatus = identityLabel(st.IdentityState)
		v.TPM = tpmLabel(st.TpmState)
		v.Version = st.SoftwareVersion
		v.Fleet = fleetFromAPI(st.GetFleetManager())
		v.Maintenance = st.IdentityState != nodev1.IdentityState_IDENTITY_STATE_ESTABLISHED
		v.AwaitingCeremony = st.IdentityState == nodev1.IdentityState_IDENTITY_STATE_NONE
		v.AwaitingParentCert = st.IdentityState == nodev1.IdentityState_IDENTITY_STATE_AWAITING_CERT
		v.CeremonyInProgress = st.IdentityState == nodev1.IdentityState_IDENTITY_STATE_CEREMONY_IN_PROGRESS
	}
	return v
}
