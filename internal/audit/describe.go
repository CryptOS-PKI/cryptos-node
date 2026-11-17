package audit

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
	"strings"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
)

// DetailSerial is the details key under which an entry records the hex serial
// of the certificate a call acted on.
const DetailSerial = "serial_hex"

// The details an ApplyConfig entry records: the generation the apply produced,
// the hex SHA-256 of the applied config, and whether it waits for a reboot
// ("true" or "false").
const (
	DetailConfigGeneration = "config_generation"
	DetailConfigDigest     = "config_digest_sha256"
	DetailRequiresReboot   = "requires_reboot"
)

// DetailError is the details key under which a call that failed records why,
// when the handler knows: the status message it returned, at most
// MaxDetailError bytes. Describe shows it after "(failed)".
const DetailError = "error"

// MaxDetailError is the longest reason an entry records, in bytes, so one
// large error can't bloat the signed, chained log.
const MaxDetailError = 256

// DetailRebootKind is the details key under which a Reboot entry records
// whether the caller asked for a restart (RebootKindReboot) or a power-off
// (RebootKindPowerOff).
const (
	DetailRebootKind   = "reboot_kind"
	RebootKindReboot   = "reboot"
	RebootKindPowerOff = "power_off"
)

// targetDetails are the details keys that name what a call acted on, in the
// order Describe prefers them.
var targetDetails = []string{DetailSerial, "request_dns_names"}

// actions describes the calls an operator looks for in the log. Any other
// call is described by its method name.
var actions = map[string]string{
	"StartCeremony":                "ran the first-boot ceremony",
	"ApplyConfig":                  "applied a machine config",
	"SetManagement":                "changed the Fleet Manager link",
	"IssueLeaf":                    "issued a leaf certificate",
	"SignSubordinateCSR":           "signed a subordinate CA certificate",
	"SubmitSubordinateCertificate": "installed this node's signed CA certificate",
	"RevokeCertificate":            "revoked a certificate",
	"BeginKeyRotation":             "began a CA key rotation",
	"CompleteKeyRotation":          "completed a CA key rotation",
	"SubmitRenewedCertificate":     "installed a renewed CA certificate",
	"ExportCAKey":                  "exported an encrypted CA key backup",
	"ImportCAKey":                  "restored the CA key from a backup",
	"Reboot":                       "rebooted or powered off the node",
	"RemoteReset":                  "reset the node",
	"Reset":                        "reset the node",
	"StageImage":                   "staged an OS image",
	"ActivateImage":                "activated a staged OS image",
	"RollbackImage":                "rolled back to the previous OS image",
}

// MethodName returns the method name alone from a full gRPC method name.
func MethodName(fullMethod string) string {
	return fullMethod[strings.LastIndexByte(fullMethod, '/')+1:]
}

// Describe derives, for display, what an entry's call acted on (empty when the
// entry doesn't record it) and a one-line summary of the entry. Neither is
// part of the chain.
func Describe(ev *nodev1.AuditEvent) (target, summary string) {
	for _, key := range targetDetails {
		if v := ev.GetDetails()[key]; v != "" {
			target = v
			break
		}
	}
	method := MethodName(ev.GetRpcMethod())
	summary = actions[method]
	if summary == "" {
		summary = "called " + method
	}
	switch details := ev.GetDetails(); method {
	case "ApplyConfig":
		if gen := details[DetailConfigGeneration]; gen != "" {
			summary += ": generation " + gen
			if details[DetailRequiresReboot] == "true" {
				summary += " (takes effect at the next reboot)"
			}
		}
	case "Reboot":
		switch details[DetailRebootKind] {
		case RebootKindReboot:
			summary = "rebooted the node"
		case RebootKindPowerOff:
			summary = "powered off the node"
		}
	}
	if target != "" {
		summary += ": " + target
	}
	switch ev.GetOutcome() {
	case nodev1.Outcome_OUTCOME_DENIED:
		summary += " (denied)"
	case nodev1.Outcome_OUTCOME_ERROR:
		summary += " (failed)"
		if reason := ev.GetDetails()[DetailError]; reason != "" {
			summary += ": " + reason
		}
	}
	return target, summary
}
