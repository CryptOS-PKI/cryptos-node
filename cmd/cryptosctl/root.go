package main

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
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

// globalOpts holds the persistent flags shared by every subcommand.
type globalOpts struct {
	endpoint     string
	identityCert string
	identityKey  string
	trustCert    string
	socket       string
	serverName   string
	output       string
	insecure     bool
}

// defaultIdentityDir is ~/.cryptos, where cryptosctl looks for its
// client identity and trust material by default.
func defaultIdentityDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".cryptos"
	}
	return filepath.Join(home, ".cryptos")
}

// newRootCmd builds the full command tree.
func newRootCmd() *cobra.Command {
	opts := &globalOpts{}
	root := &cobra.Command{
		Use:           "cryptosctl",
		Short:         "Operator CLI for a CryptOS node",
		Long:          "cryptosctl manages a CryptOS CA node over its mTLS gRPC API (or the on-box UNIX socket).",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	dir := defaultIdentityDir()
	pf := root.PersistentFlags()
	pf.StringVar(&opts.endpoint, "endpoint", "localhost:443", "node address (host:port) for the mTLS gRPC API")
	pf.StringVar(&opts.identityCert, "identity", filepath.Join(dir, "identity.crt"), "client identity certificate (PEM)")
	pf.StringVar(&opts.identityKey, "identity-key", filepath.Join(dir, "identity.key"), "client identity private key (PEM)")
	pf.StringVar(&opts.trustCert, "trust", filepath.Join(dir, "trust.crt"), "trusted server CA certificate (PEM)")
	pf.StringVar(&opts.socket, "socket", "", "on-box UNIX socket path (bypasses mTLS; e.g. /run/cryptos.sock)")
	pf.StringVar(&opts.serverName, "server-name", "", "override the TLS server name (defaults to the endpoint host)")
	pf.BoolVar(&opts.insecure, "insecure", false, "server-TLS only: skip client identity and server verification (for a maintenance node)")
	pf.StringVarP(&opts.output, "output", "o", "human", "output format: human|json|yaml")

	root.AddCommand(
		newStatusCmd(opts),
		newIdentityCmd(opts),
		newCeremonyCmd(opts),
		newCACmd(opts),
		newConfigCmd(opts),
		newBootstrapCmd(opts),
		newImageCmd(opts),
		newRebootCmd(opts),
		newResetCmd(opts),
		newVersionCmd(opts),
		newTrustCmd(opts),
		newSCEPCmd(opts),
		newTSACmd(opts),
		newAuditCmd(opts),
	)
	addDebugCommands(root, opts)
	return root
}
