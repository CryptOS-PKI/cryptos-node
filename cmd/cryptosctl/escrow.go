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
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
)

// newExportKeyCmd exports this node's CA key + chain to a strongly-encrypted,
// operator-passphrase-sealed backup file for disaster recovery / CA migration.
// It is a sensitive action (it creates an offline copy of the CA key), so it is
// gated behind a strong warning and a typed confirmation before the export RPC
// is called. The node refuses the export on a TPM node.
func newExportKeyCmd(opts *globalOpts) *cobra.Command {
	var (
		outFile   string
		assumeYes bool
		role      string
	)
	cmd := &cobra.Command{
		Use:   "export-key",
		Short: "Export this node's CA key to an encrypted backup file",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if outFile == "" {
				return errors.New("--out is required")
			}

			client, closeConn, err := dial(opts)
			if err != nil {
				return err
			}
			defer func() { _ = closeConn() }()

			// Learn the node's identity (Root CA CN and whether it is a root) so
			// the confirmation gate can require the CN on a root. --role overrides
			// the fetch when the operator prefers not to rely on it.
			cn, isRoot, err := resolveExportSubject(cmd, opts, role)
			if err != nil {
				return err
			}
			if err := confirmExport(cmd, cn, isRoot, assumeYes); err != nil {
				return err
			}

			passphrase, err := promptNewPassphrase(cmd)
			if err != nil {
				return err
			}

			resp, err := client.ExportCAKey(cmd.Context(), &nodev1.ExportCAKeyRequest{Passphrase: passphrase})
			if err != nil {
				return err
			}
			if len(resp.GetEnvelope()) == 0 {
				return errors.New("node returned an empty backup envelope")
			}
			if err := os.WriteFile(outFile, resp.GetEnvelope(), 0o600); err != nil {
				return fmt.Errorf("write backup: %w", err)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "wrote encrypted CA key backup to %s (%d bytes)\n", outFile, len(resp.GetEnvelope()))
			return err
		},
	}
	cmd.Flags().StringVar(&outFile, "out", "", "output file for the encrypted backup (required)")
	cmd.Flags().BoolVar(&assumeYes, "yes", false, "skip the interactive confirmation (for automation)")
	cmd.Flags().StringVar(&role, "role", "", "override the confirmation role: root or subordinate (default: read from the node)")
	return cmd
}

// newImportKeyCmd restores a CA identity onto a fresh, no-identity node from an
// encrypted backup file. It reads the backup, prompts for the passphrase, calls
// ImportCAKey, and prints the restored identity.
func newImportKeyCmd(opts *globalOpts) *cobra.Command {
	var backupFile string
	cmd := &cobra.Command{
		Use:   "import-key",
		Short: "Restore a CA from an encrypted backup file (fresh node)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if backupFile == "" {
				return errors.New("--backup is required")
			}
			envelope, err := os.ReadFile(backupFile)
			if err != nil {
				return fmt.Errorf("read backup: %w", err)
			}
			if len(envelope) == 0 {
				return errors.New("backup file is empty")
			}

			passphrase, err := promptPassphrase(cmd, "Backup passphrase: ")
			if err != nil {
				return err
			}

			client, closeConn, err := dial(opts)
			if err != nil {
				return err
			}
			defer func() { _ = closeConn() }()

			resp, err := client.ImportCAKey(cmd.Context(), &nodev1.ImportCAKeyRequest{
				Envelope:   envelope,
				Passphrase: passphrase,
			})
			if err != nil {
				return err
			}
			return writeIdentity(cmd.OutOrStdout(), resp.GetIdentity(), opts.output)
		},
	}
	cmd.Flags().StringVar(&backupFile, "backup", "", "encrypted backup file to restore (required)")
	return cmd
}

// resolveExportSubject determines the Root CA CN and whether the node is a root,
// for the confirmation gate. An explicit --role ("root"/"subordinate") wins;
// otherwise it calls GetIdentity and inspects the leaf certificate (a root is
// self-signed: issuer equals subject). A missing identity is an error: there is
// nothing to export.
func resolveExportSubject(cmd *cobra.Command, opts *globalOpts, role string) (cn string, isRoot bool, err error) {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "root":
		return "", true, nil
	case "subordinate", "sub", "intermediate":
		return "", false, nil
	case "":
		// fall through to the node fetch
	default:
		return "", false, fmt.Errorf("invalid --role %q (want root or subordinate)", role)
	}

	id, err := fetchIdentity(cmd, opts)
	if err != nil {
		return "", false, err
	}
	if id == nil || len(id.GetChainDer()) == 0 {
		return "", false, errors.New("node has no identity to export")
	}
	leaf, err := x509.ParseCertificate(id.GetChainDer()[0])
	if err != nil {
		return "", false, fmt.Errorf("parse identity leaf: %w", err)
	}
	return leaf.Subject.CommonName, leaf.Subject.String() == leaf.Issuer.String(), nil
}

// confirmExport gates the export behind a strong warning and a typed
// confirmation: the Root CA CN on a root (highest stakes), a plain "yes" on a
// subordinate. --yes skips the prompt for automation.
func confirmExport(cmd *cobra.Command, cn string, isRoot, assumeYes bool) error {
	out := cmd.OutOrStdout()

	var b strings.Builder
	b.WriteString("WARNING: export-key creates an offline, portable copy of this CA's private key.\n")
	b.WriteString("Anyone who obtains the backup file and its passphrase can impersonate this CA.\n")
	b.WriteString("Store the file offline, protect the passphrase, and destroy the copy when done.\n")
	if isRoot {
		b.WriteString("This is a ROOT CA: its key anchors the whole hierarchy.\n")
	}
	if assumeYes {
		b.WriteString("--yes given: proceeding without confirmation.\n")
		_, err := fmt.Fprint(out, b.String())
		return err
	}
	if isRoot {
		if cn == "" {
			return errors.New("cannot confirm a root export without the Root CA common name; pass --role subordinate only for a subordinate")
		}
		prompt := fmt.Sprintf("To proceed, type the Root CA common name exactly (%q): ", cn)
		b.WriteString(prompt)
	} else {
		b.WriteString("To proceed, type yes: ")
	}
	if _, err := fmt.Fprint(out, b.String()); err != nil {
		return err
	}

	line, err := readConfirmLine(cmd)
	if err != nil {
		return err
	}
	if isRoot {
		if line != cn {
			return errors.New("confirmation did not match the Root CA common name; aborted")
		}
		return nil
	}
	if !strings.EqualFold(line, "yes") {
		return errors.New("not confirmed; aborted")
	}
	return nil
}

// promptNewPassphrase prompts for a passphrase twice and requires the two
// entries to match, so a mistyped passphrase does not seal an unopenable
// backup.
func promptNewPassphrase(cmd *cobra.Command) ([]byte, error) {
	first, err := promptPassphrase(cmd, "New backup passphrase: ")
	if err != nil {
		return nil, err
	}
	if len(first) == 0 {
		return nil, errors.New("passphrase must not be empty")
	}
	second, err := promptPassphrase(cmd, "Confirm backup passphrase: ")
	if err != nil {
		return nil, err
	}
	if string(first) != string(second) {
		return nil, errors.New("passphrases did not match; aborted")
	}
	return first, nil
}

// promptPassphrase reads a passphrase from the operator. When the command's
// input is the real terminal it reads without echo; otherwise (a pipe, as in
// tests or automation) it reads a plain line. The prompt is written to stdout.
func promptPassphrase(cmd *cobra.Command, prompt string) ([]byte, error) {
	if _, err := fmt.Fprint(cmd.OutOrStdout(), prompt); err != nil {
		return nil, err
	}
	if f, ok := cmd.InOrStdin().(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		line, err := term.ReadPassword(int(f.Fd()))
		if err != nil {
			return nil, fmt.Errorf("read passphrase: %w", err)
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout())
		return line, nil
	}
	// Non-terminal input (a pipe, or tests): read a single line without buffering
	// ahead, so a second prompt on the same stream still sees its own line.
	return readLineUnbuffered(cmd.InOrStdin())
}

// readLineUnbuffered reads one newline-terminated line from r one byte at a
// time (no read-ahead), trims a trailing CR/LF, and returns it. It tolerates a
// final line with no trailing newline (returns what it read at EOF).
func readLineUnbuffered(r io.Reader) ([]byte, error) {
	var line []byte
	buf := make([]byte, 1)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if buf[0] == '\n' {
				break
			}
			line = append(line, buf[0])
		}
		if err != nil {
			if err == io.EOF {
				if len(line) == 0 {
					return nil, fmt.Errorf("read passphrase: %w", err)
				}
				break
			}
			return nil, fmt.Errorf("read passphrase: %w", err)
		}
	}
	return []byte(strings.TrimRight(string(line), "\r")), nil
}
