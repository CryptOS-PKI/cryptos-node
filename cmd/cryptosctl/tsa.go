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
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
)

// newTSACmd groups the RFC 3161 time-stamp authority verbs.
func newTSACmd(opts *globalOpts) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tsa",
		Short: "Inspect the RFC 3161 time-stamp authority",
	}
	cmd.AddCommand(newTSACertificatesCmd(opts))
	return cmd
}

func newTSACertificatesCmd(opts *globalOpts) *cobra.Command {
	var asPEM bool
	cmd := &cobra.Command{
		Use:   "certificates",
		Short: "List every TSA certificate the node has signed tokens with, newest first",
		Long: "List every TSA certificate the node has signed tokens with: the current one and all past\n" +
			"ones, newest first, whether or not the TSA runs this boot. A token signed before a rotation\n" +
			"names a past certificate, so keep them all where tokens are verified. --pem prints the\n" +
			"certificates themselves.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, closeConn, err := dial(opts)
			if err != nil {
				return err
			}
			defer func() { _ = closeConn() }()
			resp, err := client.ListTsaCertificates(cmd.Context(), &nodev1.ListTsaCertificatesRequest{})
			if err != nil {
				return err
			}
			if asPEM && opts.output == formatHuman {
				for _, c := range resp.GetCertificates() {
					if _, err := io.WriteString(cmd.OutOrStdout(), c.GetCertPem()); err != nil {
						return err
					}
				}
				return nil
			}
			return writeTSACertificates(cmd.OutOrStdout(), resp, opts.output)
		},
	}
	cmd.Flags().BoolVar(&asPEM, "pem", false, "print the certificates as PEM instead of a table")
	return cmd
}

func writeTSACertificates(w io.Writer, resp *nodev1.ListTsaCertificatesResponse, format string) error {
	if format != formatHuman {
		return renderProto(w, resp, format)
	}
	if len(resp.GetCertificates()) == 0 {
		_, err := io.WriteString(w, "(no TSA certificates: the TSA has never run on this node)\n")
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "SERIAL\tCURRENT\tNOT_BEFORE\tNOT_AFTER\tSHA256")
	for _, c := range resp.GetCertificates() {
		current := "-"
		if c.GetCurrent() {
			current = "yes"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", c.GetSerialHex(), current,
			c.GetNotBefore().AsTime().UTC().Format(time.RFC3339), c.GetNotAfter().AsTime().UTC().Format(time.RFC3339), c.GetSha256Hex())
	}
	return tw.Flush()
}
