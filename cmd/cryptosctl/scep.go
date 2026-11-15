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
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
)

// newSCEPCmd groups the SCEP administration verbs: the one-time challenges
// that authorize an initial enrolment, and the queue of enrolments held for
// approval on profiles with require_approval.
func newSCEPCmd(opts *globalOpts) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scep",
		Short: "Manage SCEP enrolment: one-time challenges and the approval queue",
	}
	challenge := &cobra.Command{Use: "challenge", Short: "Mint, list and revoke one-time SCEP challenges"}
	challenge.AddCommand(newSCEPMintCmd(opts), newSCEPListChallengesCmd(opts), newSCEPRevokeChallengeCmd(opts))
	enrollments := &cobra.Command{Use: "enrollments", Short: "List, approve and reject SCEP enrolments waiting for approval"}
	enrollments.AddCommand(newSCEPListEnrollmentsCmd(opts), newSCEPApproveCmd(opts), newSCEPRejectCmd(opts))
	cmd.AddCommand(challenge, enrollments)
	return cmd
}

func newSCEPMintCmd(opts *globalOpts) *cobra.Command {
	var (
		profile string
		ttl     time.Duration
		names   []string
	)
	cmd := &cobra.Command{
		Use:   "mint",
		Short: "Mint a single-use challenge for one device's initial enrolment",
		Long: "Mint a single-use challenge for one device's initial enrolment. The challenge is shown\n" +
			"once: the node keeps only its digest. Give it to the device as its enrolment password,\n" +
			"for example a Cisco trustpoint's `password`, before it expires.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if ttl < 0 || ttl%time.Second != 0 {
				return errors.New("--ttl must be a whole number of seconds, for example 1h or 30m")
			}
			if ttl/time.Second > math.MaxUint32 {
				return errors.New("--ttl is too long: the node takes at most 4294967295 seconds")
			}
			ttlSeconds := uint32(ttl / time.Second) //nolint:gosec // G115: non-negative and checked against MaxUint32 above
			client, closeConn, err := dial(opts)
			if err != nil {
				return err
			}
			defer func() { _ = closeConn() }()
			resp, err := client.MintScepChallenge(cmd.Context(), &nodev1.MintScepChallengeRequest{
				Profile: profile, TtlSeconds: ttlSeconds, BoundNames: names,
			})
			if err != nil {
				return err
			}
			if opts.output != formatHuman {
				return renderProto(cmd.OutOrStdout(), resp, opts.output)
			}
			ch := resp.GetChallenge()
			w := cmd.OutOrStdout()
			_, _ = fmt.Fprintf(w, "Challenge:   %s\n", resp.GetChallengePassword())
			_, _ = fmt.Fprintf(w, "ID:          %s\n", ch.GetId())
			_, _ = fmt.Fprintf(w, "Profile:     %s\n", ch.GetProfile())
			_, _ = fmt.Fprintf(w, "Expires:     %s\n", ch.GetExpiresAt().AsTime().UTC().Format(time.RFC3339))
			if len(ch.GetBoundNames()) > 0 {
				_, _ = fmt.Fprintf(w, "Bound names: %s\n", strings.Join(ch.GetBoundNames(), ", "))
			}
			_, err = fmt.Fprintln(cmd.ErrOrStderr(), "The challenge is shown once and works for one enrolment. The node cannot show it again.")
			return err
		},
	}
	cmd.Flags().StringVar(&profile, "profile", "", "SCEP profile the enrolment issues from (required when several are configured)")
	cmd.Flags().DurationVar(&ttl, "ttl", 0, "how long the challenge stays usable (default 1h, at most 168h)")
	cmd.Flags().StringSliceVar(&names, "name", nil, "bind the challenge to this DNS name (repeatable); the request may then carry only these names")
	return cmd
}

func newSCEPListChallengesCmd(opts *globalOpts) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the challenges that are still usable",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, closeConn, err := dial(opts)
			if err != nil {
				return err
			}
			defer func() { _ = closeConn() }()
			resp, err := client.ListScepChallenges(cmd.Context(), &nodev1.ListScepChallengesRequest{})
			if err != nil {
				return err
			}
			return writeSCEPChallenges(cmd.OutOrStdout(), resp, opts.output)
		},
	}
}

func newSCEPRevokeChallengeCmd(opts *globalOpts) *cobra.Command {
	var id string
	cmd := &cobra.Command{
		Use:   "revoke",
		Short: "Withdraw an unused challenge",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if id == "" {
				return errors.New("--id is required")
			}
			client, closeConn, err := dial(opts)
			if err != nil {
				return err
			}
			defer func() { _ = closeConn() }()
			resp, err := client.RevokeScepChallenge(cmd.Context(), &nodev1.RevokeScepChallengeRequest{Id: id})
			if err != nil {
				return err
			}
			if opts.output != formatHuman {
				return renderProto(cmd.OutOrStdout(), resp, opts.output)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Revoked challenge %s (profile %s)\n", resp.GetChallenge().GetId(), resp.GetChallenge().GetProfile())
			return err
		},
	}
	cmd.Flags().StringVar(&id, "id", "", "id of the challenge to revoke (required)")
	return cmd
}

func newSCEPListEnrollmentsCmd(opts *globalOpts) *cobra.Command {
	var profile string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the enrolments waiting for approval",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, closeConn, err := dial(opts)
			if err != nil {
				return err
			}
			defer func() { _ = closeConn() }()
			resp, err := client.ListScepEnrollments(cmd.Context(), &nodev1.ListScepEnrollmentsRequest{Profile: profile})
			if err != nil {
				return err
			}
			return writeSCEPEnrollments(cmd.OutOrStdout(), resp, opts.output)
		},
	}
	cmd.Flags().StringVar(&profile, "profile", "", "only list enrolments for this SCEP profile")
	return cmd
}

func newSCEPApproveCmd(opts *globalOpts) *cobra.Command {
	var id string
	cmd := &cobra.Command{
		Use:   "approve",
		Short: "Issue the certificate for a waiting enrolment",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if id == "" {
				return errors.New("--id is required")
			}
			client, closeConn, err := dial(opts)
			if err != nil {
				return err
			}
			defer func() { _ = closeConn() }()
			resp, err := client.ApproveScepEnrollment(cmd.Context(), &nodev1.ApproveScepEnrollmentRequest{Id: id})
			if err != nil {
				return err
			}
			if opts.output != formatHuman {
				return renderProto(cmd.OutOrStdout(), resp, opts.output)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Approved enrolment %s: issued serial %s. The device collects it at its next poll.\n",
				resp.GetEnrollment().GetId(), resp.GetSerialHex())
			return err
		},
	}
	cmd.Flags().StringVar(&id, "id", "", "id of the enrolment to approve (required)")
	return cmd
}

func newSCEPRejectCmd(opts *globalOpts) *cobra.Command {
	var id, reason string
	cmd := &cobra.Command{
		Use:   "reject",
		Short: "Refuse a waiting enrolment",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if id == "" {
				return errors.New("--id is required")
			}
			client, closeConn, err := dial(opts)
			if err != nil {
				return err
			}
			defer func() { _ = closeConn() }()
			resp, err := client.RejectScepEnrollment(cmd.Context(), &nodev1.RejectScepEnrollmentRequest{Id: id, Reason: reason})
			if err != nil {
				return err
			}
			if opts.output != formatHuman {
				return renderProto(cmd.OutOrStdout(), resp, opts.output)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Rejected enrolment %s. The device's next poll is refused.\n", resp.GetEnrollment().GetId())
			return err
		},
	}
	cmd.Flags().StringVar(&id, "id", "", "id of the enrolment to reject (required)")
	cmd.Flags().StringVar(&reason, "reason", "", "why, for the audit log (the device is not told)")
	return cmd
}

func writeSCEPChallenges(w io.Writer, resp *nodev1.ListScepChallengesResponse, format string) error {
	if format != formatHuman {
		return renderProto(w, resp, format)
	}
	if len(resp.GetChallenges()) == 0 {
		_, err := io.WriteString(w, "(no usable challenges)\n")
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "ID\tPROFILE\tEXPIRES\tBOUND_NAMES\tCREATED_BY")
	for _, c := range resp.GetChallenges() {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", c.GetId(), c.GetProfile(),
			c.GetExpiresAt().AsTime().UTC().Format(time.RFC3339), orDash(strings.Join(c.GetBoundNames(), ",")), orDash(c.GetCreatedByCn()))
	}
	return tw.Flush()
}

func writeSCEPEnrollments(w io.Writer, resp *nodev1.ListScepEnrollmentsResponse, format string) error {
	if format != formatHuman {
		return renderProto(w, resp, format)
	}
	if len(resp.GetEnrollments()) == 0 {
		_, err := io.WriteString(w, "(no enrolments waiting)\n")
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "ID\tPROFILE\tSUBJECT\tDNS_NAMES\tKEY\tRECEIVED")
	for _, e := range resp.GetEnrollments() {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", e.GetId(), e.GetProfile(), e.GetSubjectDn(),
			orDash(strings.Join(e.GetDnsNames(), ",")), e.GetKeyAlg(), e.GetReceivedAt().AsTime().UTC().Format(time.RFC3339))
	}
	return tw.Flush()
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
