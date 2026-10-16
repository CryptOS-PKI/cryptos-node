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

// In-place image upgrade (#208): replacing a node's CryptOS build without
// re-provisioning it, so an OS change stops destroying the CA key along with
// the state partition.

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
	"github.com/CryptOS-PKI/cryptos-node/internal/isoimage"
	"github.com/CryptOS-PKI/cryptos-node/internal/ukisign"
)

// imageChunkBytes is the upload chunk size. The server's default gRPC receive
// limit is 4 MiB, so a chunk has to stay under it with room for the message
// framing; 1 MiB is comfortably inside and still few enough round trips for a
// few hundred megabytes.
const imageChunkBytes = 1 << 20

// newImageCmd groups the image upgrade verbs.
func newImageCmd(opts *globalOpts) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "image",
		Short: "Upgrade the node's CryptOS image in place",
		Long: "Replace the node's CryptOS image without re-provisioning it. " +
			"The state partition -- CA key, issued history, identity -- is never touched.",
	}
	cmd.AddCommand(
		newImageStatusCmd(opts),
		newImageStageCmd(opts),
		newImageRollbackCmd(opts),
		newImageActivateCmd(opts),
		newImageSignCmd(),
	)

	return cmd
}

// newImageStatusCmd reports what the node is running and what it will boot.
func newImageStatusCmd(opts *globalOpts) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show the running and staged images",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, closeConn, err := dial(opts)
			if err != nil {
				return err
			}
			defer func() { _ = closeConn() }()

			resp, err := client.GetImageStatus(cmd.Context(), &nodev1.GetImageStatusRequest{})
			if err != nil {
				return err
			}

			return writeImageStatus(cmd.OutOrStdout(), resp.GetStatus(), opts.output)
		},
	}
}

// newImageStageCmd uploads an image and makes it the one the node will boot.
func newImageStageCmd(opts *globalOpts) *cobra.Command {
	var (
		imagePath string
		sigPath   string
	)
	cmd := &cobra.Command{
		Use:   "stage",
		Short: "Upload a signed image and make it the one the node boots next",
		Long: "Upload a signed CryptOS image. The node verifies the detached release " +
			"signature before anything reaches the ESP, keeps the current image for " +
			"rollback, and does not reboot: run 'image activate' when the outage is " +
			"acceptable.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if imagePath == "" {
				return errors.New("--image is required")
			}
			if sigPath == "" {
				// cryptos-appliance's build/uki/sign.sh writes the detached
				// signature beside the image under exactly this name.
				sigPath = imagePath + ".sig"
			}
			signature, err := os.ReadFile(sigPath)
			if err != nil {
				return fmt.Errorf("read the release signature: %w", err)
			}

			size, digest, err := imageSizeAndDigest(imagePath)
			if err != nil {
				return err
			}

			client, closeConn, err := dial(opts)
			if err != nil {
				return err
			}
			defer func() { _ = closeConn() }()

			stream, err := client.StageImage(cmd.Context())
			if err != nil {
				return err
			}
			if err := stream.Send(&nodev1.StageImageRequest{
				Payload: &nodev1.StageImageRequest_Begin{
					Begin: &nodev1.StageImageBegin{
						Sha256:    digest,
						Signature: signature,
						SizeBytes: size,
					},
				},
			}); err != nil {
				return fmt.Errorf("send the begin header: %w", err)
			}
			if err := sendImageChunks(stream, imagePath); err != nil {
				return err
			}

			resp, err := stream.CloseAndRecv()
			if err != nil {
				return err
			}

			return writeImageStatus(cmd.OutOrStdout(), resp.GetStatus(), opts.output)
		},
	}
	cmd.Flags().StringVar(&imagePath, "image", "", "signed CryptOS image (UKI) to install")
	cmd.Flags().StringVar(&sigPath, "signature", "", "detached release signature (default: <image>.sig)")

	return cmd
}

// imageSizeAndDigest measures the image before the upload starts, because the
// begin header has to declare both and the node checks them: the size lets it
// refuse an implausible transfer up front, and the digest distinguishes a
// truncated upload from a bad signature.
func imageSizeAndDigest(path string) (uint64, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, "", fmt.Errorf("open the image: %w", err)
	}
	defer func() { _ = f.Close() }()

	sum := sha256.New()
	n, err := io.Copy(sum, f)
	if err != nil {
		return 0, "", fmt.Errorf("read the image: %w", err)
	}
	if n == 0 {
		return 0, "", fmt.Errorf("the image %s is empty", path)
	}

	return uint64(n), hex.EncodeToString(sum.Sum(nil)), nil
}

// sendImageChunks streams the image rather than reading it whole, so an
// operator workstation does not need a few hundred megabytes of headroom to
// upgrade a node.
func sendImageChunks(stream nodev1.NodeService_StageImageClient, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open the image: %w", err)
	}
	defer func() { _ = f.Close() }()

	buf := make([]byte, imageChunkBytes)
	for {
		n, readErr := f.Read(buf)
		if n > 0 {
			if sendErr := stream.Send(&nodev1.StageImageRequest{
				Payload: &nodev1.StageImageRequest_Chunk{Chunk: buf[:n]},
			}); sendErr != nil {
				return fmt.Errorf("send an image chunk: %w", sendErr)
			}
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
		if readErr != nil {
			return fmt.Errorf("read the image: %w", readErr)
		}
	}
}

// newImageRollbackCmd puts the retained previous image back.
func newImageRollbackCmd(opts *globalOpts) *cobra.Command {
	return &cobra.Command{
		Use:   "rollback",
		Short: "Put the retained previous image back on the boot path",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, closeConn, err := dial(opts)
			if err != nil {
				return err
			}
			defer func() { _ = closeConn() }()

			resp, err := client.RollbackImage(cmd.Context(), &nodev1.RollbackImageRequest{})
			if err != nil {
				return err
			}

			return writeImageStatus(cmd.OutOrStdout(), resp.GetStatus(), opts.output)
		},
	}
}

// newImageActivateCmd reboots the node into a staged image.
func newImageActivateCmd(opts *globalOpts) *cobra.Command {
	var confirm string
	cmd := &cobra.Command{
		Use:   "activate",
		Short: "Reboot the node so the staged image starts running",
		Long: "Reboot the node into the staged image. This takes the CA offline for the " +
			"duration of the boot, so it asks for the CA common name as confirmation, " +
			"the same echo the reset verbs require.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if confirm == "" {
				return errors.New("--confirm is required: echo the node's CA common name")
			}

			client, closeConn, err := dial(opts)
			if err != nil {
				return err
			}
			defer func() { _ = closeConn() }()

			if _, err := client.ActivateImage(cmd.Context(), &nodev1.ActivateImageRequest{
				ConfirmCaCn: confirm,
			}); err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), "rebooting into the staged image")

			return err
		},
	}
	cmd.Flags().StringVar(&confirm, "confirm", "", "the node's CA common name, echoed to authorize the reboot")

	return cmd
}

// newImageSignCmd signs an unsigned UKI with the operator's own key and makes
// that key the image's upgrade anchor (cryptos-appliance#41). Given an ISO,
// it signs the UKI the ISO carries and writes it back into the ISO
// (cryptos-appliance#83). It runs on the workstation and never talks to a
// node.
func newImageSignCmd() *cobra.Command {
	var (
		imagePath string
		keyPath   string
		certPath  string
		outPath   string
	)
	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign an unsigned image or ISO with your key and make it the upgrade anchor",
		Long: "Sign an unsigned CryptOS image (UKI) with your own Secure Boot key. The " +
			"certificate is added to the image as its upgrade anchor, the image is " +
			"Authenticode-signed for Secure Boot, and the detached release signature " +
			"'image stage' sends is written beside it as <out>.sig. A node installed " +
			"from the signed image takes in-place upgrades signed by the same key. " +
			"Given an unsigned ISO instead, it signs the UKI inside it the same way, " +
			"writes the signed UKI back over every copy in the ISO, and also writes " +
			"the signed UKI and its .sig beside the signed ISO for staging upgrades. " +
			"Runs locally; it does not contact a node.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			switch {
			case imagePath == "":
				return errors.New("--image is required")
			case keyPath == "":
				return errors.New("--key is required")
			case certPath == "":
				return errors.New("--cert is required")
			case outPath == imagePath:
				return errors.New("--out must differ from --image")
			}

			image, err := os.ReadFile(imagePath)
			if err != nil {
				return fmt.Errorf("read the image: %w", err)
			}
			keyPEM, err := os.ReadFile(keyPath)
			if err != nil {
				return fmt.Errorf("read the key: %w", err)
			}
			key, err := ukisign.ParseKey(keyPEM)
			if err != nil {
				return err
			}
			certBytes, err := os.ReadFile(certPath)
			if err != nil {
				return fmt.Errorf("read the certificate: %w", err)
			}
			cert, err := ukisign.ParseCertificate(certBytes)
			if err != nil {
				return err
			}

			if isoimage.IsISO(image) {
				return signISO(cmd.OutOrStdout(), imagePath, outPath, image, key, cert)
			}

			if outPath == "" {
				outPath = ukisign.DefaultOut(imagePath)
			}
			if outPath == imagePath {
				return errors.New("--out must differ from --image")
			}
			res, err := ukisign.Sign(image, key, cert)
			if err != nil {
				return err
			}
			if err := os.WriteFile(outPath, res.Image, 0o644); err != nil {
				return fmt.Errorf("write the signed image: %w", err)
			}
			sigPath := outPath + ".sig"
			if err := os.WriteFile(sigPath, res.Signature, 0o644); err != nil {
				return fmt.Errorf("write the release signature: %w", err)
			}

			return writeImageSigned(cmd.OutOrStdout(), outPath, sigPath, res.Image, cert)
		},
	}
	cmd.Flags().StringVar(&imagePath, "image", "", "unsigned CryptOS image to sign: a UKI, or an ISO that carries one")
	cmd.Flags().StringVar(&keyPath, "key", "", "RSA signing key, PEM (PKCS#1 or PKCS#8, not encrypted)")
	cmd.Flags().StringVar(&certPath, "cert", "", "signing certificate, PEM or DER; it becomes the upgrade anchor")
	cmd.Flags().StringVar(&outPath, "out", "", "signed image path (default: <image> without .unsigned, else <image>.signed.uki; "+
		"for an ISO, <image> without -unsigned, else <image>.signed.iso, with the signed UKI beside it as <out without .iso>.uki)")

	return cmd
}

// signISO signs the UKI inside an ISO and writes the signed ISO, the signed
// UKI and the UKI's detached signature. Nothing is written unless the signed
// ISO passed its self-check.
func signISO(w io.Writer, isoPath, outPath string, iso []byte, key crypto.Signer, cert *x509.Certificate) error {
	if outPath == "" {
		outPath = ukisign.DefaultISOOut(isoPath)
	}
	ukiPath := ukisign.ISOUKIPath(outPath)
	sigPath := ukiPath + ".sig"
	for _, p := range []string{outPath, ukiPath, sigPath} {
		if p == isoPath {
			return fmt.Errorf("signing %s would overwrite it; pick another --out", isoPath)
		}
	}
	res, err := ukisign.SignISO(iso, key, cert)
	if err != nil {
		return err
	}
	if err := os.WriteFile(outPath, res.ISO, 0o644); err != nil {
		return fmt.Errorf("write the signed ISO: %w", err)
	}
	if err := os.WriteFile(ukiPath, res.Image, 0o644); err != nil {
		return fmt.Errorf("write the signed image: %w", err)
	}
	if err := os.WriteFile(sigPath, res.Signature, 0o644); err != nil {
		return fmt.Errorf("write the release signature: %w", err)
	}

	sum := sha256.Sum256(res.ISO)
	if _, err := fmt.Fprintf(w, "Signed ISO:       %s\nISO SHA-256:      %s\n", outPath, hex.EncodeToString(sum[:])); err != nil {
		return err
	}
	for _, c := range res.Copies {
		if _, err := fmt.Fprintf(w, "Signed in ISO:    %s\n", c); err != nil {
			return err
		}
	}

	return writeImageSigned(w, ukiPath, sigPath, res.Image, cert)
}

// writeImageSigned reports what was written and which certificate the image
// now trusts for upgrades, by subject and SHA-256 fingerprint.
func writeImageSigned(w io.Writer, outPath, sigPath string, image []byte, cert *x509.Certificate) error {
	sum := sha256.Sum256(image)
	fp := sha256.Sum256(cert.Raw)
	_, err := fmt.Fprintf(w,
		"Signed image:     %s\nImage SHA-256:    %s\nRelease sig:      %s\nUpgrade anchor:   %s\nAnchor SHA-256:   %s\n",
		outPath, hex.EncodeToString(sum[:]), sigPath, cert.Subject.String(), hex.EncodeToString(fp[:]))

	return err
}

// writeImageStatus renders an ImageStatus, human by default like the other
// verbs.
func writeImageStatus(w io.Writer, s *nodev1.ImageStatus, format string) error {
	if format != formatHuman {
		return renderProto(w, s, format)
	}
	if s == nil {
		return nil
	}

	previous := s.GetPreviousSha256()
	if previous == "" {
		previous = "(none retained)"
	}
	pending := "no"
	if s.GetRebootPending() {
		// The one line an operator is actually looking for: the upgrade is
		// installed but is not what the node is running yet.
		pending = "yes -- run 'cryptosctl image activate' to boot it"
	}

	_, err := fmt.Fprintf(w,
		"Running version:  %s\nRunning image:    %s\nNext boot image:  %s\nPrevious image:   %s\nReboot pending:   %s\n",
		s.GetRunningVersion(), s.GetRunningSha256(), s.GetActiveSha256(), previous, pending)

	return err
}
