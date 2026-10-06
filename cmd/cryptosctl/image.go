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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
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
