package grpc

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

// The image upgrade RPCs (#208): replacing a node's CryptOS image without
// re-provisioning it, so an OS change stops being an irreversible ceremony
// that destroys the CA key along with the state partition.
//
// These handlers stay thin, like the rest of this package. Verification, the
// ESP slot choreography and the reboot all live behind ImageUpgrader. What is
// here is the part that belongs at the transport boundary: who may call, what
// a well-formed stream looks like, and how far a caller may be trusted with
// the node's memory before anything has been verified.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
	"github.com/CryptOS-PKI/cryptos-node/internal/reset"
)

// maxImageBytes caps a staged image. A CryptOS UKI carries a kernel plus a
// SquashFS root filesystem and runs to a few hundred megabytes; a gibibyte is
// comfortably above any real build and still a bound.
//
// The bound matters because the image is assembled in memory before it is
// verified. Streaming it straight to the ESP would avoid that, but it would
// also mean writing bytes the node cannot yet attribute -- the exact thing
// staging refuses to do -- so the memory is the price of not touching the disk
// on an unverified transfer.
const maxImageBytes = 1 << 30

// ErrImageNotVerified is returned by an ImageUpgrader's Stage when the
// detached release signature does not check out. The handler maps it to
// InvalidArgument rather than Internal: an image the node cannot attribute is
// the caller's mistake -- most often a build signed with CI's per-run
// ephemeral key instead of the release key -- and nothing on the node is
// wrong.
var ErrImageNotVerified = errors.New("grpc: the image is not signed by the release key")

// ErrImageNotResealable is returned by an ImageUpgrader's Stage when the
// node's state key is bound to the image it boots and the node cannot be sure
// the incoming image would unseal it. The handler maps it to
// FailedPrecondition: the image is fine and nothing was written, but staging
// it would leave the node unable to open its state on the next boot.
var ErrImageNotResealable = errors.New("grpc: the state key cannot be resealed for this image")

// ErrNoPreviousImage is returned by an ImageUpgrader's Rollback when no
// previous image was retained, which is the case on a node that has never been
// upgraded. The handler maps it to FailedPrecondition. It mirrors
// ErrNotExportable and ErrIdentityExists: a package-local sentinel so this
// package need not import the implementation.
var ErrNoPreviousImage = errors.New("grpc: no previous image to roll back to")

// ErrUpgradeInProgress is returned by an ImageUpgrader's Stage, Rollback or
// Activate when another one of those three calls is already running on this
// node. The handler maps it to FailedPrecondition: the request itself is
// fine, but a second call in flight at the same time as a Stage could share
// the write slot (BOOTX64.NEW.EFI) and leave a half-written boot image.
var ErrUpgradeInProgress = errors.New("grpc: an image upgrade call is already in progress on this node")

// ImageUpgrader replaces the node's CryptOS image without touching its
// identity. It is wired on the mTLS and local servers of a running node; the
// maintenance servers leave it nil so the image RPCs return Unimplemented
// there -- a node in maintenance is being installed, which is the path that
// already writes an image.
//
// Stage verifies the detached release signature over image before anything
// reaches the ESP, then makes the new image the one the firmware boots while
// retaining the current one. It does not reboot. Activate owns the CA common
// name compare (constant time, like the resetter's) and the reboot handoff.
// Implemented in internal/init over internal/imageupgrade.
type ImageUpgrader interface {
	Stage(ctx context.Context, image, signature []byte) (*nodev1.ImageStatus, error)
	Rollback(ctx context.Context) (*nodev1.ImageStatus, error)
	Activate(ctx context.Context, confirmCommonName string) error
	Status(ctx context.Context) (*nodev1.ImageStatus, error)
}

// StageImage handles cryptos.node.v1.NodeService/StageImage: it reassembles the
// uploaded image and hands it to the upgrader, which verifies it before
// writing anything.
//
// Authorization happens before the first Recv. Reading the stream first would
// mean letting an unauthorized caller push a few hundred megabytes through the
// node to learn it was never allowed to.
func (s *Server) StageImage(stream grpc.ClientStreamingServer[nodev1.StageImageRequest, nodev1.StageImageResponse]) error {
	if s.cfg.ImageUpgrader == nil {
		return status.Error(codes.Unimplemented, "image upgrade is not available on this server")
	}
	ctx := stream.Context()
	if err := AuthorizeAdmin(ctx, s.cfg.Trust); err != nil {
		return err
	}

	image, signature, err := receiveImage(stream)
	if err != nil {
		return err
	}

	st, err := s.cfg.ImageUpgrader.Stage(ctx, image, signature)
	if err != nil {
		if errors.Is(err, ErrImageNotVerified) {
			return status.Error(codes.InvalidArgument,
				"StageImage: the image is not signed by the release key; nothing was written")
		}
		if errors.Is(err, ErrImageNotResealable) {
			return status.Errorf(codes.FailedPrecondition,
				"StageImage: nothing was written: %v", err)
		}
		if errors.Is(err, ErrUpgradeInProgress) {
			return status.Error(codes.FailedPrecondition,
				"StageImage: another image upgrade call is already in progress on this node")
		}
		return status.Errorf(codes.Internal, "StageImage: %v", err)
	}

	// requires_reboot is unconditional on success rather than read back from
	// the status: staging never reboots, so the node is by definition still
	// running the image it was running before this call.
	return stream.SendAndClose(&nodev1.StageImageResponse{RequiresReboot: true, Status: st})
}

// receiveImage reads the begin header and the chunks that follow it, returning
// the assembled image and its detached signature.
func receiveImage(stream grpc.ClientStreamingServer[nodev1.StageImageRequest, nodev1.StageImageResponse]) (image, signature []byte, err error) {
	first, err := stream.Recv()
	if err != nil {
		return nil, nil, status.Errorf(codes.InvalidArgument, "StageImage: read the begin header: %v", err)
	}
	hdr := first.GetBegin()
	if hdr == nil {
		return nil, nil, status.Error(codes.InvalidArgument, "StageImage: the first message must be the begin header")
	}
	if len(hdr.GetSignature()) == 0 {
		// Cheaper to refuse now than after the upload: without a signature the
		// upgrader would reject the image anyway.
		return nil, nil, status.Error(codes.InvalidArgument, "StageImage: begin.signature is required")
	}
	size := hdr.GetSizeBytes()
	if size == 0 {
		return nil, nil, status.Error(codes.InvalidArgument, "StageImage: begin.size_bytes is required")
	}
	if size > maxImageBytes {
		return nil, nil, status.Errorf(codes.InvalidArgument,
			"StageImage: begin.size_bytes is %d, above the %d byte limit", size, maxImageBytes)
	}

	buf := make([]byte, 0, size)
	for {
		msg, recvErr := stream.Recv()
		if errors.Is(recvErr, io.EOF) {
			break
		}
		if recvErr != nil {
			return nil, nil, status.Errorf(codes.InvalidArgument, "StageImage: read a chunk: %v", recvErr)
		}
		if msg.GetBegin() != nil {
			return nil, nil, status.Error(codes.InvalidArgument, "StageImage: a second begin header in one stream")
		}
		buf = append(buf, msg.GetChunk()...)
		if uint64(len(buf)) > size {
			return nil, nil, status.Errorf(codes.InvalidArgument,
				"StageImage: sent more than the declared %d bytes", size)
		}
	}

	if uint64(len(buf)) != size {
		// A truncated upload and a bad signature are different faults with
		// different fixes, so they get different messages.
		return nil, nil, status.Errorf(codes.InvalidArgument,
			"StageImage: received %d bytes, expected %d", len(buf), size)
	}
	if want := hdr.GetSha256(); want != "" {
		sum := sha256.Sum256(buf)
		if got := hex.EncodeToString(sum[:]); got != want {
			return nil, nil, status.Errorf(codes.InvalidArgument,
				"StageImage: image digest is %s, expected %s", got, want)
		}
	}

	return buf, hdr.GetSignature(), nil
}

// RollbackImage handles cryptos.node.v1.NodeService/RollbackImage: it puts the
// retained previous image back on the boot path. Like staging it does not
// reboot.
func (s *Server) RollbackImage(ctx context.Context, _ *nodev1.RollbackImageRequest) (*nodev1.RollbackImageResponse, error) {
	if s.cfg.ImageUpgrader == nil {
		return nil, status.Error(codes.Unimplemented, "image upgrade is not available on this server")
	}
	if err := AuthorizeAdmin(ctx, s.cfg.Trust); err != nil {
		return nil, err
	}

	st, err := s.cfg.ImageUpgrader.Rollback(ctx)
	if err != nil {
		if errors.Is(err, ErrNoPreviousImage) {
			return nil, status.Error(codes.FailedPrecondition, "RollbackImage: this node has no previous image retained")
		}
		if errors.Is(err, ErrUpgradeInProgress) {
			return nil, status.Error(codes.FailedPrecondition,
				"RollbackImage: another image upgrade call is already in progress on this node")
		}
		return nil, status.Errorf(codes.Internal, "RollbackImage: %v", err)
	}

	return &nodev1.RollbackImageResponse{RequiresReboot: true, Status: st}, nil
}

// ActivateImage handles cryptos.node.v1.NodeService/ActivateImage: it reboots the
// node so a staged image starts running.
//
// It carries the same two guards as RemoteReset, for the same reason. Nothing
// here is destructive -- the state partition is untouched and a rollback
// remains available -- but rebooting an issuing CA takes every dependent
// system's certificate operations down with it, and a reboot triggered by
// accident is indistinguishable from an outage. So: admin authorization, plus
// an echo of the CA common name. The upgrader owns the constant-time compare
// and reports reset.ErrConfirmMismatch on a mismatch (PermissionDenied), or
// reset.ErrNoCAIdentity when the node has no CA CN yet (FailedPrecondition),
// reusing the sentinels from the package that owns that check rather than
// defining a second set for the identical failures.
func (s *Server) ActivateImage(ctx context.Context, req *nodev1.ActivateImageRequest) (*nodev1.ActivateImageResponse, error) {
	if s.cfg.ImageUpgrader == nil {
		return nil, status.Error(codes.Unimplemented, "image upgrade is not available on this server")
	}
	if err := AuthorizeAdmin(ctx, s.cfg.Trust); err != nil {
		return nil, err
	}

	if err := s.cfg.ImageUpgrader.Activate(ctx, req.GetConfirmCaCn()); err != nil {
		if errors.Is(err, reset.ErrNoCAIdentity) {
			return nil, status.Error(codes.FailedPrecondition, "ActivateImage: node has no CA identity yet; confirmation cannot be checked")
		}
		if errors.Is(err, reset.ErrConfirmMismatch) {
			return nil, status.Error(codes.PermissionDenied, "ActivateImage: confirmation CN does not match the CA CN")
		}
		if errors.Is(err, ErrUpgradeInProgress) {
			return nil, status.Error(codes.FailedPrecondition,
				"ActivateImage: another image upgrade call is already in progress on this node")
		}
		return nil, status.Errorf(codes.Internal, "ActivateImage: %v", err)
	}

	return &nodev1.ActivateImageResponse{Rebooting: true}, nil
}

// GetImageStatus handles cryptos.node.v1.NodeService/GetImageStatus. It is read
// only, so it needs no CN echo, but it still names the images a node is
// carrying and so is held to the same admin authorization as the rest.
func (s *Server) GetImageStatus(ctx context.Context, _ *nodev1.GetImageStatusRequest) (*nodev1.GetImageStatusResponse, error) {
	if s.cfg.ImageUpgrader == nil {
		return nil, status.Error(codes.Unimplemented, "image upgrade is not available on this server")
	}
	if err := AuthorizeAdmin(ctx, s.cfg.Trust); err != nil {
		return nil, err
	}

	st, err := s.cfg.ImageUpgrader.Status(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "GetImageStatus: %v", err)
	}

	return &nodev1.GetImageStatusResponse{Status: st}, nil
}
