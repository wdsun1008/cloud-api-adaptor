// Copyright Confidential Containers Contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net"

	"github.com/confidential-containers/cloud-api-adaptor/src/cloud-api-adaptor/pkg/util"
	"github.com/confidential-containers/cloud-api-adaptor/src/cloud-api-adaptor/pkg/util/agentproto"
	pb "github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/agent/protocols/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

type proxyService struct {
	agentproto.Redirector
	pauseImage    string
	directVolumes *util.DirectVolumeResolution
}

const (
	defaultPauseImage     = "registry.k8s.io/pause:3.7"
	imageGuestPull        = "image_guest_pull"
	cdiAnnotationKey      = "cdi.k8s.io/peer-pods"
	defaultCDIType        = "nvidia.com/gpu=all"
	defaultGPUsAnnotation = "io.katacontainers.config.hypervisor.default_gpus"
)

func newProxyService(dialer func(context.Context) (net.Conn, error), pauseImage string, directVolumes *util.DirectVolumeResolution) *proxyService {

	redirector := agentproto.NewRedirector(dialer)

	return &proxyService{
		Redirector:    redirector,
		pauseImage:    pauseImage,
		directVolumes: directVolumes,
	}
}

// AgentServiceService methods

func (s *proxyService) CreateContainer(ctx context.Context, req *pb.CreateContainerRequest) (*emptypb.Empty, error) {
	var pullImageInGuest bool
	logger.Printf("CreateContainer: containerID:%s", req.ContainerId)
	if err := ctx.Err(); err != nil {
		logger.Printf("CreateContainer cancelled before forwarding: %v", err)
		return nil, err
	}
	if req.OCI.Annotations == nil {
		req.OCI.Annotations = make(map[string]string)
	}
	// The reserved annotation is always derived from the immutable CreateVM
	// resolution; never accept a caller-provided value for it.
	delete(req.OCI.Annotations, util.CloudVolumesAnnotationKey)

	logger.Printf("CreateContainer request shape: mounts=%d annotations=%d storages=%d devices=%d",
		len(req.OCI.Mounts), len(req.OCI.Annotations), len(req.Storages), len(req.Devices))

	if len(req.Storages) > 0 {
		for _, s := range req.Storages {
			// remote-snapshotter in contanerd appends image_guest_pull drivers for image layer will be pulled in guest.
			// Image will be pull in guest via image-rs according to the driver info.
			if s.Driver == imageGuestPull {
				pullImageInGuest = true
			}
		}
	}
	if req.OCI.Annotations != nil && req.OCI.Annotations[defaultGPUsAnnotation] != "" {
		req.OCI.Annotations[cdiAnnotationKey] = defaultCDIType
		logger.Printf("adding CDI annotation %s: %s", cdiAnnotationKey, defaultCDIType)
	}

	if !pullImageInGuest {
		logger.Printf("Pulling image separately not support on main. It is required to use the nydus-snapshotter, which isn't configured properly here.")
	}

	// Match container-specific destinations against the immutable resolution
	// captured before the PodVM attachment request. A container may use any
	// subset, but it cannot introduce an unresolvable CSI source.
	cloudVolumes := make(map[string]util.CloudVolumeAnnotation)
	for _, mount := range req.OCI.Mounts {
		_, canonical := util.CSINodePublishVolumePodUID(mount.Source)
		if !canonical {
			continue
		}
		if s.directVolumes == nil {
			return nil, fmt.Errorf("CSI direct-volume source %s has no sandbox resolution", mount.Source)
		}
		name, volume, ok := s.directVolumes.CloudVolumeForMount(mount.Source, mount.Destination)
		if !ok {
			return nil, fmt.Errorf("CSI direct-volume source %s is absent from the sandbox resolution", mount.Source)
		}
		if _, duplicate := cloudVolumes[name]; duplicate {
			return nil, fmt.Errorf("CSI direct-volume source %s is mounted more than once", mount.Source)
		}
		cloudVolumes[name] = volume
		logger.Printf("Resolved cloud volume %s (lun=%s, fs=%s, readonly=%t)", name, volume.LUN, volume.FSType, volume.ReadOnly)
	}

	if len(cloudVolumes) > 0 {
		cvJSON, err := json.Marshal(cloudVolumes)
		if err != nil {
			return nil, fmt.Errorf("marshal cloud_volumes annotation: %w", err)
		}
		req.OCI.Annotations[util.CloudVolumesAnnotationKey] = string(cvJSON)
		logger.Printf("Set cloud_volumes annotation for %d volume(s)", len(cloudVolumes))
	}

	res, err := s.Redirector.CreateContainer(ctx, req)

	if err != nil {
		logger.Printf("CreateContainer fails: %v", err)
	}

	return res, err
}

func (s *proxyService) SetPolicy(ctx context.Context, req *pb.SetPolicyRequest) (*emptypb.Empty, error) {

	logger.Printf("SetPolicy: policy bytes:%d", len(req.Policy))

	res, err := s.Redirector.SetPolicy(ctx, req)

	if err != nil {
		logger.Printf("SetPolicy fails: %v", err)
	}

	return res, err
}

func (s *proxyService) StartContainer(ctx context.Context, req *pb.StartContainerRequest) (*emptypb.Empty, error) {

	logger.Printf("StartContainer: containerID:%s", req.ContainerId)

	res, err := s.Redirector.StartContainer(ctx, req)

	if err != nil {
		logger.Printf("StartContainer fails: %v", err)
	}

	return res, err
}

func (s *proxyService) RemoveContainer(ctx context.Context, req *pb.RemoveContainerRequest) (*emptypb.Empty, error) {

	logger.Printf("RemoveContainer: containerID:%s", req.ContainerId)

	res, err := s.Redirector.RemoveContainer(ctx, req)

	if err != nil {
		logger.Printf("RemoveContainer fails: %v", err)
	}

	return res, err
}

func (s *proxyService) CreateSandbox(ctx context.Context, req *pb.CreateSandboxRequest) (*emptypb.Empty, error) {

	logger.Printf("CreateSandbox: hostname:%s sandboxId:%s", req.Hostname, req.SandboxId)

	if len(req.Storages) > 0 {
		logger.Printf("CreateSandbox request shape: storages=%d", len(req.Storages))
	}

	res, err := s.Redirector.CreateSandbox(ctx, req)

	if err != nil {
		logger.Printf("CreateSandbox fails: %v", err)
	}

	return res, err
}

func (s *proxyService) DestroySandbox(ctx context.Context, req *pb.DestroySandboxRequest) (*emptypb.Empty, error) {

	logger.Printf("DestroySandbox")

	res, err := s.Redirector.DestroySandbox(ctx, req)

	if err != nil {
		logger.Printf("DestroySandbox fails: %v", err)
	}

	return res, err
}
