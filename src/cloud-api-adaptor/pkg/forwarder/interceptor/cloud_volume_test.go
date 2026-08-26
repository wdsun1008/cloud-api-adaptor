// (C) Copyright Confidential Containers Contributors
// SPDX-License-Identifier: Apache-2.0

package interceptor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/confidential-containers/cloud-api-adaptor/src/cloud-api-adaptor/pkg/util"
	pb "github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/agent/protocols/grpc"
	"github.com/moby/sys/mountinfo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestPreparedCloudVolumeCleanupOwnsResourcesIndependently(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "volume")
	require.NoError(t, os.Mkdir(directory, 0o755))
	events := []string{}
	mapperExists := true
	rawReadOnly := true
	adapter := &cryptpilotAdapter{
		run: func(_ context.Context, arguments ...string) ([]byte, error) {
			events = append(events, arguments[0])
			mapperExists = false
			return nil, nil
		},
		mapperExists: func(string) (bool, error) { return mapperExists, nil },
		setReadOnly: func(_ context.Context, _ string, value bool) error {
			events = append(events, "setrw")
			rawReadOnly = value
			return nil
		},
		getReadOnly: func(context.Context, string) (bool, error) { return rawReadOnly, nil },
	}
	volume := &preparedCloudVolume{
		sourcePath: directory, mountedHere: true, createdDirHere: true,
		cryptpilotOwner: adapter,
		cryptpilot: &cryptpilotPreparedDevice{
			path: "/dev/mapper/peerpod-abc", name: "peerpod-abc", rawDevice: "/dev/vdb",
			openedMapperHere: true, setRawReadOnlyHere: true,
		},
		unmount: func(string, int) error {
			events = append(events, "unmount")
			return nil
		},
	}

	require.NoError(t, volume.cleanup(context.Background()))
	assert.Equal(t, []string{"unmount", "close", "setrw"}, events)
	assert.NoDirExists(t, directory)

	// Cleanup is idempotent and performs no second release.
	require.NoError(t, volume.cleanup(context.Background()))
	assert.Equal(t, []string{"unmount", "close", "setrw"}, events)
}

func TestPreparedCloudVolumeDoesNotCloseReusedMapper(t *testing.T) {
	closed := false
	adapter := &cryptpilotAdapter{run: func(context.Context, ...string) ([]byte, error) {
		closed = true
		return nil, nil
	}}
	volume := &preparedCloudVolume{
		cryptpilotOwner: adapter,
		cryptpilot:      &cryptpilotPreparedDevice{name: "reused", path: "/dev/mapper/reused"},
	}
	require.NoError(t, volume.cleanup(context.Background()))
	assert.False(t, closed)
}

func TestPreparedCloudVolumeCDHCleanupOwnsMapperIndependently(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "volume")
	require.NoError(t, os.Mkdir(directory, 0o755))
	events := []string{}
	volume := &preparedCloudVolume{
		sourcePath: directory, mountedHere: true, createdDirHere: true,
		cdhMapperName: "caa-vol-0", cdhMapperPath: "/dev/mapper/caa-vol-0",
		openedCDHMapperHere: true,
		unmount: func(string, int) error {
			events = append(events, "unmount")
			return nil
		},
		closeCDHMapper: func(context.Context, string, string) error {
			events = append(events, "close")
			return nil
		},
	}

	require.NoError(t, volume.cleanup(context.Background()))
	assert.Equal(t, []string{"unmount", "close"}, events)
	assert.NoDirExists(t, directory)
	require.NoError(t, volume.cleanup(context.Background()))
	assert.Equal(t, []string{"unmount", "close"}, events)

	reused := &preparedCloudVolume{
		cdhMapperName: "reused", cdhMapperPath: "/dev/mapper/reused",
		closeCDHMapper: func(context.Context, string, string) error {
			t.Fatal("cleanup closed a mapper that this call did not open")
			return nil
		},
	}
	require.NoError(t, reused.cleanup(context.Background()))
}

func TestPreparedCloudVolumeCleanupRetriesInDependencyOrder(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "volume")
	require.NoError(t, os.Mkdir(directory, 0o755))
	closeCalled := false
	unmountFails := true
	adapter := &cryptpilotAdapter{
		run: func(context.Context, ...string) ([]byte, error) { closeCalled = true; return nil, nil },
		mapperExists: func(string) (bool, error) {
			return !closeCalled, nil
		},
	}
	volume := &preparedCloudVolume{
		sourcePath: directory, mountedHere: true, createdDirHere: true,
		cryptpilotOwner: adapter,
		cryptpilot:      &cryptpilotPreparedDevice{name: "owned", path: "/dev/mapper/owned", openedMapperHere: true},
		unmount: func(string, int) error {
			if unmountFails {
				return errors.New("busy")
			}
			return nil
		},
	}

	assert.ErrorContains(t, volume.cleanup(context.Background()), "busy")
	assert.False(t, closeCalled, "mapper must remain open while its filesystem is mounted")
	assert.DirExists(t, directory)

	unmountFails = false
	require.NoError(t, volume.cleanup(context.Background()))
	assert.True(t, closeCalled)
	assert.NoDirExists(t, directory)
}

func TestCryptpilotRequiredNeverFallsBackToRawDisk(t *testing.T) {
	adapter, _, _ := testCryptpilotAdapter(t)
	i := &interceptor{requireCryptpilot: true, cryptpilot: adapter}
	req := &pb.CreateContainerRequest{OCI: &pb.Spec{Mounts: []*pb.Mount{{Destination: "/data"}}}}
	_, err := i.prepareCloudVolumes(context.Background(), req,
		`{"vol-0":{"mount_point":"/data","fs_type":"ext4","lun":"0","disk_id":"vol-abc","readonly":false}}`)
	assert.ErrorContains(t, err, "requires an Alibaba Cloud disk ID")
}

func TestPreserveOriginalError(t *testing.T) {
	original := errors.New("create container failed")
	assert.Same(t, original, preserveOriginalError(original, nil))
	combined := preserveOriginalError(original, errors.New("cleanup failed"))
	assert.ErrorIs(t, combined, original)
	assert.ErrorContains(t, combined, "cleanup failed")
}

func TestValidateReusableCloudMountRequiresFilesystemRoot(t *testing.T) {
	stat := &unix.Stat_t{Mode: unix.S_IFBLK, Rdev: unix.Mkdev(8, 1)}
	mount := &mountinfo.Info{
		Major: 8, Minor: 1, Root: "/workspace", FSType: "ext4", Options: "rw,relatime",
	}

	err := validateReusableCloudMount("/run/cloud-volumes/vol-0", mount, stat, "ext4", false, nil)
	require.ErrorContains(t, err, "filesystem root")

	mount.Root = "/"
	require.NoError(t, validateReusableCloudMount("/run/cloud-volumes/vol-0", mount, stat, "ext4", false, nil))
}

func TestRewriteCloudMountRejectsDuplicateDestination(t *testing.T) {
	req := &pb.CreateContainerRequest{OCI: &pb.Spec{Mounts: []*pb.Mount{
		{Destination: "/workspace", Source: "/host-controlled"},
		{Destination: "/workspace", Source: "/csi-source"},
	}}}
	volume := util.CloudVolumeAnnotation{MountPoint: "/workspace", ReadOnly: true}

	err := rewriteCloudMount(req, "vol-0", volume, "/run/cloud-volumes/vol-0")
	require.ErrorContains(t, err, "ambiguous")
	assert.Equal(t, "/host-controlled", req.OCI.Mounts[0].Source)
	assert.Equal(t, "/csi-source", req.OCI.Mounts[1].Source)
}

func TestValidateReusableCloudMountRequiresSecurityOptions(t *testing.T) {
	stat := &unix.Stat_t{Mode: unix.S_IFBLK, Rdev: unix.Mkdev(8, 1)}
	mount := &mountinfo.Info{
		Major: 8, Minor: 1, Root: "/", FSType: "ext4",
		Options: "ro,nosuid,nodev,relatime", VFSOptions: "rw",
	}

	require.NoError(t, validateReusableCloudMount(
		"/run/cloud-volumes/vol-0", mount, stat, "ext4", true,
		[]string{"nodev", "nosuid", "ro"},
	))
	err := validateReusableCloudMount(
		"/run/cloud-volumes/vol-0", mount, stat, "ext4", true,
		[]string{"nodev", "nosuid", "noexec", "ro"},
	)
	require.ErrorContains(t, err, "option noexec=false, expected true")
}
