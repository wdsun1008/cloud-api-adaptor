// (C) Copyright Confidential Containers Contributors
// SPDX-License-Identifier: Apache-2.0

package interceptor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/confidential-containers/cloud-api-adaptor/src/cloud-api-adaptor/pkg/util"
	pb "github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/agent/protocols/grpc"
	"github.com/moby/sys/mountinfo"
	"golang.org/x/sys/unix"
)

// preparedCloudVolume tracks only resources acquired by one CreateContainer
// call. Reused mounts and mappers are intentionally not owned by that call.
type preparedCloudVolume struct {
	mu                  sync.Mutex
	sourcePath          string
	mountedHere         bool
	createdDirHere      bool
	cryptpilot          *cryptpilotPreparedDevice
	cryptpilotOwner     *cryptpilotAdapter
	cdhMapperName       string
	cdhMapperPath       string
	openedCDHMapperHere bool
	unmount             func(string, int) error
	closeCDHMapper      func(context.Context, string, string) error
}

func (v *preparedCloudVolume) owned() bool {
	return v != nil && (v.mountedHere || v.createdDirHere ||
		v.openedCDHMapperHere ||
		v.cryptpilot != nil && (v.cryptpilot.openedMapperHere || v.cryptpilot.setRawReadOnlyHere))
}

func (v *preparedCloudVolume) cleanup(ctx context.Context) error {
	if v == nil {
		return nil
	}
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.mountedHere {
		unmount := v.unmount
		if unmount == nil {
			unmount = syscall.Unmount
		}
		if err := unmount(v.sourcePath, 0); err != nil && !errors.Is(err, syscall.EINVAL) && !errors.Is(err, syscall.ENOENT) {
			return fmt.Errorf("unmount %s: %w", v.sourcePath, err)
		}
		v.mountedHere = false
	}
	if v.cryptpilotOwner != nil {
		if err := v.cryptpilotOwner.cleanup(ctx, v.cryptpilot); err != nil {
			return err
		}
	}
	if v.openedCDHMapperHere {
		closeMapper := v.closeCDHMapper
		if closeMapper == nil {
			closeMapper = closeCryptsetupMapper
		}
		if err := closeMapper(ctx, v.cdhMapperName, v.cdhMapperPath); err != nil {
			return err
		}
		v.openedCDHMapperHere = false
	}
	if v.createdDirHere {
		if err := os.Remove(v.sourcePath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove mount directory %s: %w", v.sourcePath, err)
		}
		v.createdDirHere = false
	}
	return nil
}

func cleanupPreparedCloudVolumes(ctx context.Context, volumes []*preparedCloudVolume) error {
	var cleanupErrors []error
	for index := len(volumes) - 1; index >= 0; index-- {
		if err := volumes[index].cleanup(ctx); err != nil {
			cleanupErrors = append(cleanupErrors, err)
		}
	}
	return errors.Join(cleanupErrors...)
}

func preserveOriginalError(original, cleanup error) error {
	if cleanup == nil {
		return original
	}
	return errors.Join(original, fmt.Errorf("rollback cloud volumes: %w", cleanup))
}

func (i *interceptor) trackOwnedCloudVolumes(volumes []*preparedCloudVolume) {
	for _, volume := range volumes {
		if volume.owned() {
			i.cloudVolumes = append(i.cloudVolumes, volume)
		}
	}
}

func (i *interceptor) prepareCloudVolumes(ctx context.Context, req *pb.CreateContainerRequest, encoded string) ([]*preparedCloudVolume, error) {
	volumes, err := util.DecodeCloudVolumeAnnotations(encoded)
	if err != nil {
		return nil, fmt.Errorf("corrupt cloud_volumes annotation (pod would start without volumes): %w", err)
	}
	var cryptpilot *cryptpilotAdapter
	if i.requireCryptpilot && len(volumes) != 0 {
		if i.cryptpilot == nil {
			policy, err := loadCryptpilotPolicy(cryptpilotInitdataPath)
			if err != nil {
				return nil, fmt.Errorf("CryptPilot is required: %w", err)
			}
			i.cryptpilot = newCryptpilotAdapter(policy)
		}
		cryptpilot = i.cryptpilot
	}

	names := make([]string, 0, len(volumes))
	for name := range volumes {
		names = append(names, name)
	}
	sort.Strings(names)
	prepared := make([]*preparedCloudVolume, 0, len(names))
	for _, name := range names {
		volume, err := prepareCloudVolume(ctx, name, volumes[name], cryptpilot)
		if volume != nil {
			prepared = append(prepared, volume)
		}
		if err != nil {
			return prepared, preserveOriginalError(err, cleanupPreparedCloudVolumes(ctx, prepared))
		}
		if err := rewriteCloudMount(req, name, volumes[name], volume.sourcePath); err != nil {
			return prepared, preserveOriginalError(err, cleanupPreparedCloudVolumes(ctx, prepared))
		}
	}
	return prepared, nil
}

func prepareCloudVolume(ctx context.Context, name string, volume util.CloudVolumeAnnotation, cryptpilot *cryptpilotAdapter) (*preparedCloudVolume, error) {
	lun, _ := strconv.Atoi(volume.LUN) // validated by DecodeCloudVolumeAnnotations
	if cryptpilot != nil && !alibabaDiskIDPattern.MatchString(volume.DiskID) {
		return nil, fmt.Errorf("cloud volume %s: CryptPilot requires an Alibaba Cloud disk ID", name)
	}
	device, err := findDataDiskDevice(lun, volume.DiskID)
	if err != nil {
		return nil, fmt.Errorf("cloud volume %s device discovery: %w", name, err)
	}

	if err := os.MkdirAll(cloudVolumeMountBase, 0o755); err != nil {
		return nil, fmt.Errorf("create cloud volume directory: %w", err)
	}
	prepared := &preparedCloudVolume{sourcePath: filepath.Join(cloudVolumeMountBase, name), cryptpilotOwner: cryptpilot}
	if err := os.Mkdir(prepared.sourcePath, 0o755); err == nil {
		prepared.createdDirHere = true
	} else if !errors.Is(err, os.ErrExist) {
		return prepared, fmt.Errorf("create mount point for %s: %w", name, err)
	} else if info, statErr := os.Lstat(prepared.sourcePath); statErr != nil || !info.IsDir() {
		if statErr != nil {
			err = statErr
		} else {
			err = fmt.Errorf("existing path is not a directory")
		}
		return prepared, fmt.Errorf("use mount point for %s: %w", name, err)
	}

	mountDevice := device
	if cryptpilot != nil {
		prepared.cryptpilot, err = cryptpilot.prepare(ctx, volume.DiskID, device, volume.FSType, volume.ReadOnly)
		if err != nil {
			return prepared, fmt.Errorf("prepare encrypted cloud volume %s: %w", name, err)
		}
		mountDevice = prepared.cryptpilot.path
	} else if volume.EncryptType != "" {
		if err := prepareCDHCloudVolume(ctx, prepared, name, device, volume); err != nil {
			return prepared, err
		}
		if err := applyCloudVolumeFSGroup(prepared.sourcePath, name, volume); err != nil {
			return prepared, err
		}
		return prepared, nil
	}
	prepared.mountedHere, err = formatAndMount(mountDevice, prepared.sourcePath, volume.FSType, volume.ReadOnly, volume.Options)
	if err != nil {
		return prepared, fmt.Errorf("mount cloud volume %s: %w", name, err)
	}
	if err := applyCloudVolumeFSGroup(prepared.sourcePath, name, volume); err != nil {
		return prepared, err
	}
	return prepared, nil
}

func applyCloudVolumeFSGroup(path, name string, volume util.CloudVolumeAnnotation) error {
	if volume.FSGroup == "" || volume.ReadOnly {
		return nil
	}
	gid, _ := strconv.ParseUint(volume.FSGroup, 10, 32) // validated by DecodeCloudVolumeAnnotations
	if err := os.Chown(path, -1, int(gid)); err != nil {
		return fmt.Errorf("apply fsGroup to %s: %w", name, err)
	}
	if err := os.Chmod(path, 0o2775); err != nil {
		return fmt.Errorf("apply fsGroup mode to %s: %w", name, err)
	}
	return nil
}

func prepareCDHCloudVolume(ctx context.Context, prepared *preparedCloudVolume, name, device string, volume util.CloudVolumeAnnotation) error {
	prepared.cdhMapperName = "caa-" + name
	prepared.cdhMapperPath = filepath.Join("/dev/mapper", prepared.cdhMapperName)
	mapperExisted, err := blockDeviceExists(prepared.cdhMapperPath)
	if err != nil {
		return fmt.Errorf("inspect CDH mapper for %s: %w", name, err)
	}
	if mapperExisted {
		mounted, err := mountedCloudDevice(prepared.cdhMapperPath, prepared.sourcePath, volume.FSType, volume.ReadOnly, volume.Options)
		if err != nil {
			return err
		}
		if mounted {
			if volume.ReadOnly {
				readOnly, err := blockDeviceReadOnly(ctx, prepared.cdhMapperPath)
				if err != nil {
					return err
				}
				if !readOnly {
					return fmt.Errorf("reused CDH mapper for %s is writable after a readonly request", name)
				}
			}
			return nil
		}
	} else if mounted, err := mountinfo.Mounted(prepared.sourcePath); err != nil {
		return fmt.Errorf("inspect mount point for %s: %w", name, err)
	} else if mounted {
		return fmt.Errorf("mount point for %s is already backed by an unexpected device", name)
	}

	// Claim only a mapper that was absent before this request. Observing the
	// resource again after SecureMount handles an applied-but-unreported RPC.
	prepared.openedCDHMapperHere = !mapperExisted
	secureErr := secureMount(ctx, device, prepared.sourcePath, volume.FSType,
		volume.EncryptType, volume.KeyID, prepared.cdhMapperName, volume.ReadOnly, volume.Options)
	mapperExists, statErr := blockDeviceExists(prepared.cdhMapperPath)
	if statErr != nil {
		return errors.Join(secureErr, statErr)
	}
	if !mapperExists {
		prepared.openedCDHMapperHere = false
	}
	if mapperExists {
		mounted, mountErr := mountedCloudDevice(prepared.cdhMapperPath, prepared.sourcePath, volume.FSType, volume.ReadOnly, volume.Options)
		if mountErr != nil {
			return errors.Join(secureErr, mountErr)
		}
		prepared.mountedHere = mounted
	}
	if secureErr != nil {
		return fmt.Errorf("secure-mount cloud volume %s: %w", name, secureErr)
	}
	if !mapperExists || !prepared.mountedHere {
		return fmt.Errorf("CDH did not prepare the expected mapper and mount for %s", name)
	}
	if volume.ReadOnly {
		readOnly, err := blockDeviceReadOnly(ctx, prepared.cdhMapperPath)
		if err != nil {
			return err
		}
		if !readOnly {
			return fmt.Errorf("CDH mapper for %s is writable after a readonly request", name)
		}
	}
	return nil
}

func closeCryptsetupMapper(ctx context.Context, name, path string) error {
	exists, err := blockDeviceExists(path)
	if err != nil || !exists {
		return err
	}
	output, closeErr := exec.CommandContext(ctx, "cryptsetup", "close", name).CombinedOutput()
	exists, statErr := blockDeviceExists(path)
	if statErr != nil {
		return errors.Join(closeErr, statErr)
	}
	if closeErr != nil && exists {
		return fmt.Errorf("close CDH mapper %s: %s: %w", name, strings.TrimSpace(string(output)), closeErr)
	}
	if exists {
		return fmt.Errorf("CDH mapper %s remains open after close", name)
	}
	return nil
}

func rewriteCloudMount(req *pb.CreateContainerRequest, name string, volume util.CloudVolumeAnnotation, source string) error {
	matched := -1
	for index, mount := range req.OCI.Mounts {
		if mount.Destination != volume.MountPoint {
			continue
		}
		if matched >= 0 {
			return fmt.Errorf("cloud volume %s mount point %q is ambiguous in container mounts", name, volume.MountPoint)
		}
		matched = index
	}
	if matched < 0 {
		return fmt.Errorf("cloud volume %s mount point %q is absent from container mounts", name, volume.MountPoint)
	}
	mount := req.OCI.Mounts[matched]
	mount.Source = source
	mount.Type = "bind"
	mount.Options = normalizeBindMountOptions(mount.Options, volume.ReadOnly)
	return nil
}

// mountedCloudDevice rejects reuse of a mount point backed by a different
// device, filesystem, or access mode.
func mountedCloudDevice(device, mountPoint, fsType string, readOnly bool, options []string) (bool, error) {
	resolved, err := filepath.EvalSymlinks(mountPoint)
	if err != nil {
		return false, err
	}
	mounts, err := mountinfo.GetMounts(func(info *mountinfo.Info) (skip, stop bool) {
		return info.Mountpoint != resolved, false
	})
	if err != nil || len(mounts) == 0 {
		return false, err
	}
	mount := mounts[len(mounts)-1]
	var stat unix.Stat_t
	if err := unix.Stat(device, &stat); err != nil {
		return false, fmt.Errorf("stat mounted device %s: %w", device, err)
	}
	if err := validateReusableCloudMount(mountPoint, mount, &stat, fsType, readOnly, options); err != nil {
		return false, err
	}
	return true, nil
}

func validateReusableCloudMount(mountPoint string, mount *mountinfo.Info, stat *unix.Stat_t, fsType string, readOnly bool, options []string) error {
	if mount.Root != "/" {
		return fmt.Errorf("mount point %s exposes filesystem root %q, expected /", mountPoint, mount.Root)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFBLK || mount.Major != int(unix.Major(uint64(stat.Rdev))) ||
		mount.Minor != int(unix.Minor(uint64(stat.Rdev))) || mount.FSType != fsType {
		return fmt.Errorf("mount point %s is backed by an unexpected device or filesystem", mountPoint)
	}
	actual := make(map[string]bool)
	for _, option := range strings.Split(mount.Options+","+mount.VFSOptions, ",") {
		actual[option] = true
	}
	expected := map[string]bool{"ro": readOnly, "nodev": false, "noexec": false, "nosuid": false}
	for _, option := range options {
		if _, tracked := expected[option]; tracked {
			expected[option] = true
		}
	}
	for _, option := range []string{"ro", "nodev", "noexec", "nosuid"} {
		if actual[option] != expected[option] {
			return fmt.Errorf("mount point %s option %s=%t, expected %t", mountPoint, option, actual[option], expected[option])
		}
	}
	return nil
}
