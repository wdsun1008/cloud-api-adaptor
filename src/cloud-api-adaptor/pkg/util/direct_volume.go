// (C) Copyright Confidential Containers Contributors
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"bytes"
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	provider "github.com/confidential-containers/cloud-api-adaptor/src/cloud-providers"
	"golang.org/x/sys/unix"
)

const (
	DirectVolumeMetadataVersion = 1
	MaxDirectVolumeMetadataSize = 64 * 1024
	MaxDirectVolumesPerPod      = 64
)

// DirectVolumeMountInfo mirrors the versioned mountInfo.json contract written
// by caa-csi-block-driver. Readonly remains explicit rather than being inferred
// later from a runtime-specific bind mount.
type DirectVolumeMountInfo struct {
	Version      int               `json:"version"`
	VolumeType   string            `json:"volume-type"`
	VolumeMode   string            `json:"volume-mode"`
	Device       string            `json:"device"`
	FsType       string            `json:"fstype"`
	ReadOnly     bool              `json:"readonly"`
	Options      []string          `json:"options,omitempty"`
	FSGroup      string            `json:"fs-group,omitempty"`
	PodUID       string            `json:"pod-uid"`
	VolumeHandle string            `json:"volume-handle"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// DirectVolumeResolution is the immutable result of resolving one Pod's CSI
// direct-volume metadata. Its fields remain private so later container requests
// can consume the original attachment decision without mutating or reparsing it.
type DirectVolumeResolution struct {
	volumes  []CloudVolumeAnnotation
	bySource map[string]int
}

type directVolumeMountInfoWire struct {
	DirectVolumeMountInfo
	ReadOnly *bool `json:"readonly"`
}

var KataDirectVolumesDir = "/run/kata-containers/shared/direct-volumes"

const CSIPluginEscapeQualifiedName = "kubernetes.io~csi"

const CloudVolumesAnnotationKey = "io.confidentialcontainers.org.cloud_volumes"

// CloudVolumeAnnotation is the schema for each entry in the cloud_volumes
// annotation. It is serialized by the proxy and deserialized by the interceptor.
type CloudVolumeAnnotation struct {
	MountPoint  string   `json:"mount_point"`
	FSType      string   `json:"fs_type"`
	LUN         string   `json:"lun"`
	DiskID      string   `json:"disk_id"`
	ReadOnly    bool     `json:"readonly"`
	Options     []string `json:"options,omitempty"`
	FSGroup     string   `json:"fs_group,omitempty"`
	EncryptType string   `json:"encrypt_type,omitempty"`
	KeyID       string   `json:"key_id,omitempty"`
}

type cloudVolumeAnnotationWire struct {
	CloudVolumeAnnotation
	ReadOnly *bool `json:"readonly"`
}

func decodeStrictJSON(data []byte, value interface{}) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("unexpected trailing JSON value")
		}
		return err
	}
	return nil
}

// DecodeCloudVolumeAnnotations validates the host-provided annotation before
// the guest uses it to select, format, or mount a block device.
func DecodeCloudVolumeAnnotations(data string) (map[string]CloudVolumeAnnotation, error) {
	if len(data) > MaxDirectVolumeMetadataSize*MaxDirectVolumesPerPod {
		return nil, errors.New("cloud_volumes annotation is too large")
	}
	var encoded map[string]json.RawMessage
	if err := json.Unmarshal([]byte(data), &encoded); err != nil {
		return nil, err
	}
	if len(encoded) > MaxDirectVolumesPerPod {
		return nil, fmt.Errorf("cloud_volumes annotation exceeds %d volumes", MaxDirectVolumesPerPod)
	}

	result := make(map[string]CloudVolumeAnnotation, len(encoded))
	seenDisks := make(map[string]struct{}, len(encoded))
	seenLUNs := make(map[int]struct{}, len(encoded))
	seenTargets := make(map[string]struct{}, len(encoded))
	for name, raw := range encoded {
		if !strings.HasPrefix(name, "vol-") {
			return nil, fmt.Errorf("cloud volume %q has an invalid key", name)
		}
		index, err := strconv.Atoi(strings.TrimPrefix(name, "vol-"))
		if err != nil || index < 0 || index >= MaxDirectVolumesPerPod || name != "vol-"+strconv.Itoa(index) {
			return nil, fmt.Errorf("cloud volume %q has an invalid key", name)
		}

		var wire cloudVolumeAnnotationWire
		if err := decodeStrictJSON(raw, &wire); err != nil {
			return nil, fmt.Errorf("cloud volume %s: %w", name, err)
		}
		if wire.ReadOnly == nil {
			return nil, fmt.Errorf("cloud volume %s has no explicit readonly field", name)
		}
		volume := wire.CloudVolumeAnnotation
		volume.ReadOnly = *wire.ReadOnly
		if !filepath.IsAbs(volume.MountPoint) || filepath.Clean(volume.MountPoint) != volume.MountPoint {
			return nil, fmt.Errorf("cloud volume %s has invalid mount_point %q", name, volume.MountPoint)
		}
		if strings.TrimSpace(volume.DiskID) == "" || strings.TrimSpace(volume.DiskID) != volume.DiskID {
			return nil, fmt.Errorf("cloud volume %s has invalid disk_id", name)
		}
		if !allowedDirectVolumeFSType(volume.FSType) {
			return nil, fmt.Errorf("cloud volume %s has unsupported filesystem type %q", name, volume.FSType)
		}
		lun, err := strconv.Atoi(volume.LUN)
		if err != nil || lun != index || volume.LUN != strconv.Itoa(lun) {
			return nil, fmt.Errorf("cloud volume %s has invalid lun %q", name, volume.LUN)
		}
		options, readOnly, err := NormalizeDirectVolumeOptions(volume.Options, volume.ReadOnly)
		if err != nil {
			return nil, fmt.Errorf("cloud volume %s has invalid mount options: %w", name, err)
		}
		volume.Options = options
		volume.ReadOnly = readOnly
		if err := validateFSGroup(volume.FSGroup); err != nil {
			return nil, fmt.Errorf("cloud volume %s has invalid fs_group: %w", name, err)
		}
		if _, exists := seenDisks[volume.DiskID]; exists {
			return nil, fmt.Errorf("cloud volume %s duplicates disk_id %q", name, volume.DiskID)
		}
		if _, exists := seenLUNs[lun]; exists {
			return nil, fmt.Errorf("cloud volume %s duplicates lun %d", name, lun)
		}
		if _, exists := seenTargets[volume.MountPoint]; exists {
			return nil, fmt.Errorf("cloud volume %s duplicates mount_point %q", name, volume.MountPoint)
		}
		seenDisks[volume.DiskID] = struct{}{}
		seenLUNs[lun] = struct{}{}
		seenTargets[volume.MountPoint] = struct{}{}
		result[name] = volume
	}
	return result, nil
}

func ReadDirectVolumeMountInfo(path string) (*DirectVolumeMountInfo, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, errors.New("direct-volume metadata is not a regular file")
	}
	if stat.Size < 0 || stat.Size > MaxDirectVolumeMetadataSize {
		return nil, fmt.Errorf("direct-volume metadata exceeds %d bytes", MaxDirectVolumeMetadataSize)
	}

	data, err := io.ReadAll(io.LimitReader(file, MaxDirectVolumeMetadataSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxDirectVolumeMetadataSize {
		return nil, fmt.Errorf("direct-volume metadata exceeds %d bytes", MaxDirectVolumeMetadataSize)
	}
	var wire directVolumeMountInfoWire
	if err := decodeStrictJSON(data, &wire); err != nil {
		return nil, err
	}
	if wire.ReadOnly == nil {
		return nil, errors.New("direct-volume metadata has no explicit readonly field")
	}
	info := wire.DirectVolumeMountInfo
	info.ReadOnly = *wire.ReadOnly
	if err := validateDirectVolumeMountInfo(&info); err != nil {
		return nil, err
	}
	return &info, nil
}

func validateDirectVolumeMountInfo(info *DirectVolumeMountInfo) error {
	if info.Version != DirectVolumeMetadataVersion || info.VolumeType != "block" || info.VolumeMode != "filesystem" {
		return errors.New("direct-volume metadata has an invalid v1 schema")
	}
	for name, value := range map[string]string{
		"device": info.Device, "pod-uid": info.PodUID, "volume-handle": info.VolumeHandle,
	} {
		if strings.TrimSpace(value) == "" || strings.TrimSpace(value) != value {
			return fmt.Errorf("direct-volume metadata has an invalid %s", name)
		}
	}
	if !allowedDirectVolumeFSType(info.FsType) {
		return fmt.Errorf("direct-volume metadata has unsupported filesystem type %q", info.FsType)
	}
	options, readOnly, err := NormalizeDirectVolumeOptions(info.Options, info.ReadOnly)
	if err != nil {
		return fmt.Errorf("direct-volume metadata has invalid mount options: %w", err)
	}
	info.Options = options
	info.ReadOnly = readOnly
	if err := validateFSGroup(info.FSGroup); err != nil {
		return fmt.Errorf("direct-volume metadata has invalid fs-group: %w", err)
	}
	return nil
}

func allowedDirectVolumeFSType(fsType string) bool {
	return fsType == "ext4" || fsType == "ext3" || fsType == "xfs"
}

func validateFSGroup(fsGroup string) error {
	if fsGroup == "" {
		return nil
	}
	value, err := strconv.ParseUint(fsGroup, 10, 32)
	if err != nil || strconv.FormatUint(value, 10) != fsGroup {
		return fmt.Errorf("invalid value %q", fsGroup)
	}
	return nil
}

// NormalizeDirectVolumeOptions validates the narrow filesystem option set in
// the CSI v1 contract and returns its canonical ordering.
func NormalizeDirectVolumeOptions(values []string, readOnly bool) ([]string, bool, error) {
	allowed := map[string]bool{
		"async": true, "atime": true, "defaults": true, "diratime": true,
		"dev": true, "dirsync": true, "discard": true, "exec": true,
		"lazytime": true, "noatime": true, "nodev": true, "nodiratime": true,
		"noexec": true, "nosuid": true, "relatime": true, "ro": true,
		"rw": true, "strictatime": true, "suid": true, "sync": true,
	}
	conflictGroup := map[string]string{
		"ro": "access", "rw": "access", "sync": "io", "async": "io",
		"atime": "atime", "noatime": "atime", "relatime": "atime", "strictatime": "atime",
		"diratime": "diratime", "nodiratime": "diratime", "exec": "exec", "noexec": "exec",
		"dev": "dev", "nodev": "dev", "suid": "suid", "nosuid": "suid",
	}
	seen := make(map[string]struct{}, len(values)+1)
	selected := make(map[string]string)
	options := make([]string, 0, len(values)+1)
	for _, value := range values {
		option := strings.ToLower(strings.TrimSpace(value))
		if option == "" {
			continue
		}
		if strings.ContainsAny(option, " ,\t\r\n") || !allowed[option] {
			return nil, false, fmt.Errorf("mount option %q is not allowed", value)
		}
		if group := conflictGroup[option]; group != "" {
			if previous := selected[group]; previous != "" && previous != option {
				return nil, false, fmt.Errorf("mount options %q and %q conflict", previous, option)
			}
			selected[group] = option
		}
		if option == "ro" {
			readOnly = true
		}
		if _, exists := seen[option]; exists {
			continue
		}
		seen[option] = struct{}{}
		options = append(options, option)
	}
	if readOnly {
		if _, exists := seen["rw"]; exists {
			return nil, false, errors.New("readonly volume conflicts with mount option \"rw\"")
		}
		if _, exists := seen["ro"]; !exists {
			options = append(options, "ro")
		}
	}
	sort.Strings(options)
	return options, readOnly, nil
}

// CSINodePublishVolumePodUID recognizes only canonical kubelet CSI filesystem
// target paths and returns the owning pod UID.
func CSINodePublishVolumePodUID(volumePath string) (string, bool) {
	cleanPath := filepath.Clean(volumePath)
	if !filepath.IsAbs(volumePath) || cleanPath != volumePath {
		return "", false
	}
	parts := strings.Split(cleanPath, string(filepath.Separator))
	for index := 0; index+5 < len(parts); index++ {
		if parts[index] == "pods" && parts[index+1] != "" &&
			parts[index+2] == "volumes" && parts[index+3] == CSIPluginEscapeQualifiedName &&
			parts[index+4] != "" && parts[index+5] == "mount" && index+6 == len(parts) {
			return parts[index+1], true
		}
	}
	return "", false
}

// ResolveCSIVolumesForPod scans and validates the CSI metadata exactly once for
// a logical CreateVM operation. CreateVM does not currently carry the CRI pod
// UID, so lookupPodUID is invoked lazily and at most once when a direct volume
// is present. The returned resolution preserves this attachment order for
// every later CreateContainer request in the sandbox.
func ResolveCSIVolumesForPod(podUID string, lookupPodUID func() (string, error)) (*DirectVolumeResolution, error) {
	resolution := &DirectVolumeResolution{bySource: make(map[string]int)}
	seenDisks := make(map[string]struct{})

	entries, err := os.ReadDir(KataDirectVolumesDir)
	if errors.Is(err, os.ErrNotExist) {
		return resolution, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read CSI direct-volume directory: %w", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		decodedPath, err := b64.URLEncoding.DecodeString(entry.Name())
		if err != nil {
			continue
		}
		decodedStr := string(decodedPath)
		entryPodUID, isCSIVolume := CSINodePublishVolumePodUID(decodedStr)
		if !isCSIVolume {
			continue
		}
		if podUID == "" {
			if lookupPodUID == nil {
				return nil, errors.New("pod UID lookup is required for CSI direct volumes")
			}
			podUID, err = lookupPodUID()
			if err != nil {
				return nil, fmt.Errorf("look up pod UID: %w", err)
			}
			if podUID == "" {
				return nil, errors.New("pod UID lookup returned an empty UID")
			}
		}
		if entryPodUID != podUID {
			continue
		}
		if _, exists := resolution.bySource[decodedStr]; exists {
			continue
		}

		mountInfoPath := filepath.Join(KataDirectVolumesDir, entry.Name(), "mountInfo.json")
		info, err := ReadDirectVolumeMountInfo(mountInfoPath)
		if err != nil {
			return nil, fmt.Errorf("parse CSI mount info for %s: %w", decodedStr, err)
		}
		if info.PodUID != podUID {
			return nil, fmt.Errorf("CSI mount info for %s has pod UID %q, expected %q", decodedStr, info.PodUID, podUID)
		}

		volPath := info.Device
		if info.Metadata != nil {
			if cp, ok := info.Metadata["cloud-volume-path"]; ok && cp != "" {
				volPath = cp
			}
		}

		if strings.TrimSpace(volPath) == "" || strings.TrimSpace(volPath) != volPath {
			return nil, fmt.Errorf("CSI mount info for %s has invalid disk ID", decodedStr)
		}
		if _, exists := seenDisks[volPath]; exists {
			return nil, fmt.Errorf("CSI mount info for %s duplicates disk ID %q", decodedStr, volPath)
		}
		if len(resolution.volumes) >= MaxDirectVolumesPerPod {
			return nil, fmt.Errorf("pod %s exceeds %d direct volumes", podUID, MaxDirectVolumesPerPod)
		}
		index := len(resolution.volumes)
		seenDisks[volPath] = struct{}{}
		resolution.bySource[decodedStr] = index
		resolution.volumes = append(resolution.volumes, CloudVolumeAnnotation{
			FSType:      info.FsType,
			LUN:         strconv.Itoa(index),
			DiskID:      volPath,
			ReadOnly:    info.ReadOnly,
			Options:     info.Options,
			FSGroup:     info.FSGroup,
			EncryptType: info.Metadata["encrypt-type"],
			KeyID:       info.Metadata["kbs-key-id"],
		})
	}

	return resolution, nil
}

// ProviderVolumes returns a fresh, provider-facing attachment slice. It
// intentionally exposes only the existing CloudVolume DiskID contract.
func (r *DirectVolumeResolution) ProviderVolumes() []provider.CloudVolume {
	if r == nil || len(r.volumes) == 0 {
		return nil
	}
	volumes := make([]provider.CloudVolume, len(r.volumes))
	for index, volume := range r.volumes {
		volumes[index] = provider.CloudVolume{DiskID: volume.DiskID}
	}
	return volumes
}

// CloudVolumeForMount returns a copy of the cached guest annotation for one
// exact OCI source. The destination is container-specific and therefore is the
// only value supplied after CreateVM.
func (r *DirectVolumeResolution) CloudVolumeForMount(source, destination string) (string, CloudVolumeAnnotation, bool) {
	if r == nil {
		return "", CloudVolumeAnnotation{}, false
	}
	index, ok := r.bySource[source]
	if !ok {
		return "", CloudVolumeAnnotation{}, false
	}
	volume := r.volumes[index]
	volume.Options = append([]string(nil), volume.Options...)
	volume.MountPoint = destination
	return "vol-" + strconv.Itoa(index), volume, true
}
