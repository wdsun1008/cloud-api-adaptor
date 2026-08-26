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
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/moby/sys/mountinfo"
)

var (
	alibabaDiskIDPattern      = regexp.MustCompile(`^d-[A-Za-z0-9]+$`)
	alibabaDiskIDInIdentity   = regexp.MustCompile(`(?:^|[^a-z0-9])d[-_]([a-z0-9]+)(?:$|[^a-z0-9])`)
	unsupportedBlockNameStart = regexp.MustCompile(`^(loop|dm-|md|ram|zram|sr|fd)`)
	errAlibabaDiskIDInvalid   = errors.New("invalid Alibaba Cloud disk identity")
	errAlibabaDiskNotFound    = errors.New("Alibaba Cloud disk is not visible")
	errAlibabaDiskAmbiguous   = errors.New("Alibaba Cloud disk identity is ambiguous")
)

type alibabaDeviceLocator struct {
	sysBlockRoot   string
	deviceRoot     string
	byIDRoot       string
	isSystemDisk   func(string) bool
	udevProperties func(string) (map[string]string, error)
}

func normalizeAlibabaDiskID(value string) string {
	return strings.TrimPrefix(strings.ToLower(strings.Trim(value, " \t\r\n\x00")), "d-")
}

func identityMatchesAlibabaDisk(value, diskID string) bool {
	wanted := normalizeAlibabaDiskID(diskID)
	value = strings.ToLower(strings.Trim(value, " \t\r\n\x00"))
	if value == wanted || value == "d-"+wanted || value == "d_"+wanted {
		return true
	}
	for _, match := range alibabaDiskIDInIdentity.FindAllStringSubmatch(value, -1) {
		if len(match) == 2 && match[1] == wanted {
			return true
		}
	}
	return false
}

func isAlibabaDiskIdentity(diskID string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(diskID)), "d-")
}

func findAlibabaDataDisk(diskID string) (string, error) {
	locator := alibabaDeviceLocator{
		sysBlockRoot:   "/sys/block",
		deviceRoot:     "/dev",
		byIDRoot:       "/dev/disk/by-id",
		isSystemDisk:   isAlibabaSystemDisk,
		udevProperties: readUdevProperties,
	}
	return locator.find(diskID)
}

func (l alibabaDeviceLocator) find(diskID string) (string, error) {
	if !alibabaDiskIDPattern.MatchString(diskID) {
		return "", fmt.Errorf("%w: %q", errAlibabaDiskIDInvalid, diskID)
	}

	// Stable udev links are the strongest guest-visible identity and work for
	// both NVMe namespaces and virtio/SCSI disks.
	if l.byIDRoot != "" {
		matches, err := l.findByID(diskID)
		if err != nil {
			return "", err
		}
		if device, ok, err := uniqueAlibabaDevice(matches, diskID, "udev by-id"); ok || err != nil {
			return device, err
		}
	}

	entries, err := os.ReadDir(l.sysBlockRoot)
	if err != nil {
		return "", fmt.Errorf("read block devices: %w", err)
	}

	// Some images do not create by-id links but retain the same identity in the
	// udev database.
	if l.udevProperties != nil {
		var matches []string
		for _, entry := range entries {
			if !l.safeWholeDisk(entry.Name()) {
				continue
			}
			device := filepath.Join(l.deviceRoot, entry.Name())
			properties, err := l.udevProperties(device)
			if err != nil {
				continue
			}
			for _, key := range []string{"ID_SERIAL_SHORT", "ID_SERIAL", "ID_WWN", "ID_WWN_WITH_EXTENSION"} {
				if identityMatchesAlibabaDisk(properties[key], diskID) {
					matches = append(matches, device)
					break
				}
			}
		}
		if device, ok, err := uniqueAlibabaDevice(matches, diskID, "udev properties"); ok || err != nil {
			return device, err
		}
	}

	// Kernel identities cover NVMe serials as well as virtio/SCSI serial and
	// WWID layouts. There is deliberately no /dev/vdX or /dev/nvmeXnY order
	// fallback: a wrong disk is worse than a retryable discovery failure.
	var matches []string
	for _, entry := range entries {
		name := entry.Name()
		if !l.safeWholeDisk(name) {
			continue
		}
		for _, identity := range l.sysfsIdentities(name) {
			if identityMatchesAlibabaDisk(identity, diskID) {
				matches = append(matches, filepath.Join(l.deviceRoot, name))
				break
			}
		}
	}
	if device, ok, err := uniqueAlibabaDevice(matches, diskID, "sysfs identity"); ok || err != nil {
		return device, err
	}

	return "", fmt.Errorf("%w: %s was not found by by-id, udev, serial, or WWID", errAlibabaDiskNotFound, diskID)
}

func (l alibabaDeviceLocator) findByID(diskID string) ([]string, error) {
	entries, err := os.ReadDir(l.byIDRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", l.byIDRoot, err)
	}
	var matches []string
	for _, entry := range entries {
		if strings.Contains(strings.ToLower(entry.Name()), "part") || !identityMatchesAlibabaDisk(entry.Name(), diskID) {
			continue
		}
		target, err := filepath.EvalSymlinks(filepath.Join(l.byIDRoot, entry.Name()))
		if err != nil {
			continue
		}
		name := filepath.Base(target)
		if !l.safeWholeDisk(name) {
			continue
		}
		matches = append(matches, filepath.Join(l.deviceRoot, name))
	}
	return matches, nil
}

func (l alibabaDeviceLocator) safeWholeDisk(name string) bool {
	if name == "" || filepath.Base(name) != name || unsupportedBlockNameStart.MatchString(name) {
		return false
	}
	if _, err := os.Stat(filepath.Join(l.sysBlockRoot, name)); err != nil {
		return false
	}
	if _, err := os.Stat(filepath.Join(l.sysBlockRoot, name, "partition")); err == nil {
		return false
	}
	if hasPartitionsIn(l.sysBlockRoot, name) {
		return false
	}
	return l.isSystemDisk == nil || !l.isSystemDisk(name)
}

func hasPartitionsIn(sysBlockRoot, name string) bool {
	entries, err := os.ReadDir(filepath.Join(sysBlockRoot, name))
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), name) {
			if _, err := os.Stat(filepath.Join(sysBlockRoot, name, entry.Name(), "partition")); err == nil {
				return true
			}
		}
	}
	return false
}

func (l alibabaDeviceLocator) sysfsIdentities(name string) []string {
	var identities []string
	for _, relative := range []string{
		"device/serial", // virtio/SCSI and many NVMe kernels
		"serial",        // NVMe namespace layouts
		"device/wwid",
		"wwid",
		"device/vpd_pg83",
	} {
		if value, err := os.ReadFile(filepath.Join(l.sysBlockRoot, name, relative)); err == nil {
			identities = append(identities, string(value))
		}
	}
	for _, relative := range []string{"uevent", "device/uevent"} {
		if value, err := os.ReadFile(filepath.Join(l.sysBlockRoot, name, relative)); err == nil {
			for _, line := range strings.Split(string(value), "\n") {
				key, candidate, found := strings.Cut(line, "=")
				if found && (key == "SERIAL" || key == "WWID") {
					identities = append(identities, candidate)
				}
			}
		}
	}
	return identities
}

func uniqueAlibabaDevice(matches []string, diskID, source string) (string, bool, error) {
	set := make(map[string]struct{}, len(matches))
	for _, match := range matches {
		set[filepath.Clean(match)] = struct{}{}
	}
	devices := make([]string, 0, len(set))
	for device := range set {
		devices = append(devices, device)
	}
	sort.Strings(devices)
	switch len(devices) {
	case 0:
		return "", false, nil
	case 1:
		return devices[0], true, nil
	default:
		return "", false, fmt.Errorf("%w: multiple block devices match %s via %s: %s", errAlibabaDiskAmbiguous, diskID, source, strings.Join(devices, ", "))
	}
}

func readUdevProperties(device string) (map[string]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "udevadm", "info", "--query=property", "--name", device).Output()
	if err != nil {
		return nil, err
	}
	properties := make(map[string]string)
	for _, line := range strings.Split(string(out), "\n") {
		key, value, found := strings.Cut(line, "=")
		if found {
			properties[key] = value
		}
	}
	return properties, nil
}

func isAlibabaSystemDisk(devName string) bool {
	criticalMounts := map[string]struct{}{`/`: {}, `/boot`: {}, `/boot/efi`: {}, `/usr`: {}, `/var`: {}}
	mounts, err := mountinfo.GetMounts(func(mount *mountinfo.Info) (skip, stop bool) {
		_, critical := criticalMounts[mount.Mountpoint]
		return !critical, false
	})
	if err == nil {
		for _, mount := range mounts {
			// The source may be /dev/root, UUID=..., or another alias. Resolve
			// the kernel device number so a partition maps to its whole disk.
			devicePath, resolveErr := filepath.EvalSymlinks(fmt.Sprintf("/sys/dev/block/%d:%d", mount.Major, mount.Minor))
			if resolveErr == nil {
				rootDevice := filepath.Base(devicePath)
				if sysfsPathBelongsToDisk(devicePath, devName) ||
					blockDeviceGraphContains("/sys/class/block", rootDevice, devName) {
					return true
				}
			}
			if strings.HasPrefix(filepath.Clean(mount.Source), "/dev/"+devName) {
				return true
			}
		}
	}

	// Retain the source-name fallback for minimal images without /sys/dev.
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.HasPrefix(fields[0], "/dev/"+devName) {
			continue
		}
		switch fields[1] {
		case "/", "/boot", "/boot/efi", "/usr", "/var":
			return true
		}
	}
	return false
}

// blockDeviceGraphContains follows the kernel block graph instead of assuming
// that a critical filesystem is mounted directly from a whole disk. This
// covers dm-crypt/LVM roots (slaves), partitions (their parent whole disk), and
// holder links used by stacked block devices. Failures are conservative at the
// caller: the source-name fallback is still evaluated.
func blockDeviceGraphContains(classBlockRoot, start, target string) bool {
	seen := make(map[string]struct{})
	var visit func(string) bool
	visit = func(name string) bool {
		name = filepath.Base(filepath.Clean(name))
		if name == "" || name == "." {
			return false
		}
		if name == target {
			return true
		}
		if _, exists := seen[name]; exists {
			return false
		}
		seen[name] = struct{}{}

		devicePath := filepath.Join(classBlockRoot, name)
		if _, err := os.Stat(filepath.Join(devicePath, "partition")); err == nil {
			if resolved, err := filepath.EvalSymlinks(devicePath); err == nil {
				parent := filepath.Base(filepath.Dir(resolved))
				if parent != name && visit(parent) {
					return true
				}
			}
		}
		for _, relationship := range []string{"slaves", "holders"} {
			entries, err := os.ReadDir(filepath.Join(devicePath, relationship))
			if err != nil {
				continue
			}
			for _, entry := range entries {
				if visit(entry.Name()) {
					return true
				}
			}
		}
		return false
	}
	return visit(start)
}

func sysfsPathBelongsToDisk(path, devName string) bool {
	parts := strings.Split(filepath.Clean(path), string(filepath.Separator))
	for _, part := range parts {
		if part == devName {
			return true
		}
	}
	return false
}
