// (C) Copyright Confidential Containers Contributors
// SPDX-License-Identifier: Apache-2.0

package interceptor

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func addTestBlockDevice(t *testing.T, sysBlock, deviceRoot, name string, identities map[string]string) {
	t.Helper()
	dir := filepath.Join(sysBlock, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for relative, value := range identities {
		path := filepath.Join(dir, relative)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(value+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(deviceRoot, name), nil, 0o600); err != nil {
		t.Fatal(err)
	}
}

func newTestAlibabaLocator(t *testing.T) (alibabaDeviceLocator, string, string, string) {
	t.Helper()
	root := t.TempDir()
	sysBlock := filepath.Join(root, "sys", "block")
	deviceRoot := filepath.Join(root, "dev")
	byIDRoot := filepath.Join(deviceRoot, "disk", "by-id")
	for _, dir := range []string{sysBlock, deviceRoot, byIDRoot} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return alibabaDeviceLocator{
		sysBlockRoot: sysBlock,
		deviceRoot:   deviceRoot,
		byIDRoot:     byIDRoot,
		isSystemDisk: func(string) bool { return false },
	}, sysBlock, deviceRoot, byIDRoot
}

func TestFindAlibabaDataDiskByNVMeSerial(t *testing.T) {
	locator, sysBlock, deviceRoot, _ := newTestAlibabaLocator(t)
	addTestBlockDevice(t, sysBlock, deviceRoot, "nvme0n1", map[string]string{"device/serial": "systemdisk"})
	addTestBlockDevice(t, sysBlock, deviceRoot, "nvme1n1", map[string]string{"serial": "d-workspace123"})

	device, err := locator.find("d-workspace123")
	if err != nil {
		t.Fatal(err)
	}
	if device != filepath.Join(deviceRoot, "nvme1n1") {
		t.Fatalf("got device %q", device)
	}
}

func TestFindAlibabaDataDiskByVirtioSerial(t *testing.T) {
	locator, sysBlock, deviceRoot, _ := newTestAlibabaLocator(t)
	addTestBlockDevice(t, sysBlock, deviceRoot, "vda", map[string]string{"device/serial": "systemdisk"})
	addTestBlockDevice(t, sysBlock, deviceRoot, "vdb", map[string]string{"device/serial": "workspace123"})

	device, err := locator.find("d-workspace123")
	if err != nil {
		t.Fatal(err)
	}
	if device != filepath.Join(deviceRoot, "vdb") {
		t.Fatalf("got device %q", device)
	}
}

func TestFindAlibabaDataDiskPrefersByID(t *testing.T) {
	locator, sysBlock, deviceRoot, byIDRoot := newTestAlibabaLocator(t)
	addTestBlockDevice(t, sysBlock, deviceRoot, "vdb", nil)
	link := filepath.Join(byIDRoot, "virtio-d-workspace123")
	if err := os.Symlink(filepath.Join(deviceRoot, "vdb"), link); err != nil {
		t.Fatal(err)
	}

	device, err := locator.find("d-workspace123")
	if err != nil {
		t.Fatal(err)
	}
	if device != filepath.Join(deviceRoot, "vdb") {
		t.Fatalf("got device %q", device)
	}
}

func TestFindAlibabaDataDiskByUdevWWID(t *testing.T) {
	locator, sysBlock, deviceRoot, _ := newTestAlibabaLocator(t)
	addTestBlockDevice(t, sysBlock, deviceRoot, "vdb", nil)
	locator.udevProperties = func(device string) (map[string]string, error) {
		return map[string]string{"ID_WWN": "scsi-d-workspace123"}, nil
	}

	device, err := locator.find("d-workspace123")
	if err != nil {
		t.Fatal(err)
	}
	if device != filepath.Join(deviceRoot, "vdb") {
		t.Fatalf("got device %q", device)
	}
}

func TestFindAlibabaDataDiskRejectsUnsafeDevices(t *testing.T) {
	locator, sysBlock, deviceRoot, _ := newTestAlibabaLocator(t)
	addTestBlockDevice(t, sysBlock, deviceRoot, "loop0", map[string]string{"device/serial": "workspace123"})
	addTestBlockDevice(t, sysBlock, deviceRoot, "vda", map[string]string{"device/serial": "workspace123"})
	if err := os.MkdirAll(filepath.Join(sysBlock, "vda", "vda1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sysBlock, "vda", "vda1", "partition"), []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := locator.find("d-workspace123"); !errors.Is(err, errAlibabaDiskNotFound) {
		t.Fatal("expected virtual and partitioned devices to be rejected")
	}
}

func TestFindAlibabaDataDiskRejectsSystemDisk(t *testing.T) {
	locator, sysBlock, deviceRoot, _ := newTestAlibabaLocator(t)
	addTestBlockDevice(t, sysBlock, deviceRoot, "vda", map[string]string{"device/serial": "workspace123"})
	locator.isSystemDisk = func(name string) bool { return name == "vda" }

	if _, err := locator.find("d-workspace123"); !errors.Is(err, errAlibabaDiskNotFound) {
		t.Fatalf("expected system disk to be rejected, got %v", err)
	}
}

func TestFindAlibabaDataDiskRejectsAmbiguousIdentity(t *testing.T) {
	locator, sysBlock, deviceRoot, _ := newTestAlibabaLocator(t)
	addTestBlockDevice(t, sysBlock, deviceRoot, "vdb", map[string]string{"device/serial": "workspace123"})
	addTestBlockDevice(t, sysBlock, deviceRoot, "vdc", map[string]string{"device/wwid": "d-workspace123"})

	if _, err := locator.find("d-workspace123"); !errors.Is(err, errAlibabaDiskAmbiguous) {
		t.Fatal("expected duplicate disk identities to fail closed")
	}
}

func TestFindAlibabaDataDiskRejectsConsumedDiskPrefixWhileTargetIsMissing(t *testing.T) {
	locator, sysBlock, deviceRoot, _ := newTestAlibabaLocator(t)
	addTestBlockDevice(t, sysBlock, deviceRoot, "vdb", map[string]string{"device/serial": "dabc123"})

	if device, err := locator.find("d-abc123"); !errors.Is(err, errAlibabaDiskNotFound) {
		t.Fatalf("wrong disk must not satisfy target identity: device=%q err=%v", device, err)
	}

	// A later retry may resolve the target after udev exposes it, but must never
	// have returned the prefix-consuming false match while only vdb was visible.
	addTestBlockDevice(t, sysBlock, deviceRoot, "vdc", map[string]string{"device/serial": "abc123"})
	device, err := locator.find("d-abc123")
	if err != nil {
		t.Fatal(err)
	}
	if device != filepath.Join(deviceRoot, "vdc") {
		t.Fatalf("got device %q", device)
	}
}

func TestFindAlibabaDataDiskRejectsInvalidIdentity(t *testing.T) {
	locator, _, _, _ := newTestAlibabaLocator(t)
	if _, err := locator.find("workspace123"); !errors.Is(err, errAlibabaDiskIDInvalid) {
		t.Fatalf("expected invalid identity error, got %v", err)
	}
}

func TestIsAlibabaDiskIdentity(t *testing.T) {
	for _, diskID := range []string{"d-workspace123", " D-WORKSPACE123 ", "d-invalid-suffix"} {
		if !isAlibabaDiskIdentity(diskID) {
			t.Errorf("%q must use the Alibaba identity-only locator", diskID)
		}
	}
	for _, diskID := range []string{"", "vol-123", "/subscriptions/disk"} {
		if isAlibabaDiskIdentity(diskID) {
			t.Errorf("%q was misclassified as Alibaba Cloud", diskID)
		}
	}
}

func TestFindAlibabaDataDiskWithoutByID(t *testing.T) {
	root := t.TempDir()
	sysBlock := filepath.Join(root, "sys", "block")
	deviceRoot := filepath.Join(root, "dev")
	if err := os.MkdirAll(deviceRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	addTestBlockDevice(t, sysBlock, deviceRoot, "vdb", map[string]string{"device/serial": "workspace123"})
	device, err := (alibabaDeviceLocator{
		sysBlockRoot: sysBlock,
		deviceRoot:   deviceRoot,
		isSystemDisk: func(string) bool { return false },
	}).find("d-workspace123")
	if err != nil {
		t.Fatal(err)
	}
	if device != filepath.Join(deviceRoot, "vdb") {
		t.Fatalf("got device %q", device)
	}
}

func TestSysfsPathBelongsToDisk(t *testing.T) {
	tests := []struct {
		path string
		disk string
		want bool
	}{
		{path: "/sys/devices/pci/block/vda/vda1", disk: "vda", want: true},
		{path: "/sys/devices/pci/nvme/nvme0/nvme0n1", disk: "nvme0n1", want: true},
		{path: "/sys/devices/pci/block/nvme0n1/nvme0n1p1", disk: "nvme0n1", want: true},
		{path: "/sys/devices/pci/block/vdb/vdb1", disk: "vda", want: false},
	}
	for _, test := range tests {
		if got := sysfsPathBelongsToDisk(test.path, test.disk); got != test.want {
			t.Errorf("sysfsPathBelongsToDisk(%q, %q) = %t, want %t", test.path, test.disk, got, test.want)
		}
	}
}

func TestBlockDeviceGraphContainsLVMRootBackingDisk(t *testing.T) {
	root := t.TempDir()
	classBlock := filepath.Join(root, "sys", "class", "block")
	devices := filepath.Join(root, "sys", "devices", "pci", "block", "vda")
	requireMkdir := func(path string) {
		t.Helper()
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	requireMkdir(filepath.Join(classBlock, "dm-0", "slaves"))
	requireMkdir(filepath.Join(devices, "vda2"))
	requireMkdir(filepath.Join(classBlock, "vda"))
	if err := os.WriteFile(filepath.Join(devices, "vda2", "partition"), []byte("2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(devices, "vda2"), filepath.Join(classBlock, "vda2")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(classBlock, "vda2"), filepath.Join(classBlock, "dm-0", "slaves", "vda2")); err != nil {
		t.Fatal(err)
	}

	if !blockDeviceGraphContains(classBlock, "dm-0", "vda") {
		t.Fatal("dm/LVM root did not resolve to its whole-disk backing device")
	}
	if blockDeviceGraphContains(classBlock, "dm-0", "vdb") {
		t.Fatal("unrelated data disk was classified as a system-disk backing device")
	}
}

func TestBlockDeviceGraphContainsHolderRelationship(t *testing.T) {
	classBlock := filepath.Join(t.TempDir(), "sys", "class", "block")
	if err := os.MkdirAll(filepath.Join(classBlock, "vda", "holders"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(classBlock, "dm-0"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(classBlock, "dm-0"), filepath.Join(classBlock, "vda", "holders", "dm-0")); err != nil {
		t.Fatal(err)
	}
	if !blockDeviceGraphContains(classBlock, "vda", "dm-0") {
		t.Fatal("holder relationship was not traversed")
	}
}
