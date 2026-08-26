package util

import (
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func setupDirectVolumesDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	origDir := KataDirectVolumesDir

	t.Cleanup(func() {
		KataDirectVolumesDir = origDir
	})
	KataDirectVolumesDir = dir
	return dir
}

func writeMountInfo(t *testing.T, dir, volumePath string, info map[string]interface{}) {
	t.Helper()
	if podUID, ok := CSINodePublishVolumePodUID(volumePath); ok {
		metadata := map[string]interface{}{
			"version":       DirectVolumeMetadataVersion,
			"volume-type":   "block",
			"volume-mode":   "filesystem",
			"device":        "",
			"fstype":        "ext4",
			"readonly":      false,
			"pod-uid":       podUID,
			"volume-handle": filepath.Base(filepath.Dir(volumePath)),
		}
		for key, value := range info {
			metadata[key] = value
		}
		options, _ := metadata["options"].([]string)
		readOnly, _ := metadata["readonly"].(bool)
		canonicalOptions, canonicalReadOnly, err := NormalizeDirectVolumeOptions(options, readOnly)
		require.NoError(t, err)
		metadata["options"] = canonicalOptions
		metadata["readonly"] = canonicalReadOnly
		info = metadata
	}
	writeRawMountInfo(t, dir, volumePath, info)
}

func writeRawMountInfo(t *testing.T, dir, volumePath string, info interface{}) {
	t.Helper()
	encoded := b64.URLEncoding.EncodeToString([]byte(volumePath))
	volDir := filepath.Join(dir, encoded)
	require.NoError(t, os.MkdirAll(volDir, 0o755))

	data, err := json.Marshal(info)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(volDir, "mountInfo.json"), data, 0o644))
}

func TestDirectVolumeMetadataV1GoldenContract(t *testing.T) {
	dir := setupDirectVolumesDir(t)
	volumePath := "/var/lib/kubelet/pods/pod-uid-123/volumes/kubernetes.io~csi/pvc-workspace/mount"
	encoded := b64.URLEncoding.EncodeToString([]byte(volumePath))
	volumeDir := filepath.Join(dir, encoded)
	require.NoError(t, os.MkdirAll(volumeDir, 0o755))
	golden, err := os.ReadFile(filepath.Join("testdata", "direct-volume-v1.json"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(volumeDir, "mountInfo.json"), golden, 0o600))

	info, err := ReadDirectVolumeMountInfo(filepath.Join(volumeDir, "mountInfo.json"))
	require.NoError(t, err)
	assert.Equal(t, "d-workspace123", info.Device)
	assert.True(t, info.ReadOnly)
	assert.Equal(t, []string{"noatime", "ro"}, info.Options)
	assert.Equal(t, "2000", info.FSGroup)

	resolution, err := ResolveCSIVolumesForPod("pod-uid-123", nil)
	require.NoError(t, err)
	volumes := resolution.ProviderVolumes()
	require.Len(t, volumes, 1)
	assert.Equal(t, "d-workspace123", volumes[0].DiskID)
}

func TestDirectVolumeResolutionMapsAttachmentsAndMounts(t *testing.T) {
	dir := setupDirectVolumesDir(t)
	podUID := "pod-uid-copy"
	volumePath := "/var/lib/kubelet/pods/" + podUID + "/volumes/kubernetes.io~csi/pvc-copy/mount"
	writeMountInfo(t, dir, volumePath, map[string]interface{}{
		"device": "disk-original", "readonly": true, "options": []string{"nodev", "ro"},
	})

	resolution, err := ResolveCSIVolumesForPod(podUID, nil)
	require.NoError(t, err)
	attachments := resolution.ProviderVolumes()
	require.Len(t, attachments, 1)
	assert.Equal(t, "disk-original", attachments[0].DiskID)

	name, volume, ok := resolution.CloudVolumeForMount(volumePath, "/workspace")
	require.True(t, ok)
	assert.Equal(t, "vol-0", name)
	assert.Equal(t, []string{"nodev", "ro"}, volume.Options)
}

func TestDirectVolumeResolutionLooksUpPodUIDOnce(t *testing.T) {
	dir := setupDirectVolumesDir(t)
	podUID := "pod-uid-lookup"
	for _, handle := range []string{"pvc-a", "pvc-b"} {
		volumePath := "/var/lib/kubelet/pods/" + podUID +
			"/volumes/kubernetes.io~csi/" + handle + "/mount"
		writeMountInfo(t, dir, volumePath, map[string]interface{}{
			"device": "disk-" + handle,
		})
	}

	lookups := 0
	resolution, err := ResolveCSIVolumesForPod("", func() (string, error) {
		lookups++
		return podUID, nil
	})
	require.NoError(t, err)
	assert.Equal(t, 1, lookups)
	assert.Len(t, resolution.ProviderVolumes(), 2)
}

func TestDirectVolumeResolutionRequiresPodUIDLookup(t *testing.T) {
	dir := setupDirectVolumesDir(t)
	volumePath := "/var/lib/kubelet/pods/pod-uid-missing/volumes/" +
		"kubernetes.io~csi/pvc-missing/mount"
	writeMountInfo(t, dir, volumePath, map[string]interface{}{
		"device": "disk-missing",
	})

	_, err := ResolveCSIVolumesForPod("", nil)
	require.ErrorContains(t, err, "pod UID lookup is required")
}

func TestDirectVolumeMetadataV1FailsClosed(t *testing.T) {
	valid := func() map[string]interface{} {
		return map[string]interface{}{
			"version": 1, "volume-type": "block", "volume-mode": "filesystem",
			"device": "d-workspace123", "fstype": "ext4", "readonly": true,
			"options": []string{"noatime", "ro"}, "pod-uid": "pod-uid-123",
			"volume-handle": "pvc-workspace",
		}
	}
	tests := []struct {
		name   string
		mutate func(map[string]interface{})
	}{
		{name: "missing readonly", mutate: func(info map[string]interface{}) { delete(info, "readonly") }},
		{name: "wrong version", mutate: func(info map[string]interface{}) { info["version"] = 0 }},
		{name: "unsupported filesystem", mutate: func(info map[string]interface{}) { info["fstype"] = "btrfs" }},
		{name: "unsafe option", mutate: func(info map[string]interface{}) { info["options"] = []string{"bind"} }},
		{name: "conflicting atime options", mutate: func(info map[string]interface{}) {
			info["options"] = []string{"atime", "noatime"}
		}},
		{name: "non-canonical fs-group", mutate: func(info map[string]interface{}) { info["fs-group"] = "02000" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "mountInfo.json")
			info := valid()
			test.mutate(info)
			data, err := json.Marshal(info)
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(path, data, 0o600))
			_, err = ReadDirectVolumeMountInfo(path)
			require.Error(t, err)
		})
	}
}

func TestReadDirectVolumeMountInfoRejectsUnsafeFiles(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "target.json")
		require.NoError(t, os.WriteFile(target, []byte(`{}`), 0o600))
		path := filepath.Join(dir, "mountInfo.json")
		require.NoError(t, os.Symlink(target, path))

		_, err := ReadDirectVolumeMountInfo(path)
		require.ErrorIs(t, err, unix.ELOOP)
	})

	t.Run("fifo", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "mountInfo.json")
		require.NoError(t, unix.Mkfifo(path, 0o600))

		_, err := ReadDirectVolumeMountInfo(path)
		require.ErrorContains(t, err, "not a regular file")
	})

	t.Run("oversize", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "mountInfo.json")
		file, err := os.Create(path)
		require.NoError(t, err)
		require.NoError(t, file.Truncate(MaxDirectVolumeMetadataSize+1))
		require.NoError(t, file.Close())

		_, err = ReadDirectVolumeMountInfo(path)
		require.ErrorContains(t, err, "exceeds")
	})
}

func TestDecodeCloudVolumeAnnotations(t *testing.T) {
	valid := `{"vol-0":{"mount_point":"/workspace","fs_type":"ext4","lun":"0","disk_id":"d-workspace123","readonly":true,"options":["noatime","ro"],"fs_group":"2000"}}`
	volumes, err := DecodeCloudVolumeAnnotations(valid)
	require.NoError(t, err)
	require.Len(t, volumes, 1)
	assert.True(t, volumes["vol-0"].ReadOnly)
	assert.Equal(t, []string{"noatime", "ro"}, volumes["vol-0"].Options)

	for name, annotation := range map[string]string{
		"missing readonly": `{"vol-0":{"mount_point":"/workspace","fs_type":"ext4","lun":"0","disk_id":"d-one"}}`,
		"duplicate target": `{"vol-0":{"mount_point":"/workspace","fs_type":"ext4","lun":"0","disk_id":"d-one","readonly":false},` +
			`"vol-1":{"mount_point":"/workspace","fs_type":"ext4","lun":"1","disk_id":"d-two","readonly":false}}`,
		"incomplete encryption": `{"vol-0":{"mount_point":"/workspace","fs_type":"ext4","lun":"0","disk_id":"d-one","readonly":false,"encrypt_type":"luks2"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := DecodeCloudVolumeAnnotations(annotation)
			require.Error(t, err)
		})
	}

	optionReadOnly := `{"vol-0":{"mount_point":"/workspace","fs_type":"ext4","lun":"0","disk_id":"d-one","readonly":false,"options":["ro"]}}`
	volumes, err = DecodeCloudVolumeAnnotations(optionReadOnly)
	require.NoError(t, err)
	assert.True(t, volumes["vol-0"].ReadOnly)
	assert.Equal(t, []string{"ro"}, volumes["vol-0"].Options)

	unknownField := `{"vol-0":{"mount_point":"/workspace","fs_type":"ext4","lun":"0","disk_id":"d-one","readonly":false,"future_field":true}}`
	_, err = DecodeCloudVolumeAnnotations(unknownField)
	require.ErrorContains(t, err, "unknown field")
}

func TestNormalizeDirectVolumeOptions(t *testing.T) {
	options, readOnly, err := NormalizeDirectVolumeOptions([]string{"noexec", "ro"}, false)
	require.NoError(t, err)
	assert.True(t, readOnly)
	assert.Equal(t, []string{"noexec", "ro"}, options)

	_, _, err = NormalizeDirectVolumeOptions([]string{"rw"}, true)
	require.ErrorContains(t, err, "readonly volume conflicts")
}

func TestDirectVolumeResolutionRejectsDuplicateDisksAndExcessVolumes(t *testing.T) {
	t.Run("duplicate final disk identity", func(t *testing.T) {
		dir := setupDirectVolumesDir(t)
		podUID := "pod-duplicate"
		for _, handle := range []string{"pvc-a", "pvc-b"} {
			path := "/var/lib/kubelet/pods/" + podUID +
				"/volumes/kubernetes.io~csi/" + handle + "/mount"
			writeMountInfo(t, dir, path, map[string]interface{}{
				"device":   "device-" + handle,
				"metadata": map[string]string{"cloud-volume-path": "disk-shared"},
			})
		}
		_, err := ResolveCSIVolumesForPod(podUID, nil)
		require.ErrorContains(t, err, "duplicates disk ID")
	})

	t.Run("per-pod volume limit", func(t *testing.T) {
		dir := setupDirectVolumesDir(t)
		podUID := "pod-volume-limit"
		for index := 0; index <= MaxDirectVolumesPerPod; index++ {
			handle := fmt.Sprintf("pvc-%03d", index)
			path := "/var/lib/kubelet/pods/" + podUID +
				"/volumes/kubernetes.io~csi/" + handle + "/mount"
			writeMountInfo(t, dir, path, map[string]interface{}{"device": "disk-" + handle})
		}
		_, err := ResolveCSIVolumesForPod(podUID, nil)
		require.ErrorContains(t, err, "exceeds 64 direct volumes")
	})
}

func TestCloudVolumeForMountReturnsIndependentOptions(t *testing.T) {
	dir := setupDirectVolumesDir(t)
	podUID := "pod-options-copy"
	path := "/var/lib/kubelet/pods/" + podUID +
		"/volumes/kubernetes.io~csi/pvc-options/mount"
	writeMountInfo(t, dir, path, map[string]interface{}{
		"device": "disk-options", "options": []string{"nodev"},
	})

	resolution, err := ResolveCSIVolumesForPod(podUID, nil)
	require.NoError(t, err)
	_, first, ok := resolution.CloudVolumeForMount(path, "/first")
	require.True(t, ok)
	first.Options[0] = "noexec"
	_, second, ok := resolution.CloudVolumeForMount(path, "/second")
	require.True(t, ok)
	assert.Equal(t, []string{"nodev"}, second.Options)
}
