// (C) Copyright Confidential Containers Contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	b64 "encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/confidential-containers/cloud-api-adaptor/src/cloud-api-adaptor/pkg/util"
	pb "github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/agent/protocols/grpc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeTestMountInfo(t *testing.T, dir, volumePath string, info map[string]interface{}) {
	t.Helper()
	podUID, ok := util.CSINodePublishVolumePodUID(volumePath)
	require.True(t, ok, "test volume path must be canonical")
	metadata := map[string]interface{}{
		"version":       util.DirectVolumeMetadataVersion,
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
	canonicalOptions, canonicalReadOnly, err := util.NormalizeDirectVolumeOptions(options, readOnly)
	require.NoError(t, err)
	metadata["options"] = canonicalOptions
	metadata["readonly"] = canonicalReadOnly
	encoded := b64.URLEncoding.EncodeToString([]byte(volumePath))
	volDir := filepath.Join(dir, encoded)
	require.NoError(t, os.MkdirAll(volDir, 0o755))

	data, err := json.Marshal(metadata)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(volDir, "mountInfo.json"), data, 0o644))
}

func overrideKataDirectVolumesDir(t *testing.T, dir string) {
	t.Helper()
	origDir := util.KataDirectVolumesDir
	util.KataDirectVolumesDir = dir
	t.Cleanup(func() { util.KataDirectVolumesDir = origDir })
}

func setTestDirectVolumeResolution(t *testing.T, service *proxyService, podUID string) *util.DirectVolumeResolution {
	t.Helper()
	resolution, err := util.ResolveCSIVolumesForPod(podUID, nil)
	require.NoError(t, err)
	service.directVolumes = resolution
	return resolution
}

func TestCloudVolumes_SingleVolumeAnnotation(t *testing.T) {
	dir := t.TempDir()
	overrideKataDirectVolumesDir(t, dir)

	service, cleanup := setupMockAgentAndService(t)
	defer cleanup()

	podUID := "pod-uid-111"
	volPath := "/var/lib/kubelet/pods/" + podUID + "/volumes/kubernetes.io~csi/pvc-test/mount"

	writeTestMountInfo(t, dir, volPath, map[string]interface{}{
		"device": "/subscriptions/sub/disks/csi-vol-pvc-test",
		"fstype": "ext4",
		"metadata": map[string]interface{}{
			"cloud-volume-path": "/subscriptions/sub/disks/csi-vol-pvc-test",
		},
	})
	setTestDirectVolumeResolution(t, service, podUID)

	req := newCreateContainerRequest("test-cloud-vol").
		withAnnotations(map[string]string{
			"io.kubernetes.cri.sandbox-uid": podUID,
		}).
		withMounts(&pb.Mount{
			Destination: "/mnt/data",
			Source:      volPath,
			Type:        "bind",
		}).
		build()

	_, err := service.CreateContainer(context.Background(), req)
	require.NoError(t, err)

	cvJSON, ok := req.OCI.Annotations["io.confidentialcontainers.org.cloud_volumes"]
	require.True(t, ok, "cloud_volumes annotation should be set")

	var cloudVolumes map[string]util.CloudVolumeAnnotation
	require.NoError(t, json.Unmarshal([]byte(cvJSON), &cloudVolumes))

	require.Contains(t, cloudVolumes, "vol-0")
	assert.Equal(t, "/mnt/data", cloudVolumes["vol-0"].MountPoint)
	assert.Equal(t, "ext4", cloudVolumes["vol-0"].FSType)
	assert.Equal(t, "0", cloudVolumes["vol-0"].LUN)
	assert.Equal(t, "/subscriptions/sub/disks/csi-vol-pvc-test", cloudVolumes["vol-0"].DiskID)
}

func TestCloudVolumes_MultipleVolumes(t *testing.T) {
	dir := t.TempDir()
	overrideKataDirectVolumesDir(t, dir)

	service, cleanup := setupMockAgentAndService(t)
	defer cleanup()

	podUID := "pod-uid-222"
	volPathA := "/var/lib/kubelet/pods/" + podUID + "/volumes/kubernetes.io~csi/pvc-alpha/mount"
	volPathB := "/var/lib/kubelet/pods/" + podUID + "/volumes/kubernetes.io~csi/pvc-bravo/mount"

	writeTestMountInfo(t, dir, volPathA, map[string]interface{}{
		"device": "disk-alpha",
		"fstype": "ext4",
	})
	writeTestMountInfo(t, dir, volPathB, map[string]interface{}{
		"device": "disk-bravo",
		"fstype": "xfs",
	})
	setTestDirectVolumeResolution(t, service, podUID)

	req := newCreateContainerRequest("test-multi-vol").
		withAnnotations(map[string]string{
			"io.kubernetes.cri.sandbox-uid": podUID,
		}).
		withMounts(
			&pb.Mount{Destination: "/data/a", Source: volPathA, Type: "bind"},
			&pb.Mount{Destination: "/data/b", Source: volPathB, Type: "bind"},
		).
		build()

	_, err := service.CreateContainer(context.Background(), req)
	require.NoError(t, err)

	cvJSON := req.OCI.Annotations["io.confidentialcontainers.org.cloud_volumes"]
	require.NotEmpty(t, cvJSON)

	var cloudVolumes map[string]util.CloudVolumeAnnotation
	require.NoError(t, json.Unmarshal([]byte(cvJSON), &cloudVolumes))
	assert.Len(t, cloudVolumes, 2)
}

func TestCloudVolumes_FsTypeFromMountInfo(t *testing.T) {
	dir := t.TempDir()
	overrideKataDirectVolumesDir(t, dir)

	service, cleanup := setupMockAgentAndService(t)
	defer cleanup()

	podUID := "pod-uid-333"
	volPath := "/var/lib/kubelet/pods/" + podUID + "/volumes/kubernetes.io~csi/pvc-xfs/mount"

	writeTestMountInfo(t, dir, volPath, map[string]interface{}{
		"device": "disk-xfs",
		"fstype": "xfs",
	})
	setTestDirectVolumeResolution(t, service, podUID)

	req := newCreateContainerRequest("test-fstype").
		withAnnotations(map[string]string{
			"io.kubernetes.cri.sandbox-uid": podUID,
		}).
		withMounts(&pb.Mount{
			Destination: "/mnt/xfs",
			Source:      volPath,
			Type:        "bind",
		}).
		build()

	_, err := service.CreateContainer(context.Background(), req)
	require.NoError(t, err)

	var cloudVolumes map[string]util.CloudVolumeAnnotation
	require.NoError(t, json.Unmarshal([]byte(req.OCI.Annotations["io.confidentialcontainers.org.cloud_volumes"]), &cloudVolumes))
	assert.Equal(t, "xfs", cloudVolumes["vol-0"].FSType)
}

func TestCloudVolumes_FsTypeFallsBackToExt4(t *testing.T) {
	dir := t.TempDir()
	overrideKataDirectVolumesDir(t, dir)

	service, cleanup := setupMockAgentAndService(t)
	defer cleanup()

	podUID := "pod-uid-444"
	volPath := "/var/lib/kubelet/pods/" + podUID + "/volumes/kubernetes.io~csi/pvc-nofs/mount"

	writeTestMountInfo(t, dir, volPath, map[string]interface{}{
		"device": "disk-nofs",
	})
	setTestDirectVolumeResolution(t, service, podUID)

	req := newCreateContainerRequest("test-fstype-default").
		withAnnotations(map[string]string{
			"io.kubernetes.cri.sandbox-uid": podUID,
		}).
		withMounts(&pb.Mount{
			Destination: "/mnt/default",
			Source:      volPath,
			Type:        "bind",
		}).
		build()

	_, err := service.CreateContainer(context.Background(), req)
	require.NoError(t, err)

	var cloudVolumes map[string]util.CloudVolumeAnnotation
	require.NoError(t, json.Unmarshal([]byte(req.OCI.Annotations["io.confidentialcontainers.org.cloud_volumes"]), &cloudVolumes))
	assert.Equal(t, "ext4", cloudVolumes["vol-0"].FSType)
}

func TestCloudVolumes_ReadOnlyContract(t *testing.T) {
	tests := []struct {
		name     string
		readOnly bool
		options  []string
	}{
		{name: "explicit readonly", readOnly: true, options: []string{"nodev", "ro"}},
		{name: "ro mount flag", options: []string{"noexec", "ro"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			overrideKataDirectVolumesDir(t, dir)
			service, cleanup := setupMockAgentAndService(t)
			defer cleanup()

			podUID := "pod-uid-readonly"
			volumePath := "/var/lib/kubelet/pods/" + podUID + "/volumes/kubernetes.io~csi/pvc-ro/mount"
			writeTestMountInfo(t, dir, volumePath, map[string]interface{}{
				"device": "disk-readonly", "fstype": "ext4",
				"readonly": tt.readOnly, "options": tt.options,
			})
			setTestDirectVolumeResolution(t, service, podUID)
			req := newCreateContainerRequest("test-readonly").
				withAnnotations(map[string]string{"io.kubernetes.cri.sandbox-uid": podUID}).
				withMounts(&pb.Mount{Destination: "/workspace", Source: volumePath, Type: "bind"}).
				build()

			_, err := service.CreateContainer(context.Background(), req)
			require.NoError(t, err)
			var volumes map[string]util.CloudVolumeAnnotation
			require.NoError(t, json.Unmarshal([]byte(req.OCI.Annotations[util.CloudVolumesAnnotationKey]), &volumes))
			assert.True(t, volumes["vol-0"].ReadOnly)
			assert.Contains(t, volumes["vol-0"].Options, "ro")
			assert.NotContains(t, volumes["vol-0"].Options, "rw")
		})
	}
}

func TestCloudVolumes_NoAnnotationWhenNoCSIVolumes(t *testing.T) {
	dir := t.TempDir()
	overrideKataDirectVolumesDir(t, dir)

	service, cleanup := setupMockAgentAndService(t)
	defer cleanup()

	req := newCreateContainerRequest("test-no-vol").
		withAnnotations(map[string]string{
			util.CloudVolumesAnnotationKey: `{"vol-0":{"disk_id":"caller-controlled"}}`,
		}).
		withMounts(&pb.Mount{
			Destination: "/mnt/regular",
			Source:      "/some/regular/path",
			Type:        "bind",
		}).
		build()

	_, err := service.CreateContainer(context.Background(), req)
	require.NoError(t, err)

	_, ok := req.OCI.Annotations["io.confidentialcontainers.org.cloud_volumes"]
	assert.False(t, ok, "cloud_volumes annotation should not be set for non-CSI volumes")
}

func TestCloudVolumes_SkipsVolumesFromOtherPods(t *testing.T) {
	dir := t.TempDir()
	overrideKataDirectVolumesDir(t, dir)

	service, cleanup := setupMockAgentAndService(t)
	defer cleanup()

	writeTestMountInfo(t, dir,
		"/var/lib/kubelet/pods/other-pod-uid/volumes/kubernetes.io~csi/pvc-other/mount",
		map[string]interface{}{"device": "other-disk", "fstype": "ext4"})
	setTestDirectVolumeResolution(t, service, "my-pod-uid")

	req := newCreateContainerRequest("test-other-pod").
		withAnnotations(map[string]string{
			"io.kubernetes.cri.sandbox-uid": "my-pod-uid",
		}).
		build()

	_, err := service.CreateContainer(context.Background(), req)
	require.NoError(t, err)

	_, ok := req.OCI.Annotations["io.confidentialcontainers.org.cloud_volumes"]
	assert.False(t, ok, "should not include volumes from other pods")
}

func TestCloudVolumes_LUNIndexSkippedVolumeConsistency(t *testing.T) {
	dir := t.TempDir()
	overrideKataDirectVolumesDir(t, dir)

	service, cleanup := setupMockAgentAndService(t)
	defer cleanup()

	podUID := "pod-uid-555"

	// vol-a has matching OCI mount
	volPathA := "/var/lib/kubelet/pods/" + podUID + "/volumes/kubernetes.io~csi/pvc-alpha/mount"
	writeTestMountInfo(t, dir, volPathA, map[string]interface{}{
		"device": "disk-alpha", "fstype": "ext4",
	})

	// vol-b has NO matching OCI mount (will be skipped in annotation but still counted)
	volPathB := "/var/lib/kubelet/pods/" + podUID + "/volumes/kubernetes.io~csi/pvc-bravo/mount"
	writeTestMountInfo(t, dir, volPathB, map[string]interface{}{
		"device": "disk-bravo", "fstype": "ext4",
	})

	// vol-c has matching OCI mount
	volPathC := "/var/lib/kubelet/pods/" + podUID + "/volumes/kubernetes.io~csi/pvc-charlie/mount"
	writeTestMountInfo(t, dir, volPathC, map[string]interface{}{
		"device": "disk-charlie", "fstype": "ext4",
	})
	setTestDirectVolumeResolution(t, service, podUID)

	req := newCreateContainerRequest("test-lun-skip").
		withAnnotations(map[string]string{
			"io.kubernetes.cri.sandbox-uid": podUID,
		}).
		withMounts(
			&pb.Mount{Destination: "/data/a", Source: volPathA, Type: "bind"},
			// No mount for volPathB
			&pb.Mount{Destination: "/data/c", Source: volPathC, Type: "bind"},
		).
		build()

	_, err := service.CreateContainer(context.Background(), req)
	require.NoError(t, err)

	cvJSON := req.OCI.Annotations["io.confidentialcontainers.org.cloud_volumes"]
	require.NotEmpty(t, cvJSON)

	var cloudVolumes map[string]util.CloudVolumeAnnotation
	require.NoError(t, json.Unmarshal([]byte(cvJSON), &cloudVolumes))

	// Should only have 2 entries (vol-b is skipped because no OCI mount)
	assert.Len(t, cloudVolumes, 2)

	// Collect LUN values
	luns := make(map[string]string)
	for _, vol := range cloudVolumes {
		luns[vol.LUN] = vol.DiskID
	}

	// vol-a should get LUN 0 (canonical index 0)
	// vol-b gets canonical index 1 (skipped in annotation but index still incremented)
	// vol-c should get LUN 2 (canonical index 2)
	assert.Contains(t, luns, "0", "vol-a should be at LUN 0")
	assert.Contains(t, luns, "2", "vol-c should be at LUN 2, not LUN 1")
	assert.NotContains(t, luns, "1", "LUN 1 should be skipped (vol-b had no OCI mount)")

	assert.Equal(t, "disk-alpha", luns["0"])
	assert.Equal(t, "disk-charlie", luns["2"])
}

func TestCloudVolumes_RejectsVolumeWithNoDiskIDDuringResolution(t *testing.T) {
	dir := t.TempDir()
	overrideKataDirectVolumesDir(t, dir)

	podUID := "pod-uid-666"
	volPath := "/var/lib/kubelet/pods/" + podUID + "/volumes/kubernetes.io~csi/pvc-nodisk/mount"

	writeTestMountInfo(t, dir, volPath, map[string]interface{}{
		"fstype": "ext4",
	})

	_, err := util.ResolveCSIVolumesForPod(podUID, nil)
	require.ErrorContains(t, err, "invalid device")
}

func TestCloudVolumes_RejectsInvalidMountInfoDuringResolution(t *testing.T) {
	dir := t.TempDir()
	overrideKataDirectVolumesDir(t, dir)

	podUID := "pod-uid-777"
	volPath := "/var/lib/kubelet/pods/" + podUID + "/volumes/kubernetes.io~csi/pvc-badjson/mount"

	encoded := b64.URLEncoding.EncodeToString([]byte(volPath))
	volDir := filepath.Join(dir, encoded)
	require.NoError(t, os.MkdirAll(volDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(volDir, "mountInfo.json"), []byte("not json"), 0o644))

	_, err := util.ResolveCSIVolumesForPod(podUID, nil)
	require.ErrorContains(t, err, "parse CSI mount info")
}

func TestCloudVolumes_MetadataMutationDoesNotChangeResolution(t *testing.T) {
	dir := t.TempDir()
	overrideKataDirectVolumesDir(t, dir)
	service, cleanup := setupMockAgentAndService(t)
	defer cleanup()

	podUID := "pod-uid-immutable"
	volumePath := "/var/lib/kubelet/pods/" + podUID + "/volumes/kubernetes.io~csi/pvc-workspace/mount"
	writeTestMountInfo(t, dir, volumePath, map[string]interface{}{
		"device": "disk-original", "readonly": true, "options": []string{"nodev", "ro"},
	})
	resolution := setTestDirectVolumeResolution(t, service, podUID)
	require.Equal(t, "disk-original", resolution.ProviderVolumes()[0].DiskID)

	// A host-side change after CreateVM must not alter the attached disk or the
	// guest mount contract used by CreateContainer.
	writeTestMountInfo(t, dir, volumePath, map[string]interface{}{
		"device": "disk-mutated", "readonly": false, "options": []string{"rw"},
	})
	req := newCreateContainerRequest("test-immutable").
		withAnnotations(map[string]string{"io.kubernetes.cri.sandbox-uid": podUID}).
		withMounts(&pb.Mount{Destination: "/workspace", Source: volumePath, Type: "bind"}).
		build()

	_, err := service.CreateContainer(context.Background(), req)
	require.NoError(t, err)
	var volumes map[string]util.CloudVolumeAnnotation
	require.NoError(t, json.Unmarshal([]byte(req.OCI.Annotations[util.CloudVolumesAnnotationKey]), &volumes))
	assert.Equal(t, "disk-original", volumes["vol-0"].DiskID)
	assert.True(t, volumes["vol-0"].ReadOnly)
	assert.Equal(t, []string{"nodev", "ro"}, volumes["vol-0"].Options)
}

func TestCloudVolumes_UnknownCanonicalSourceFailsClosed(t *testing.T) {
	dir := t.TempDir()
	overrideKataDirectVolumesDir(t, dir)
	service, cleanup := setupMockAgentAndService(t)
	defer cleanup()

	podUID := "pod-uid-unknown"
	known := "/var/lib/kubelet/pods/" + podUID + "/volumes/kubernetes.io~csi/pvc-known/mount"
	unknown := "/var/lib/kubelet/pods/" + podUID + "/volumes/kubernetes.io~csi/pvc-unknown/mount"
	writeTestMountInfo(t, dir, known, map[string]interface{}{"device": "disk-known"})
	setTestDirectVolumeResolution(t, service, podUID)

	req := newCreateContainerRequest("test-unknown").
		withAnnotations(map[string]string{"io.kubernetes.cri.sandbox-uid": podUID}).
		withMounts(&pb.Mount{Destination: "/workspace", Source: unknown, Type: "bind"}).
		build()
	_, err := service.CreateContainer(context.Background(), req)
	require.ErrorContains(t, err, "absent from the sandbox resolution")
	assert.NotContains(t, req.OCI.Annotations, util.CloudVolumesAnnotationKey)
}

func TestCloudVolumes_MultipleContainersReuseOneResolution(t *testing.T) {
	dir := t.TempDir()
	overrideKataDirectVolumesDir(t, dir)
	service, cleanup := setupMockAgentAndService(t)
	defer cleanup()

	podUID := "pod-uid-containers"
	volumeA := "/var/lib/kubelet/pods/" + podUID + "/volumes/kubernetes.io~csi/pvc-a/mount"
	volumeB := "/var/lib/kubelet/pods/" + podUID + "/volumes/kubernetes.io~csi/pvc-b/mount"
	writeTestMountInfo(t, dir, volumeA, map[string]interface{}{"device": "disk-a"})
	writeTestMountInfo(t, dir, volumeB, map[string]interface{}{"device": "disk-b", "readonly": true, "options": []string{"ro"}})
	resolution := setTestDirectVolumeResolution(t, service, podUID)
	nameA, expectedA, ok := resolution.CloudVolumeForMount(volumeA, "/data/a")
	require.True(t, ok)
	nameB, expectedB, ok := resolution.CloudVolumeForMount(volumeB, "/data/b")
	require.True(t, ok)
	require.NoError(t, os.RemoveAll(dir))

	requests := []*pb.CreateContainerRequest{
		newCreateContainerRequest("container-a").
			withAnnotations(map[string]string{"io.kubernetes.cri.sandbox-uid": podUID}).
			withMounts(&pb.Mount{Destination: "/data/a", Source: volumeA, Type: "bind"}).build(),
		newCreateContainerRequest("container-b").
			withAnnotations(map[string]string{"io.kubernetes.cri.sandbox-uid": podUID}).
			withMounts(&pb.Mount{Destination: "/data/b", Source: volumeB, Type: "bind"}).build(),
	}
	for _, req := range requests {
		_, err := service.CreateContainer(context.Background(), req)
		require.NoError(t, err)
	}

	var first, second map[string]util.CloudVolumeAnnotation
	require.NoError(t, json.Unmarshal([]byte(requests[0].OCI.Annotations[util.CloudVolumesAnnotationKey]), &first))
	require.NoError(t, json.Unmarshal([]byte(requests[1].OCI.Annotations[util.CloudVolumesAnnotationKey]), &second))
	require.Len(t, first, 1)
	require.Len(t, second, 1)
	assert.Equal(t, expectedA.DiskID, first[nameA].DiskID)
	assert.Equal(t, expectedA.LUN, first[nameA].LUN)
	assert.Equal(t, expectedA.MountPoint, first[nameA].MountPoint)
	assert.Equal(t, expectedB.DiskID, second[nameB].DiskID)
	assert.Equal(t, expectedB.LUN, second[nameB].LUN)
	assert.Equal(t, expectedB.MountPoint, second[nameB].MountPoint)
	assert.True(t, second[nameB].ReadOnly)
}

func TestCloudVolumes_EncryptionAnnotation(t *testing.T) {
	dir := t.TempDir()
	overrideKataDirectVolumesDir(t, dir)

	service, cleanup := setupMockAgentAndService(t)
	defer cleanup()

	podUID := "pod-uid-enc-333"
	volPath := "/var/lib/kubelet/pods/" + podUID + "/volumes/kubernetes.io~csi/pvc-encrypted/mount"

	writeTestMountInfo(t, dir, volPath, map[string]interface{}{
		"device": "/subscriptions/sub/disks/csi-vol-pvc-encrypted",
		"fstype": "ext4",
		"metadata": map[string]interface{}{
			"cloud-volume-path": "/subscriptions/sub/disks/csi-vol-pvc-encrypted",
			"encrypt-type":      "LUKS",
			"kbs-key-id":        "default/key/volume-enc-key",
		},
	})
	setTestDirectVolumeResolution(t, service, podUID)

	req := newCreateContainerRequest("test-encrypted-vol").
		withAnnotations(map[string]string{
			"io.kubernetes.cri.sandbox-uid": podUID,
		}).
		withMounts(&pb.Mount{
			Destination: "/mnt/secret",
			Source:      volPath,
			Type:        "bind",
		}).
		build()

	_, err := service.CreateContainer(context.Background(), req)
	require.NoError(t, err)

	cvJSON, ok := req.OCI.Annotations[util.CloudVolumesAnnotationKey]
	require.True(t, ok, "cloud_volumes annotation should be set")

	var cloudVolumes map[string]util.CloudVolumeAnnotation
	require.NoError(t, json.Unmarshal([]byte(cvJSON), &cloudVolumes))

	require.Contains(t, cloudVolumes, "vol-0")
	vol := cloudVolumes["vol-0"]
	assert.Equal(t, "/mnt/secret", vol.MountPoint)
	assert.Equal(t, "ext4", vol.FSType)
	assert.Equal(t, "0", vol.LUN)
	assert.Equal(t, "/subscriptions/sub/disks/csi-vol-pvc-encrypted", vol.DiskID)
	assert.Equal(t, "LUKS", vol.EncryptType)
	assert.Equal(t, "default/key/volume-enc-key", vol.KeyID)
}

func TestCloudVolumes_NoEncryptionParamsWhenAbsent(t *testing.T) {
	dir := t.TempDir()
	overrideKataDirectVolumesDir(t, dir)

	service, cleanup := setupMockAgentAndService(t)
	defer cleanup()

	podUID := "pod-uid-plain-444"
	volPath := "/var/lib/kubelet/pods/" + podUID + "/volumes/kubernetes.io~csi/pvc-plain/mount"

	writeTestMountInfo(t, dir, volPath, map[string]interface{}{
		"device": "vol-abc123def",
		"fstype": "xfs",
	})
	setTestDirectVolumeResolution(t, service, podUID)

	req := newCreateContainerRequest("test-plain-vol").
		withAnnotations(map[string]string{
			"io.kubernetes.cri.sandbox-uid": podUID,
		}).
		withMounts(&pb.Mount{
			Destination: "/mnt/data",
			Source:      volPath,
			Type:        "bind",
		}).
		build()

	_, err := service.CreateContainer(context.Background(), req)
	require.NoError(t, err)

	cvJSON, ok := req.OCI.Annotations[util.CloudVolumesAnnotationKey]
	require.True(t, ok, "cloud_volumes annotation should be set")

	var cloudVolumes map[string]util.CloudVolumeAnnotation
	require.NoError(t, json.Unmarshal([]byte(cvJSON), &cloudVolumes))

	require.Contains(t, cloudVolumes, "vol-0")
	vol := cloudVolumes["vol-0"]
	assert.Equal(t, "", vol.EncryptType)
	assert.Equal(t, "", vol.KeyID)
}
