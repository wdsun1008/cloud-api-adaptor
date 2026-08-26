// (C) Copyright Confidential Containers Contributors
// SPDX-License-Identifier: Apache-2.0

package alibabacloud

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	ecs "github.com/alibabacloud-go/ecs-20140526/v4/client"
	"github.com/alibabacloud-go/tea/tea"

	provider "github.com/confidential-containers/cloud-api-adaptor/src/cloud-providers"
)

type fakeAlibabaDisk struct {
	status             string
	instanceID         string
	zone               string
	multiAttach        string
	hasMultiAttach     bool
	deleteWithInstance *bool
}

type fakeVolumeECSClient struct {
	*ecs.Client
	instanceStatus string
	instanceZone   string
	disks          map[string]*fakeAlibabaDisk
	attachErrors   map[string]error
	attachApplied  map[string]bool
	attachHook     func(string)
	attachOrder    []string
}

func newFakeVolumeECSClient(disks map[string]*fakeAlibabaDisk) *fakeVolumeECSClient {
	return &fakeVolumeECSClient{
		instanceStatus: "Running",
		instanceZone:   "cn-hangzhou-i",
		disks:          disks,
		attachErrors:   make(map[string]error),
		attachApplied:  make(map[string]bool),
	}
}

func (f *fakeVolumeECSClient) DescribeInstanceAttribute(*ecs.DescribeInstanceAttributeRequest) (*ecs.DescribeInstanceAttributeResponse, error) {
	return &ecs.DescribeInstanceAttributeResponse{
		Body: &ecs.DescribeInstanceAttributeResponseBody{
			Status: tea.String(f.instanceStatus),
			ZoneId: tea.String(f.instanceZone),
		},
	}, nil
}

func (f *fakeVolumeECSClient) DescribeDisks(request *ecs.DescribeDisksRequest) (*ecs.DescribeDisksResponse, error) {
	var diskIDs []string
	if err := json.Unmarshal([]byte(tea.StringValue(request.DiskIds)), &diskIDs); err != nil {
		return nil, err
	}
	disks := make([]*ecs.DescribeDisksResponseBodyDisksDisk, 0, len(diskIDs))
	for _, diskID := range diskIDs {
		disk, found := f.disks[diskID]
		if !found {
			continue
		}
		multiAttach := "Disabled"
		if disk.hasMultiAttach {
			multiAttach = disk.multiAttach
		}
		disks = append(disks, &ecs.DescribeDisksResponseBodyDisksDisk{
			DiskId:             tea.String(diskID),
			Status:             tea.String(disk.status),
			InstanceId:         tea.String(disk.instanceID),
			ZoneId:             tea.String(disk.zone),
			Type:               tea.String("data"),
			Portable:           tea.Bool(true),
			MultiAttach:        tea.String(multiAttach),
			DeleteWithInstance: disk.deleteWithInstance,
		})
	}
	return &ecs.DescribeDisksResponse{
		Body: &ecs.DescribeDisksResponseBody{
			Disks: &ecs.DescribeDisksResponseBodyDisks{Disk: disks},
		},
	}, nil
}

func (f *fakeVolumeECSClient) AttachDisk(request *ecs.AttachDiskRequest) (*ecs.AttachDiskResponse, error) {
	diskID := tea.StringValue(request.DiskId)
	f.attachOrder = append(f.attachOrder, diskID)
	if tea.BoolValue(request.DeleteWithInstance) || tea.BoolValue(request.Bootable) {
		return nil, errors.New("data disk was not requested as retained and non-bootable")
	}
	if f.attachApplied[diskID] || f.attachErrors[diskID] == nil {
		disk := f.disks[diskID]
		disk.status = "In_use"
		disk.instanceID = tea.StringValue(request.InstanceId)
		disk.deleteWithInstance = tea.Bool(false)
	}
	if f.attachHook != nil {
		f.attachHook(diskID)
	}
	if err := f.attachErrors[diskID]; err != nil {
		return nil, err
	}
	return &ecs.AttachDiskResponse{Body: &ecs.AttachDiskResponseBody{}}, nil
}

func TestValidateAlibabaDataDisks(t *testing.T) {
	tests := []struct {
		name    string
		volumes []provider.CloudVolume
		wantErr string
	}{
		{name: "valid", volumes: []provider.CloudVolume{{DiskID: "d-one"}, {DiskID: "d-two"}}},
		{name: "invalid identity", volumes: []provider.CloudVolume{{DiskID: "vol-123"}}, wantErr: "invalid Alibaba Cloud disk ID"},
		{name: "duplicate", volumes: []provider.CloudVolume{{DiskID: "d-one"}, {DiskID: "d-one"}}, wantErr: "duplicate Alibaba Cloud disk ID"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := validateAlibabaDataDisks(test.volumes)
			if test.wantErr == "" && err != nil {
				t.Fatalf("validateAlibabaDataDisks() error = %v", err)
			}
			if test.wantErr != "" && (err == nil || !strings.Contains(err.Error(), test.wantErr)) {
				t.Fatalf("validateAlibabaDataDisks() error = %v, want %q", err, test.wantErr)
			}
		})
	}
}

func TestPlanAlibabaDataDiskAttachments(t *testing.T) {
	disks := []alibabaDataDisk{
		{id: "d-new", zone: "cn-hangzhou-i", status: "Available", diskType: "data", portable: true, multiAttach: "Disabled"},
		{id: "d-existing", zone: "cn-hangzhou-i", status: "In_use", instanceID: "i-peerpod", diskType: "data", portable: true, multiAttach: "Disabled", hasDeleteWithInstance: true},
	}
	toAttach, alreadyAttached, err := planAlibabaDataDiskAttachments(
		"i-peerpod", "cn-hangzhou-i", []string{"d-new", "d-existing"}, disks,
	)
	if err != nil {
		t.Fatalf("planAlibabaDataDiskAttachments() error = %v", err)
	}
	if !reflect.DeepEqual(toAttach, []string{"d-new"}) || !reflect.DeepEqual(alreadyAttached, []string{"d-existing"}) {
		t.Fatalf("unexpected plan: attach=%v existing=%v", toAttach, alreadyAttached)
	}

	disks[0].zone = "cn-shanghai-a"
	if _, _, err := planAlibabaDataDiskAttachments("i-peerpod", "cn-hangzhou-i", []string{"d-new"}, disks); err == nil {
		t.Fatal("expected a cross-zone disk to be rejected")
	}
	for _, mode := range []string{"", "Enabled"} {
		disks[0].zone = "cn-hangzhou-i"
		disks[0].multiAttach = mode
		if _, _, err := planAlibabaDataDiskAttachments("i-peerpod", "cn-hangzhou-i", []string{"d-new"}, disks); err == nil {
			t.Fatalf("expected multi-attach mode %q to be rejected", mode)
		}
	}
}

func TestWaitForDataDiskAttachedStateRejectsMultiAttach(t *testing.T) {
	for _, mode := range []string{"", "Enabled"} {
		t.Run(mode, func(t *testing.T) {
			client := newFakeVolumeECSClient(map[string]*fakeAlibabaDisk{
				"d-one": {
					status: "In_use", instanceID: "i-peerpod", zone: "cn-hangzhou-i",
					multiAttach: mode, hasMultiAttach: true, deleteWithInstance: tea.Bool(false),
				},
			})
			err := waitForDataDiskAttachedState(context.Background(), client, "cn-hangzhou", "i-peerpod", "d-one")
			if err == nil || !strings.Contains(err.Error(), "unsupported multi-attach") {
				t.Fatalf("mode %q error = %v", mode, err)
			}
		})
	}
}

func TestAttachAlibabaDataDisks(t *testing.T) {
	client := newFakeVolumeECSClient(map[string]*fakeAlibabaDisk{
		"d-one": {status: "Available", zone: "cn-hangzhou-i"},
		"d-two": {status: "Available", zone: "cn-hangzhou-i"},
	})
	p := &alibabaCloudProvider{
		ecsClient:     client,
		serviceConfig: &Config{Region: "cn-hangzhou"},
	}
	volumes := []provider.CloudVolume{{DiskID: "d-one"}, {DiskID: "d-two"}}

	attached, err := p.attachDataDisks(context.Background(), "i-peerpod", volumes)
	if err != nil {
		t.Fatalf("attachDataDisks() error = %v", err)
	}
	if !reflect.DeepEqual(attached, []string{"d-one", "d-two"}) {
		t.Fatalf("attachDataDisks() = %v", attached)
	}
	if !reflect.DeepEqual(client.attachOrder, []string{"d-one", "d-two"}) {
		t.Fatalf("attach order = %v", client.attachOrder)
	}

	for diskID, disk := range client.disks {
		if disk.status != "In_use" || disk.instanceID != "i-peerpod" || tea.BoolValue(disk.deleteWithInstance) {
			t.Errorf("disk %s was not attached as retained: %+v", diskID, disk)
		}
	}
}

func TestAttachDataDisksReconcilesAmbiguousSuccess(t *testing.T) {
	client := newFakeVolumeECSClient(map[string]*fakeAlibabaDisk{
		"d-one": {status: "Available", zone: "cn-hangzhou-i"},
	})
	client.attachErrors["d-one"] = context.DeadlineExceeded
	client.attachApplied["d-one"] = true
	p := &alibabaCloudProvider{ecsClient: client, serviceConfig: &Config{Region: "cn-hangzhou"}}

	attached, err := p.attachDataDisks(context.Background(), "i-peerpod", []provider.CloudVolume{{DiskID: "d-one"}})
	if err != nil {
		t.Fatalf("attachDataDisks() error = %v", err)
	}
	if !reflect.DeepEqual(attached, []string{"d-one"}) {
		t.Fatalf("attachDataDisks() = %v", attached)
	}
}

func TestAttachDataDisksFailsClosedOnDefinitiveError(t *testing.T) {
	client := newFakeVolumeECSClient(map[string]*fakeAlibabaDisk{
		"d-one": {status: "Available", zone: "cn-hangzhou-i"},
	})
	status := 403
	client.attachErrors["d-one"] = &tea.SDKError{StatusCode: &status, Code: tea.String("Forbidden")}
	p := &alibabaCloudProvider{ecsClient: client, serviceConfig: &Config{Region: "cn-hangzhou"}}

	attached, err := p.attachDataDisks(context.Background(), "i-peerpod", []provider.CloudVolume{{DiskID: "d-one"}})
	if err == nil || !strings.Contains(err.Error(), "attach disk d-one") {
		t.Fatalf("attachDataDisks() error = %v", err)
	}
	if !reflect.DeepEqual(attached, []string{"d-one"}) {
		t.Fatalf("attachDataDisks() partial acquisition = %v", attached)
	}
	if client.disks["d-one"].status != "Available" {
		t.Fatalf("definitively rejected attach changed disk state: %+v", client.disks["d-one"])
	}
}

func TestAttachDataDisksReturnsAcquisitionWhenVisibilityWaitIsCanceled(t *testing.T) {
	client := newFakeVolumeECSClient(map[string]*fakeAlibabaDisk{
		"d-one": {status: "Available", zone: "cn-hangzhou-i"},
	})
	ctx, cancel := context.WithCancel(context.Background())
	client.attachHook = func(string) { cancel() }
	p := &alibabaCloudProvider{ecsClient: client, serviceConfig: &Config{Region: "cn-hangzhou"}}

	attached, err := p.attachDataDisks(ctx, "i-peerpod", []provider.CloudVolume{{DiskID: "d-one"}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("attachDataDisks() error = %v, want context cancellation", err)
	}
	if !reflect.DeepEqual(attached, []string{"d-one"}) {
		t.Fatalf("attachDataDisks() partial acquisition = %v", attached)
	}
	if disk := client.disks["d-one"]; disk.status != "In_use" || disk.instanceID != "i-peerpod" {
		t.Fatalf("partially observed disk acquisition was not retained for caller cleanup: %+v", disk)
	}
}
