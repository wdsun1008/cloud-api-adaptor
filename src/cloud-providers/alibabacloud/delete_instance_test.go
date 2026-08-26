// (C) Copyright Confidential Containers Contributors
// SPDX-License-Identifier: Apache-2.0

package alibabacloud

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	ecs "github.com/alibabacloud-go/ecs-20140526/v4/client"
	"github.com/alibabacloud-go/tea/tea"
)

type fakeDeleteOutcome struct {
	err     error
	applied bool
}

type fakeCleanupDisk struct {
	status             string
	instanceID         string
	diskType           string
	multiAttach        string
	portable           bool
	deleteWithInstance *bool
}

type fakeCleanupECSClient struct {
	*ecs.Client

	mu                    sync.Mutex
	instanceID            string
	instanceExists        bool
	disks                 map[string]*fakeCleanupDisk
	deleteOutcomes        []fakeDeleteOutcome
	deleteCalls           int
	deleteForce           []bool
	describeAttachedCalls int
	releaseAfter          int
	diskPollsAfterDelete  int
	operationLocks        []string
	rebindAfter           int
	rebindInstanceID      string
	omitSpecificDisk      bool
}

func retainedFakeDisk(instanceID string) *fakeCleanupDisk {
	return &fakeCleanupDisk{
		status: "In_use", instanceID: instanceID, diskType: "data",
		multiAttach: "Disabled", portable: true, deleteWithInstance: tea.Bool(false),
	}
}

func (f *fakeCleanupECSClient) DeleteInstance(request *ecs.DeleteInstanceRequest) (*ecs.DeleteInstanceResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleteForce = append(f.deleteForce, tea.BoolValue(request.Force))
	index := f.deleteCalls
	f.deleteCalls++
	if tea.StringValue(request.InstanceId) != f.instanceID || !f.instanceExists {
		return nil, fakeSDKError(404, "InvalidInstanceId.NotFound")
	}
	outcome := fakeDeleteOutcome{applied: true}
	if index < len(f.deleteOutcomes) {
		outcome = f.deleteOutcomes[index]
	}
	if outcome.applied {
		f.instanceExists = false
		for _, disk := range f.disks {
			if disk.instanceID == f.instanceID {
				disk.status = "Detaching"
			}
		}
		if f.releaseAfter == 0 {
			f.releaseDisksLocked()
		}
	}
	return &ecs.DeleteInstanceResponse{Body: &ecs.DeleteInstanceResponseBody{}}, outcome.err
}

func (f *fakeCleanupECSClient) DescribeInstanceAttribute(request *ecs.DescribeInstanceAttributeRequest) (*ecs.DescribeInstanceAttributeResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if tea.StringValue(request.InstanceId) != f.instanceID || !f.instanceExists {
		return nil, fakeSDKError(404, "InvalidInstanceId.NotFound")
	}
	locks := make([]*ecs.DescribeInstanceAttributeResponseBodyOperationLocksLockReason, 0, len(f.operationLocks))
	for _, reason := range f.operationLocks {
		locks = append(locks, &ecs.DescribeInstanceAttributeResponseBodyOperationLocksLockReason{
			LockReason: tea.String(reason),
		})
	}
	return &ecs.DescribeInstanceAttributeResponse{Body: &ecs.DescribeInstanceAttributeResponseBody{
		Status:         tea.String("Running"),
		OperationLocks: &ecs.DescribeInstanceAttributeResponseBodyOperationLocks{LockReason: locks},
	}}, nil
}

func (f *fakeCleanupECSClient) DescribeDisks(request *ecs.DescribeDisksRequest) (*ecs.DescribeDisksResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	var diskIDs []string
	if instanceID := tea.StringValue(request.InstanceId); instanceID != "" {
		f.describeAttachedCalls++
		for diskID, disk := range f.disks {
			if disk.instanceID == instanceID {
				diskIDs = append(diskIDs, diskID)
			}
		}
	} else if err := json.Unmarshal([]byte(tea.StringValue(request.DiskIds)), &diskIDs); err != nil {
		return nil, err
	}

	if !f.instanceExists && tea.StringValue(request.DiskIds) != "" {
		f.diskPollsAfterDelete++
		if f.rebindAfter > 0 && f.diskPollsAfterDelete >= f.rebindAfter {
			f.rebindDisksLocked()
		} else if f.releaseAfter > 0 && f.diskPollsAfterDelete >= f.releaseAfter {
			f.releaseDisksLocked()
		}
	}

	items := make([]*ecs.DescribeDisksResponseBodyDisksDisk, 0, len(diskIDs))
	for _, diskID := range diskIDs {
		if f.omitSpecificDisk && tea.StringValue(request.DiskIds) != "" {
			continue
		}
		disk := f.disks[diskID]
		if disk == nil {
			continue
		}
		items = append(items, &ecs.DescribeDisksResponseBodyDisksDisk{
			DiskId: tea.String(diskID), Status: tea.String(disk.status),
			InstanceId: tea.String(disk.instanceID), Type: tea.String(disk.diskType),
			MultiAttach: diskString(disk.multiAttach), Portable: tea.Bool(disk.portable),
			DeleteWithInstance: disk.deleteWithInstance,
		})
	}
	total := int32(len(items))
	return &ecs.DescribeDisksResponse{Body: &ecs.DescribeDisksResponseBody{
		TotalCount: &total, Disks: &ecs.DescribeDisksResponseBodyDisks{Disk: items},
	}}, nil
}

func diskString(value string) *string {
	if value == "" {
		return nil
	}
	return tea.String(value)
}

func (f *fakeCleanupECSClient) releaseDisksLocked() {
	for _, disk := range f.disks {
		if disk.instanceID == f.instanceID {
			disk.status = "Available"
			disk.instanceID = ""
		}
	}
}

func (f *fakeCleanupECSClient) rebindDisksLocked() {
	for _, disk := range f.disks {
		if disk.instanceID == f.instanceID {
			disk.status = "In_use"
			disk.instanceID = f.rebindInstanceID
		}
	}
}

func fakeSDKError(status int, code string) error {
	return &tea.SDKError{StatusCode: tea.Int(status), Code: tea.String(code)}
}

func newCleanupTestProvider(client *fakeCleanupECSClient, tracked ...string) *alibabaCloudProvider {
	volumes := make(map[string][]string)
	if tracked != nil {
		volumes[client.instanceID] = append([]string(nil), tracked...)
	}
	return &alibabaCloudProvider{
		ecsClient: client, serviceConfig: &Config{Region: "cn-hangzhou"},
		volumes: volumes,
	}
}

func useFastCleanupTimings(t *testing.T) {
	t.Helper()
	oldTimeout, oldPoll := instanceCleanupTimeout, instanceCleanupPollInterval
	instanceCleanupTimeout = 250 * time.Millisecond
	instanceCleanupPollInterval = time.Millisecond
	t.Cleanup(func() {
		instanceCleanupTimeout = oldTimeout
		instanceCleanupPollInterval = oldPoll
	})
}

func TestDeleteInstanceForceDeletesBeforeWaitingForRetainedDisk(t *testing.T) {
	useFastCleanupTimings(t)
	client := &fakeCleanupECSClient{
		instanceID: "i-peerpod", instanceExists: true, releaseAfter: 3,
		disks: map[string]*fakeCleanupDisk{"d-workspace": retainedFakeDisk("i-peerpod")},
	}
	p := newCleanupTestProvider(client, "d-workspace")

	if err := p.DeleteInstance(context.Background(), "i-peerpod"); err != nil {
		t.Fatalf("DeleteInstance() error = %v", err)
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.deleteCalls != 1 || len(client.deleteForce) != 1 || !client.deleteForce[0] {
		t.Fatalf("DeleteInstance calls=%d Force=%v", client.deleteCalls, client.deleteForce)
	}
	if client.diskPollsAfterDelete < 3 {
		t.Fatalf("retained disk polls after delete = %d, want at least 3", client.diskPollsAfterDelete)
	}
	if disk := client.disks["d-workspace"]; disk.status != "Available" || disk.instanceID != "" {
		t.Fatalf("retained disk final state = %+v", disk)
	}
}

func TestDeleteInstanceFailsClosedForUnsafeRetainedDisk(t *testing.T) {
	useFastCleanupTimings(t)
	tests := []struct {
		name    string
		disk    *fakeCleanupDisk
		tracked bool
		want    string
	}{
		{name: "DeleteWithInstance true", disk: func() *fakeCleanupDisk {
			disk := retainedFakeDisk("i-peerpod")
			disk.deleteWithInstance = tea.Bool(true)
			return disk
		}(), want: "DeleteWithInstance=false"},
		{name: "DeleteWithInstance missing", disk: func() *fakeCleanupDisk {
			disk := retainedFakeDisk("i-peerpod")
			disk.deleteWithInstance = nil
			return disk
		}(), want: "DeleteWithInstance=false"},
		{name: "other instance cannot weaken retention", disk: func() *fakeCleanupDisk {
			disk := retainedFakeDisk("i-other")
			disk.deleteWithInstance = tea.Bool(true)
			return disk
		}(), tracked: true, want: "DeleteWithInstance=false"},
		{name: "multi-attach", disk: func() *fakeCleanupDisk {
			disk := retainedFakeDisk("i-peerpod")
			disk.multiAttach = "Enabled"
			return disk
		}(), want: "multi-attach"},
		{name: "non-data", disk: func() *fakeCleanupDisk {
			disk := retainedFakeDisk("i-peerpod")
			disk.diskType = "system"
			return disk
		}(), want: "detachable data disk"},
		{name: "non-portable", disk: func() *fakeCleanupDisk {
			disk := retainedFakeDisk("i-peerpod")
			disk.portable = false
			return disk
		}(), want: "detachable data disk"},
		{name: "available but bound", disk: func() *fakeCleanupDisk {
			disk := retainedFakeDisk("i-peerpod")
			disk.status = "Available"
			return disk
		}(), tracked: true, want: "unexpectedly bound"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &fakeCleanupECSClient{
				instanceID: "i-peerpod", instanceExists: true,
				disks: map[string]*fakeCleanupDisk{"d-workspace": test.disk},
			}
			var p *alibabaCloudProvider
			if test.tracked {
				p = newCleanupTestProvider(client, "d-workspace")
			} else {
				p = newCleanupTestProvider(client)
			}
			err := p.DeleteInstance(context.Background(), "i-peerpod")
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("DeleteInstance() error = %v, want %q", err, test.want)
			}
			if client.deleteCalls != 0 {
				t.Fatalf("unsafe disk reached DeleteInstance %d time(s)", client.deleteCalls)
			}
		})
	}
}

func TestDeleteInstancePrunesStaleTrackedDisk(t *testing.T) {
	useFastCleanupTimings(t)
	tests := []struct {
		name  string
		disks map[string]*fakeCleanupDisk
	}{
		{name: "deleted", disks: map[string]*fakeCleanupDisk{}},
		{name: "rebound", disks: map[string]*fakeCleanupDisk{"d-workspace": retainedFakeDisk("i-other")}},
		{name: "transitioning elsewhere", disks: map[string]*fakeCleanupDisk{"d-workspace": func() *fakeCleanupDisk {
			disk := retainedFakeDisk("i-other")
			disk.status = "Attaching"
			return disk
		}()}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &fakeCleanupECSClient{
				instanceID: "i-peerpod", instanceExists: true, disks: test.disks,
			}
			p := newCleanupTestProvider(client, "d-workspace")
			if err := p.DeleteInstance(context.Background(), "i-peerpod"); err != nil {
				t.Fatalf("DeleteInstance() error = %v", err)
			}
			if client.deleteCalls != 1 {
				t.Fatalf("DeleteInstance calls = %d, want one", client.deleteCalls)
			}
		})
	}
}

func TestDeleteInstanceDoesNotPruneDiskObservedOnTarget(t *testing.T) {
	useFastCleanupTimings(t)
	client := &fakeCleanupECSClient{
		instanceID: "i-peerpod", instanceExists: true, omitSpecificDisk: true,
		disks: map[string]*fakeCleanupDisk{"d-workspace": retainedFakeDisk("i-peerpod")},
	}
	p := newCleanupTestProvider(client)
	err := p.DeleteInstance(context.Background(), "i-peerpod")
	if err == nil || !strings.Contains(err.Error(), "disappeared while validating") {
		t.Fatalf("DeleteInstance() error = %v", err)
	}
	if client.deleteCalls != 0 {
		t.Fatalf("inconsistent attached disk reached DeleteInstance %d time(s)", client.deleteCalls)
	}
}

func TestDeleteInstanceTreatsDiskReboundDuringWaitAsComplete(t *testing.T) {
	useFastCleanupTimings(t)
	client := &fakeCleanupECSClient{
		instanceID: "i-peerpod", instanceExists: true, releaseAfter: -1,
		rebindAfter: 2, rebindInstanceID: "i-replacement",
		disks: map[string]*fakeCleanupDisk{"d-workspace": retainedFakeDisk("i-peerpod")},
	}
	p := newCleanupTestProvider(client, "d-workspace")
	if err := p.DeleteInstance(context.Background(), "i-peerpod"); err != nil {
		t.Fatalf("DeleteInstance() error = %v", err)
	}
	client.mu.Lock()
	disk := *client.disks["d-workspace"]
	client.mu.Unlock()
	if disk.status != "In_use" || disk.instanceID != "i-replacement" {
		t.Fatalf("rebound disk state = %+v", disk)
	}
	p.volumesMu.Lock()
	_, tracked := p.volumes["i-peerpod"]
	p.volumesMu.Unlock()
	if tracked {
		t.Fatal("successful rebound reconciliation retained stale volume tracking")
	}
}

func TestDeleteInstanceHandlesAlreadyAbsentInstance(t *testing.T) {
	useFastCleanupTimings(t)
	client := &fakeCleanupECSClient{
		instanceID: "i-peerpod", disks: map[string]*fakeCleanupDisk{
			"d-workspace": {
				status: "Available", diskType: "data", multiAttach: "Disabled",
				portable: true, deleteWithInstance: tea.Bool(false),
			},
		},
	}
	p := newCleanupTestProvider(client, "d-workspace")
	if err := p.DeleteInstance(context.Background(), "i-peerpod"); err != nil {
		t.Fatalf("DeleteInstance() error = %v", err)
	}
	if client.deleteCalls != 0 {
		t.Fatalf("DeleteInstance calls = %d after preflight established absence", client.deleteCalls)
	}
}

func TestDeleteInstanceReconcilesAmbiguousOutcomes(t *testing.T) {
	useFastCleanupTimings(t)
	t.Run("unknown success", func(t *testing.T) {
		client := &fakeCleanupECSClient{
			instanceID: "i-peerpod", instanceExists: true,
			disks:          map[string]*fakeCleanupDisk{"d-workspace": retainedFakeDisk("i-peerpod")},
			deleteOutcomes: []fakeDeleteOutcome{{err: context.DeadlineExceeded, applied: true}},
		}
		p := newCleanupTestProvider(client, "d-workspace")
		if err := p.DeleteInstance(context.Background(), "i-peerpod"); err != nil {
			t.Fatalf("DeleteInstance() error = %v", err)
		}
		if client.deleteCalls != 1 {
			t.Fatalf("DeleteInstance calls = %d, want reconciliation without duplicate mutation", client.deleteCalls)
		}
	})

	t.Run("retry after unknown failure", func(t *testing.T) {
		client := &fakeCleanupECSClient{
			instanceID: "i-peerpod", instanceExists: true,
			disks:          map[string]*fakeCleanupDisk{"d-workspace": retainedFakeDisk("i-peerpod")},
			deleteOutcomes: []fakeDeleteOutcome{{err: context.DeadlineExceeded}, {applied: true}},
		}
		p := newCleanupTestProvider(client, "d-workspace")
		if err := p.DeleteInstance(context.Background(), "i-peerpod"); err != nil {
			t.Fatalf("DeleteInstance() error = %v", err)
		}
		if client.deleteCalls != 2 {
			t.Fatalf("DeleteInstance calls = %d, want retry", client.deleteCalls)
		}
	})
}

func TestDeleteInstanceRejectsDefinitiveAPIError(t *testing.T) {
	useFastCleanupTimings(t)
	client := &fakeCleanupECSClient{
		instanceID: "i-peerpod", instanceExists: true,
		disks:          map[string]*fakeCleanupDisk{"d-workspace": retainedFakeDisk("i-peerpod")},
		deleteOutcomes: []fakeDeleteOutcome{{err: fakeSDKError(403, "Forbidden")}},
	}
	p := newCleanupTestProvider(client, "d-workspace")
	err := p.DeleteInstance(context.Background(), "i-peerpod")
	if err == nil || !strings.Contains(err.Error(), "Forbidden") {
		t.Fatalf("DeleteInstance() error = %v", err)
	}
	if _, found := p.volumes["i-peerpod"]; !found {
		t.Fatal("definitive failure discarded retained-disk tracking")
	}
}

func TestDeleteInstanceFailsClosedForSecurityLock(t *testing.T) {
	useFastCleanupTimings(t)
	client := &fakeCleanupECSClient{
		instanceID: "i-peerpod", instanceExists: true, operationLocks: []string{"security"},
		disks: map[string]*fakeCleanupDisk{"d-workspace": retainedFakeDisk("i-peerpod")},
	}
	p := newCleanupTestProvider(client, "d-workspace")
	err := p.DeleteInstance(context.Background(), "i-peerpod")
	if err == nil || !strings.Contains(err.Error(), "security-locked") {
		t.Fatalf("DeleteInstance() error = %v", err)
	}
	if client.deleteCalls != 0 {
		t.Fatalf("security-locked instance reached DeleteInstance %d time(s)", client.deleteCalls)
	}
}

func TestDeleteInstanceRetriesDocumentedTransitionErrors(t *testing.T) {
	useFastCleanupTimings(t)
	for _, code := range []string{"IncorrectInstanceStatus.Initializing", "DependencyViolation.SLBConfiguring"} {
		t.Run(code, func(t *testing.T) {
			client := &fakeCleanupECSClient{
				instanceID: "i-peerpod", instanceExists: true,
				disks:          map[string]*fakeCleanupDisk{"d-workspace": retainedFakeDisk("i-peerpod")},
				deleteOutcomes: []fakeDeleteOutcome{{err: fakeSDKError(403, code)}, {applied: true}},
			}
			p := newCleanupTestProvider(client, "d-workspace")
			if err := p.DeleteInstance(context.Background(), "i-peerpod"); err != nil {
				t.Fatalf("DeleteInstance() error = %v", err)
			}
			if client.deleteCalls != 2 {
				t.Fatalf("DeleteInstance calls = %d, want transition retry", client.deleteCalls)
			}
		})
	}
}

func TestDeleteInstanceDiscoversDiskAfterProviderRestart(t *testing.T) {
	useFastCleanupTimings(t)
	client := &fakeCleanupECSClient{
		instanceID: "i-peerpod", instanceExists: true,
		disks: map[string]*fakeCleanupDisk{"d-workspace": retainedFakeDisk("i-peerpod")},
	}
	p := newCleanupTestProvider(client)
	if err := p.DeleteInstance(context.Background(), "i-peerpod"); err != nil {
		t.Fatalf("DeleteInstance() error = %v", err)
	}
	if client.describeAttachedCalls == 0 {
		t.Fatal("DeleteInstance did not discover attached data disks")
	}
}

func TestDeleteInstancePreservesTrackedVolumesOnDiskWaitTimeout(t *testing.T) {
	useFastCleanupTimings(t)
	instanceCleanupTimeout = 20 * time.Millisecond
	client := &fakeCleanupECSClient{
		instanceID: "i-peerpod", instanceExists: true, releaseAfter: -1,
		disks: map[string]*fakeCleanupDisk{"d-workspace": retainedFakeDisk("i-peerpod")},
	}
	p := newCleanupTestProvider(client, "d-workspace")

	err := p.DeleteInstance(context.Background(), "i-peerpod")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("DeleteInstance() error = %v, want cleanup deadline", err)
	}
	if _, found := p.volumes["i-peerpod"]; !found {
		t.Fatal("disk wait timeout discarded retained-disk tracking")
	}
}

func TestDeleteInstanceIgnoresCanceledParentWithinBoundedCleanup(t *testing.T) {
	useFastCleanupTimings(t)
	client := &fakeCleanupECSClient{
		instanceID: "i-peerpod", instanceExists: true,
		disks: map[string]*fakeCleanupDisk{"d-workspace": retainedFakeDisk("i-peerpod")},
	}
	p := newCleanupTestProvider(client, "d-workspace")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := p.DeleteInstance(ctx, "i-peerpod"); err != nil {
		t.Fatalf("DeleteInstance() error with canceled parent = %v", err)
	}
}

func TestDeleteInstanceIsIdempotentAndSerializesConcurrentCalls(t *testing.T) {
	useFastCleanupTimings(t)
	client := &fakeCleanupECSClient{
		instanceID: "i-peerpod", instanceExists: true, releaseAfter: 2,
		disks: map[string]*fakeCleanupDisk{"d-workspace": retainedFakeDisk("i-peerpod")},
	}
	p := newCleanupTestProvider(client, "d-workspace")

	var wg sync.WaitGroup
	errorsByCall := make([]error, 2)
	for index := range errorsByCall {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			errorsByCall[index] = p.DeleteInstance(context.Background(), "i-peerpod")
		}(index)
	}
	wg.Wait()
	for index, err := range errorsByCall {
		if err != nil {
			t.Fatalf("DeleteInstance call %d error = %v", index, err)
		}
	}
	if err := p.DeleteInstance(context.Background(), "i-peerpod"); err != nil {
		t.Fatalf("repeated DeleteInstance() error = %v", err)
	}
	p.deleteLocksMu.Lock()
	defer p.deleteLocksMu.Unlock()
	if len(p.deleteLocks) != 0 {
		t.Fatalf("delete locks leaked after calls: %v", p.deleteLocks)
	}
}
