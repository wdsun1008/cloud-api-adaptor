// (C) Copyright Confidential Containers Contributors
// SPDX-License-Identifier: Apache-2.0

package alibabacloud

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"time"

	ecs "github.com/alibabacloud-go/ecs-20140526/v4/client"
	"github.com/alibabacloud-go/tea/tea"

	provider "github.com/confidential-containers/cloud-api-adaptor/src/cloud-providers"
)

const (
	maxAlibabaDataDisks       = 16
	instanceAttachableTimeout = 5 * time.Minute
	dataDiskStateTimeout      = time.Minute
	dataDiskPollInterval      = 2 * time.Second
)

var alibabaDataDiskIDPattern = regexp.MustCompile(`^d-[A-Za-z0-9]+$`)

type alibabaDataDisk struct {
	id                    string
	zone                  string
	status                string
	instanceID            string
	diskType              string
	multiAttach           string
	portable              bool
	deleteWithInstance    bool
	hasDeleteWithInstance bool
}

func validateAlibabaDataDisks(volumes []provider.CloudVolume) ([]string, error) {
	if len(volumes) > maxAlibabaDataDisks {
		return nil, fmt.Errorf("Alibaba Cloud supports at most %d peer-pod data disks", maxAlibabaDataDisks)
	}
	diskIDs := make([]string, 0, len(volumes))
	seen := make(map[string]struct{}, len(volumes))
	for _, volume := range volumes {
		if !alibabaDataDiskIDPattern.MatchString(volume.DiskID) {
			return nil, fmt.Errorf("invalid Alibaba Cloud disk ID %q", volume.DiskID)
		}
		if _, exists := seen[volume.DiskID]; exists {
			return nil, fmt.Errorf("duplicate Alibaba Cloud disk ID %q", volume.DiskID)
		}
		seen[volume.DiskID] = struct{}{}
		diskIDs = append(diskIDs, volume.DiskID)
	}
	return diskIDs, nil
}

func (p *alibabaCloudProvider) attachDataDisks(ctx context.Context, instanceID string, volumes []provider.CloudVolume) ([]string, error) {
	diskIDs, err := validateAlibabaDataDisks(volumes)
	if err != nil || len(diskIDs) == 0 {
		return nil, err
	}
	zone, err := waitForAttachableInstance(ctx, p.ecsClient, instanceID)
	if err != nil {
		return nil, err
	}
	disks, err := describeAlibabaDataDisks(ctx, p.ecsClient, p.serviceConfig.Region, diskIDs)
	if err != nil {
		return nil, err
	}
	toAttach, alreadyAttached, err := planAlibabaDataDiskAttachments(instanceID, zone, diskIDs, disks)
	if err != nil {
		return nil, err
	}

	attached := append([]string(nil), alreadyAttached...)
	for _, diskID := range toAttach {
		request := &ecs.AttachDiskRequest{
			InstanceId:         tea.String(instanceID),
			DiskId:             tea.String(diskID),
			DeleteWithInstance: tea.Bool(false),
			Bootable:           tea.Bool(false),
		}
		logger.Printf("Attaching retained data disk %s to instance %s", diskID, instanceID)
		// Once the mutating request starts, treat the disk as possibly acquired.
		// Cleanup safely re-describes it and is a no-op if the service rejected
		// the request before changing the disk.
		attached = append(attached, diskID)
		if _, err := p.ecsClient.AttachDisk(request); err != nil {
			if !isAmbiguousAlibabaCloudError(err) {
				return attached, fmt.Errorf("attach disk %s: %w", diskID, err)
			}
			if reconcileErr := reconcileDataDiskAttach(context.WithoutCancel(ctx), p.ecsClient, p.serviceConfig.Region, instanceID, diskID); reconcileErr != nil {
				return attached, fmt.Errorf("attach disk %s returned %v; reconciliation failed: %w", diskID, err, reconcileErr)
			}
		} else if err := waitForDataDiskAttachedState(ctx, p.ecsClient, p.serviceConfig.Region, instanceID, diskID); err != nil {
			return attached, err
		}
	}
	return attached, nil
}

func waitForAttachableInstance(ctx context.Context, client ecsClient, instanceID string) (string, error) {
	// TDX instances can remain Starting for more than a minute while firmware
	// and memory initialization complete. Disk state transitions use the shorter
	// timeout below, but do not tear down a healthy CVM before it is attachable.
	ctx, cancel := context.WithTimeout(ctx, instanceAttachableTimeout)
	defer cancel()
	for {
		response, err := client.DescribeInstanceAttribute(&ecs.DescribeInstanceAttributeRequest{InstanceId: tea.String(instanceID)})
		if err != nil {
			return "", fmt.Errorf("describe instance %s: %w", instanceID, err)
		}
		if response == nil || response.Body == nil {
			return "", errors.New("DescribeInstanceAttribute returned an incomplete response")
		}
		switch status := tea.StringValue(response.Body.Status); status {
		case "Running":
			zone := tea.StringValue(response.Body.ZoneId)
			if zone == "" {
				return "", fmt.Errorf("instance %s has no zone", instanceID)
			}
			return zone, nil
		case "Pending", "Starting", "Stopping", "Stopped":
		default:
			return "", fmt.Errorf("instance %s is not attachable from state %q", instanceID, status)
		}
		if err := waitForDataDiskPoll(ctx); err != nil {
			return "", fmt.Errorf("waiting for instance %s to become attachable: %w", instanceID, err)
		}
	}
}

func describeAlibabaDataDisks(ctx context.Context, client ecsClient, region string, diskIDs []string) ([]alibabaDataDisk, error) {
	if len(diskIDs) == 0 {
		return nil, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	encodedIDs, err := json.Marshal(diskIDs)
	if err != nil {
		return nil, err
	}
	response, err := client.DescribeDisks(&ecs.DescribeDisksRequest{
		RegionId: tea.String(region), DiskIds: tea.String(string(encodedIDs)),
		DiskType: tea.String("data"), PageSize: tea.Int32(100),
	})
	if err != nil {
		return nil, fmt.Errorf("describe data disks: %w", err)
	}
	return parseAlibabaDataDisksResponse(response)
}

func describeAlibabaAttachedDataDisks(ctx context.Context, client ecsClient, region, instanceID string) ([]alibabaDataDisk, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	response, err := client.DescribeDisks(&ecs.DescribeDisksRequest{
		RegionId: tea.String(region), InstanceId: tea.String(instanceID),
		DiskType: tea.String("data"), PageSize: tea.Int32(100),
	})
	if err != nil {
		return nil, fmt.Errorf("describe data disks attached to instance %s: %w", instanceID, err)
	}
	return parseAlibabaDataDisksResponse(response)
}

func parseAlibabaDataDisksResponse(response *ecs.DescribeDisksResponse) ([]alibabaDataDisk, error) {
	if response == nil || response.Body == nil || response.Body.Disks == nil {
		return nil, errors.New("DescribeDisks returned an incomplete response")
	}
	if tea.StringValue(response.Body.NextToken) != "" {
		return nil, errors.New("DescribeDisks returned a truncated response")
	}
	items := response.Body.Disks.Disk
	if response.Body.TotalCount != nil && int(tea.Int32Value(response.Body.TotalCount)) != len(items) {
		return nil, fmt.Errorf("DescribeDisks reported %d disks but returned %d", tea.Int32Value(response.Body.TotalCount), len(items))
	}
	disks := make([]alibabaDataDisk, 0, len(response.Body.Disks.Disk))
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		if item == nil {
			return nil, errors.New("DescribeDisks returned an empty disk entry")
		}
		diskID := tea.StringValue(item.DiskId)
		if diskID == "" {
			return nil, errors.New("DescribeDisks returned a disk without an ID")
		}
		if _, found := seen[diskID]; found {
			return nil, fmt.Errorf("DescribeDisks returned duplicate disk %s", diskID)
		}
		seen[diskID] = struct{}{}
		disks = append(disks, alibabaDataDisk{
			id: diskID, zone: tea.StringValue(item.ZoneId),
			status: tea.StringValue(item.Status), instanceID: tea.StringValue(item.InstanceId),
			diskType: tea.StringValue(item.Type), multiAttach: tea.StringValue(item.MultiAttach),
			portable: tea.BoolValue(item.Portable), deleteWithInstance: tea.BoolValue(item.DeleteWithInstance),
			hasDeleteWithInstance: item.DeleteWithInstance != nil,
		})
	}
	return disks, nil
}

func (p *alibabaCloudProvider) retainedDataDisksForInstanceDelete(ctx context.Context, instanceID string) ([]string, error) {
	p.volumesMu.Lock()
	tracked := append([]string(nil), p.volumes[instanceID]...)
	p.volumesMu.Unlock()

	attached, err := describeAlibabaAttachedDataDisks(ctx, p.ecsClient, p.serviceConfig.Region, instanceID)
	if err != nil {
		return nil, err
	}
	attachedIDs := make(map[string]struct{}, len(attached))
	known := make(map[string]struct{}, len(tracked)+len(attached))
	for _, diskID := range tracked {
		known[diskID] = struct{}{}
	}
	for _, disk := range attached {
		attachedIDs[disk.id] = struct{}{}
		known[disk.id] = struct{}{}
	}
	if len(known) > maxAlibabaDataDisks {
		return nil, fmt.Errorf("instance %s has %d data disks, exceeding the supported maximum %d", instanceID, len(known), maxAlibabaDataDisks)
	}
	diskIDs := make([]string, 0, len(known))
	for diskID := range known {
		if !alibabaDataDiskIDPattern.MatchString(diskID) {
			return nil, fmt.Errorf("invalid Alibaba Cloud disk ID %q", diskID)
		}
		diskIDs = append(diskIDs, diskID)
	}
	sort.Strings(diskIDs)
	if len(diskIDs) == 0 {
		return nil, nil
	}

	disks, err := describeAlibabaDataDisks(ctx, p.ecsClient, p.serviceConfig.Region, diskIDs)
	if err != nil {
		return nil, err
	}
	byID := make(map[string]alibabaDataDisk, len(disks))
	for _, disk := range disks {
		if _, requested := known[disk.id]; !requested {
			return nil, fmt.Errorf("DescribeDisks returned unrequested data disk %s", disk.id)
		}
		byID[disk.id] = disk
	}
	retained := make([]string, 0, len(diskIDs))
	for _, diskID := range diskIDs {
		disk, found := byID[diskID]
		if !found {
			if _, wasAttached := attachedIDs[diskID]; wasAttached {
				return nil, fmt.Errorf("data disk %s disappeared while validating its attachment to instance %s", diskID, instanceID)
			}
			logger.Printf("Dropping stale tracking for data disk %s because it no longer exists", diskID)
			continue
		}
		_, relevant, err := classifyRetainedAlibabaDataDisk(instanceID, disk)
		if err != nil {
			return nil, err
		}
		if !relevant {
			if _, wasAttached := attachedIDs[diskID]; wasAttached {
				return nil, fmt.Errorf("data disk %s changed attachment while validating instance %s", diskID, instanceID)
			}
			logger.Printf("Dropping stale tracking for data disk %s because it is now attached to instance %s", diskID, disk.instanceID)
			continue
		}
		retained = append(retained, diskID)
	}
	return retained, nil
}

func classifyRetainedAlibabaDataDisk(instanceID string, disk alibabaDataDisk) (available, relevant bool, err error) {
	if disk.diskType != "data" || !disk.portable {
		return false, false, fmt.Errorf("disk %s is not a detachable data disk", disk.id)
	}
	if disk.multiAttach != "Disabled" {
		return false, false, fmt.Errorf("disk %s has unsupported multi-attach mode %q", disk.id, disk.multiAttach)
	}
	if !disk.hasDeleteWithInstance || disk.deleteWithInstance {
		return false, false, fmt.Errorf("disk %s does not explicitly set DeleteWithInstance=false", disk.id)
	}
	switch disk.status {
	case "Available":
		if disk.instanceID != "" {
			return false, false, fmt.Errorf("available disk %s is unexpectedly bound to instance %s", disk.id, disk.instanceID)
		}
		return true, true, nil
	case "In_use":
		if disk.instanceID == "" {
			return false, false, fmt.Errorf("in-use disk %s has no instance identity", disk.id)
		}
		return false, disk.instanceID == instanceID, nil
	case "Attaching", "Detaching":
		if disk.instanceID == "" || disk.instanceID == instanceID {
			return false, true, nil
		}
		return false, false, nil
	default:
		return false, false, fmt.Errorf("disk %s is in unsupported cleanup state %q", disk.id, disk.status)
	}
}

func (p *alibabaCloudProvider) rememberInstanceVolumes(instanceID string, diskIDs []string) {
	p.volumesMu.Lock()
	defer p.volumesMu.Unlock()
	if p.volumes == nil {
		p.volumes = make(map[string][]string)
	}
	p.volumes[instanceID] = append([]string(nil), diskIDs...)
}

func (p *alibabaCloudProvider) forgetInstanceVolumes(instanceID string) {
	p.volumesMu.Lock()
	defer p.volumesMu.Unlock()
	delete(p.volumes, instanceID)
}

func (p *alibabaCloudProvider) waitForRetainedDataDisks(ctx context.Context, instanceID string, diskIDs []string) error {
	for len(diskIDs) > 0 {
		disks, err := describeAlibabaDataDisks(ctx, p.ecsClient, p.serviceConfig.Region, diskIDs)
		if err != nil {
			return err
		}
		requested := make(map[string]struct{}, len(diskIDs))
		for _, diskID := range diskIDs {
			requested[diskID] = struct{}{}
		}
		byID := make(map[string]alibabaDataDisk, len(disks))
		for _, disk := range disks {
			if _, found := requested[disk.id]; !found {
				return fmt.Errorf("DescribeDisks returned unrequested data disk %s", disk.id)
			}
			byID[disk.id] = disk
		}
		remaining := make([]string, 0, len(diskIDs))
		for _, diskID := range diskIDs {
			disk, found := byID[diskID]
			if !found {
				logger.Printf("Retained data disk %s no longer exists; cleanup for instance %s is complete for that disk", diskID, instanceID)
				continue
			}
			available, relevant, err := classifyRetainedAlibabaDataDisk(instanceID, disk)
			if err != nil {
				return err
			}
			if !relevant {
				logger.Printf("Retained data disk %s is now attached to instance %s; cleanup for instance %s is complete for that disk", diskID, disk.instanceID, instanceID)
				continue
			}
			if !available {
				remaining = append(remaining, diskID)
			}
		}
		if len(remaining) == 0 {
			return nil
		}
		diskIDs = remaining
		if err := waitForAlibabaCleanupPoll(ctx); err != nil {
			return err
		}
	}
	return nil
}

func planAlibabaDataDiskAttachments(instanceID, zone string, diskIDs []string, disks []alibabaDataDisk) (toAttach, alreadyAttached []string, err error) {
	byID := make(map[string]alibabaDataDisk, len(disks))
	for _, disk := range disks {
		byID[disk.id] = disk
	}
	for _, diskID := range diskIDs {
		disk, found := byID[diskID]
		if !found {
			return nil, nil, fmt.Errorf("data disk %s was not returned by DescribeDisks", diskID)
		}
		if disk.diskType != "data" || !disk.portable {
			return nil, nil, fmt.Errorf("disk %s is not a detachable data disk", diskID)
		}
		if disk.zone != zone {
			return nil, nil, fmt.Errorf("disk %s is in zone %s, instance %s is in zone %s", diskID, disk.zone, instanceID, zone)
		}
		if disk.multiAttach != "Disabled" {
			return nil, nil, fmt.Errorf("disk %s has unsupported multi-attach mode %q", diskID, disk.multiAttach)
		}
		switch {
		case disk.status == "Available" && disk.instanceID == "":
			toAttach = append(toAttach, diskID)
		case disk.status == "In_use" && disk.instanceID == instanceID && disk.hasDeleteWithInstance && !disk.deleteWithInstance:
			alreadyAttached = append(alreadyAttached, diskID)
		default:
			return nil, nil, fmt.Errorf("disk %s cannot attach from state %q (instance %q)", diskID, disk.status, disk.instanceID)
		}
	}
	return toAttach, alreadyAttached, nil
}

func waitForDataDiskAttachedState(ctx context.Context, client ecsClient, region, instanceID, diskID string) error {
	ctx, cancel := context.WithTimeout(ctx, dataDiskStateTimeout)
	defer cancel()
	for {
		disks, err := describeAlibabaDataDisks(ctx, client, region, []string{diskID})
		if err != nil {
			return err
		}
		if len(disks) != 1 {
			return fmt.Errorf("disk %s was not uniquely returned while waiting for state", diskID)
		}
		disk := disks[0]
		if disk.multiAttach != "Disabled" {
			return fmt.Errorf("disk %s has unsupported multi-attach mode %q", diskID, disk.multiAttach)
		}
		if disk.status == "In_use" && disk.instanceID == instanceID && disk.hasDeleteWithInstance && !disk.deleteWithInstance {
			return nil
		}
		if disk.status != "Available" && disk.status != "Attaching" {
			return fmt.Errorf("disk %s entered state %q while attaching", diskID, disk.status)
		}
		if err := waitForDataDiskPoll(ctx); err != nil {
			return fmt.Errorf("waiting for disk %s state: %w", diskID, err)
		}
	}
}

func reconcileDataDiskAttach(ctx context.Context, client ecsClient, region, instanceID, diskID string) error {
	return waitForDataDiskAttachedState(ctx, client, region, instanceID, diskID)
}

func waitForDataDiskPoll(ctx context.Context) error {
	timer := time.NewTimer(dataDiskPollInterval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// isAmbiguousAlibabaCloudError reports whether the request may have reached the
// service even though the client did not receive a conclusive response.
func isAmbiguousAlibabaCloudError(err error) bool {
	var sdkErr *tea.SDKError
	if errors.As(err, &sdkErr) && sdkErr.StatusCode != nil {
		status := *sdkErr.StatusCode
		return status == 408 || status == 429 || status >= 500
	}
	var netErr net.Error
	return errors.As(err, &netErr) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
}
