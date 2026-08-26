// (C) Copyright Confidential Containers Contributors
// SPDX-License-Identifier: Apache-2.0

package alibabacloud

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	ecs "github.com/alibabacloud-go/ecs-20140526/v4/client"
	"github.com/alibabacloud-go/tea/tea"

	provider "github.com/confidential-containers/cloud-api-adaptor/src/cloud-providers"
)

const (
	sandboxIDTagKey         = "SandboxId"
	createOperationTagKey   = "CreateOperationId"
	createFingerprintTagKey = "CreateRequestFingerprint"
	createOperationDomain   = "confidential-containers/cloud-api-adaptor/alibabacloud/create-instance/v1\x00"
)

var (
	createReconcileTimeout  = 15 * time.Second
	createReconcileInterval = time.Second
)

type createOperation struct {
	id          string
	clientToken string
	fingerprint string
}

// createOperationForRequest binds Alibaba Cloud idempotency to the CRI
// sandbox lifetime. Retries, including retries after a provider restart, use
// the same ClientToken. A recreated CRI sandbox has a new sandbox ID and thus
// a new token.
func createOperationForRequest(sandboxID, fingerprint string) (createOperation, error) {
	if sandboxID == "" {
		return createOperation{}, errors.New("cannot create an Alibaba Cloud instance without a sandbox ID")
	}
	digest := sha256.Sum256([]byte(createOperationDomain + sandboxID))
	id := hex.EncodeToString(digest[:16])
	return createOperation{
		id: id, clientToken: "caa-" + id, fingerprint: fingerprint,
	}, nil
}

func instanceTagValue(instance *ecs.DescribeInstancesResponseBodyInstancesInstance, key string) string {
	if instance == nil || instance.Tags == nil {
		return ""
	}
	for _, tag := range instance.Tags.Tag {
		if tag != nil && tea.StringValue(tag.TagKey) == key {
			return tea.StringValue(tag.TagValue)
		}
	}
	return ""
}

func createRequestFingerprint(request *ecs.RunInstancesRequest, volumes []provider.CloudVolume) (string, error) {
	diskIDs := make([]string, len(volumes))
	for index, volume := range volumes {
		diskIDs[index] = volume.DiskID
	}
	payload, err := json.Marshal(struct {
		Request *ecs.RunInstancesRequest `json:"request"`
		Disks   []string                 `json:"disks"`
	}{Request: request, Disks: diskIDs})
	if err != nil {
		return "", fmt.Errorf("encode Alibaba Cloud create parameters: %w", err)
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]), nil
}

func runInstancesInstanceID(response *ecs.RunInstancesResponse) string {
	if response == nil || response.Body == nil || response.Body.InstanceIdSets == nil || len(response.Body.InstanceIdSets.InstanceIdSet) != 1 {
		return ""
	}
	return tea.StringValue(response.Body.InstanceIdSets.InstanceIdSet[0])
}

func (p *alibabaCloudProvider) runInstanceForCreateOperation(ctx context.Context, sandboxID string, request *ecs.RunInstancesRequest, operation createOperation) (string, error) {
	request.ClientToken = tea.String(operation.clientToken)
	request.Tag = append(request.Tag, &ecs.RunInstancesRequestTag{
		Key: tea.String(createOperationTagKey), Value: tea.String(operation.id),
	})
	response, runErr := p.ecsClient.RunInstances(request)
	instanceID := runInstancesInstanceID(response)
	if runErr != nil && instanceID == "" && !isAmbiguousAlibabaCloudError(runErr) {
		return "", fmt.Errorf("create Alibaba Cloud instance: %w", runErr)
	}
	if instanceID != "" {
		return instanceID, nil
	}

	if runErr != nil {
		logger.Printf("RunInstances outcome is unknown for operation %s; reconciling by tag", operation.id)
	}
	instanceID, err := p.reconcileCreateOperation(ctx, sandboxID, operation)
	if err != nil {
		return "", fmt.Errorf("reconcile Alibaba Cloud create operation: %w", err)
	}
	if instanceID == "" {
		if runErr == nil {
			runErr = errors.New("RunInstances returned no instance ID")
		}
		return "", fmt.Errorf("Alibaba Cloud create outcome remains unknown: %w", runErr)
	}
	return instanceID, nil
}

func (p *alibabaCloudProvider) reconcileCreateOperation(ctx context.Context, sandboxID string, operation createOperation) (string, error) {
	reconcileCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), createReconcileTimeout)
	defer cancel()
	for {
		response, err := p.ecsClient.DescribeInstances(&ecs.DescribeInstancesRequest{
			RegionId: tea.String(p.serviceConfig.Region),
			PageSize: tea.Int32(10),
			Tag: []*ecs.DescribeInstancesRequestTag{
				{Key: tea.String(sandboxIDTagKey), Value: tea.String(sandboxID)},
				{Key: tea.String(createOperationTagKey), Value: tea.String(operation.id)},
			},
		})
		if err != nil {
			return "", err
		}
		instanceID, err := reconciledCreateInstanceID(response, sandboxID, operation)
		if err != nil || instanceID != "" {
			return instanceID, err
		}

		timer := time.NewTimer(createReconcileInterval)
		select {
		case <-reconcileCtx.Done():
			timer.Stop()
			return "", nil
		case <-timer.C:
		}
	}
}

func reconciledCreateInstanceID(response *ecs.DescribeInstancesResponse, sandboxID string, operation createOperation) (string, error) {
	if response == nil || response.Body == nil || response.Body.Instances == nil {
		return "", errors.New("DescribeInstances returned an incomplete response")
	}
	instances := response.Body.Instances.Instance
	if response.Body.TotalCount != nil && int(tea.Int32Value(response.Body.TotalCount)) != len(instances) {
		return "", fmt.Errorf("create operation %s matched %d instances but DescribeInstances returned %d", operation.id, tea.Int32Value(response.Body.TotalCount), len(instances))
	}
	if len(instances) == 0 {
		return "", nil
	}
	if len(instances) != 1 || instances[0] == nil {
		return "", fmt.Errorf("create operation %s matched %d instances", operation.id, len(instances))
	}

	instance := instances[0]
	instanceID := tea.StringValue(instance.InstanceId)
	if instanceID == "" {
		return "", fmt.Errorf("create operation %s matched an instance without an ID", operation.id)
	}
	expectedTags := []struct {
		key   string
		value string
	}{
		{key: sandboxIDTagKey, value: sandboxID},
		{key: createOperationTagKey, value: operation.id},
		{key: createFingerprintTagKey, value: operation.fingerprint},
	}
	for _, expected := range expectedTags {
		if value := instanceTagValue(instance, expected.key); value != expected.value {
			return "", fmt.Errorf("instance %s has %s tag %q, expected %q", instanceID, expected.key, value, expected.value)
		}
	}
	return instanceID, nil
}
