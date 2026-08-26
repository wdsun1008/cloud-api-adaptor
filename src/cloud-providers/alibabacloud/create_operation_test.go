// (C) Copyright Confidential Containers Contributors
// SPDX-License-Identifier: Apache-2.0

package alibabacloud

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	ecs "github.com/alibabacloud-go/ecs-20140526/v4/client"
	"github.com/alibabacloud-go/tea/tea"

	provider "github.com/confidential-containers/cloud-api-adaptor/src/cloud-providers"
)

type fakeCreateECSClient struct {
	*ecs.Client
	runResponses      []*ecs.RunInstancesResponse
	runErrors         []error
	runRequests       []*ecs.RunInstancesRequest
	describeInstances []*ecs.DescribeInstancesResponseBodyInstancesInstance
	describeRequests  []*ecs.DescribeInstancesRequest
	describeError     error
	describeTotal     *int32
}

func (f *fakeCreateECSClient) RunInstances(request *ecs.RunInstancesRequest) (*ecs.RunInstancesResponse, error) {
	f.runRequests = append(f.runRequests, request)
	index := len(f.runRequests) - 1
	var response *ecs.RunInstancesResponse
	var err error
	if index < len(f.runResponses) {
		response = f.runResponses[index]
	}
	if index < len(f.runErrors) {
		err = f.runErrors[index]
	}
	return response, err
}

func (f *fakeCreateECSClient) DescribeInstances(request *ecs.DescribeInstancesRequest) (*ecs.DescribeInstancesResponse, error) {
	f.describeRequests = append(f.describeRequests, request)
	if f.describeError != nil {
		return nil, f.describeError
	}
	return &ecs.DescribeInstancesResponse{
		Body: &ecs.DescribeInstancesResponseBody{
			TotalCount: f.describeTotal,
			Instances:  &ecs.DescribeInstancesResponseBodyInstances{Instance: f.describeInstances},
		},
	}, nil
}

func describedCreateInstance(instanceID, sandboxID, fingerprint, operationID string) *ecs.DescribeInstancesResponseBodyInstancesInstance {
	values := []struct {
		key   string
		value string
	}{
		{key: sandboxIDTagKey, value: sandboxID},
		{key: createOperationTagKey, value: operationID},
		{key: createFingerprintTagKey, value: fingerprint},
	}
	tags := make([]*ecs.DescribeInstancesResponseBodyInstancesInstanceTagsTag, 0, len(values))
	for _, value := range values {
		if value.value != "" {
			tags = append(tags, &ecs.DescribeInstancesResponseBodyInstancesInstanceTagsTag{
				TagKey: tea.String(value.key), TagValue: tea.String(value.value),
			})
		}
	}
	return &ecs.DescribeInstancesResponseBodyInstancesInstance{
		InstanceId: tea.String(instanceID),
		Tags:       &ecs.DescribeInstancesResponseBodyInstancesInstanceTags{Tag: tags},
	}
}

func newCreateTestProvider(client ecsClient) *alibabaCloudProvider {
	return &alibabaCloudProvider{
		ecsClient: client, serviceConfig: &Config{Region: "cn-hangzhou"},
	}
}

func successfulRunInstances(instanceID string) *ecs.RunInstancesResponse {
	return &ecs.RunInstancesResponse{
		Body: &ecs.RunInstancesResponseBody{
			InstanceIdSets: &ecs.RunInstancesResponseBodyInstanceIdSets{
				InstanceIdSet: []*string{tea.String(instanceID)},
			},
		},
	}
}

func createTestRequest(sandboxID, fingerprint string) *ecs.RunInstancesRequest {
	return &ecs.RunInstancesRequest{Tag: []*ecs.RunInstancesRequestTag{
		{Key: tea.String(sandboxIDTagKey), Value: tea.String(sandboxID)},
		{Key: tea.String(createFingerprintTagKey), Value: tea.String(fingerprint)},
	}}
}

func requestTagValue(tags []*ecs.RunInstancesRequestTag, key string) string {
	for _, tag := range tags {
		if tag != nil && tea.StringValue(tag.Key) == key {
			return tea.StringValue(tag.Value)
		}
	}
	return ""
}

func requestDescribeTagValue(tags []*ecs.DescribeInstancesRequestTag, key string) string {
	for _, tag := range tags {
		if tag != nil && tea.StringValue(tag.Key) == key {
			return tea.StringValue(tag.Value)
		}
	}
	return ""
}

func useFastCreateReconcile(t *testing.T) {
	t.Helper()
	oldTimeout, oldInterval := createReconcileTimeout, createReconcileInterval
	createReconcileTimeout, createReconcileInterval = 8*time.Millisecond, time.Millisecond
	t.Cleanup(func() {
		createReconcileTimeout, createReconcileInterval = oldTimeout, oldInterval
	})
}

func TestCreateOperationStableAcrossFreshProviders(t *testing.T) {
	firstClient := &fakeCreateECSClient{runResponses: []*ecs.RunInstancesResponse{successfulRunInstances("i-first")}}
	firstProvider := newCreateTestProvider(firstClient)
	secondClient := &fakeCreateECSClient{runResponses: []*ecs.RunInstancesResponse{successfulRunInstances("i-created")}}
	secondProvider := newCreateTestProvider(secondClient)

	first, err := createOperationForRequest("sandbox-stable", "fingerprint")
	if err != nil {
		t.Fatal(err)
	}
	second, err := createOperationForRequest("sandbox-stable", "fingerprint")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("fresh providers derived different operations: first=%+v second=%+v", first, second)
	}
	if !strings.HasPrefix(first.clientToken, "caa-") || len(first.id) != 32 {
		t.Fatalf("operation has unexpected Alibaba Cloud identities: %+v", first)
	}

	// The provider restart does not need a speculative pre-query. Alibaba Cloud
	// resolves the deterministic ClientToken when RunInstances is retried.
	if _, err := firstProvider.runInstanceForCreateOperation(context.Background(), "sandbox-stable", createTestRequest("sandbox-stable", "fingerprint"), first); err != nil {
		t.Fatal(err)
	}
	if _, err := secondProvider.runInstanceForCreateOperation(context.Background(), "sandbox-stable", createTestRequest("sandbox-stable", "fingerprint"), second); err != nil {
		t.Fatal(err)
	}
	if len(firstClient.describeRequests) != 0 || len(secondClient.describeRequests) != 0 {
		t.Fatalf("successful calls performed pre-Run recovery queries: first=%d second=%d", len(firstClient.describeRequests), len(secondClient.describeRequests))
	}
	if firstToken, secondToken := tea.StringValue(firstClient.runRequests[0].ClientToken), tea.StringValue(secondClient.runRequests[0].ClientToken); firstToken != first.clientToken || firstToken != secondToken {
		t.Fatalf("RunInstances tokens = %q and %q, want %q", firstToken, secondToken, first.clientToken)
	}
}

func TestCreateOperationUnknownSuccessReconcilesByIdentity(t *testing.T) {
	operation, err := createOperationForRequest("sandbox-unknown", "fingerprint")
	if err != nil {
		t.Fatal(err)
	}
	total := int32(1)
	client := &fakeCreateECSClient{
		runErrors:     []error{context.DeadlineExceeded},
		describeTotal: &total,
		describeInstances: []*ecs.DescribeInstancesResponseBodyInstancesInstance{
			describedCreateInstance("i-reconciled", "sandbox-unknown", "fingerprint", operation.id),
		},
	}
	p := newCreateTestProvider(client)

	instanceID, err := p.runInstanceForCreateOperation(context.Background(), "sandbox-unknown", createTestRequest("sandbox-unknown", "fingerprint"), operation)
	if err != nil {
		t.Fatalf("runInstanceForCreateOperation() error = %v", err)
	}
	if instanceID != "i-reconciled" {
		t.Fatalf("instance ID = %q, want i-reconciled", instanceID)
	}
	if len(client.describeRequests) != 1 ||
		requestDescribeTagValue(client.describeRequests[0].Tag, sandboxIDTagKey) != "sandbox-unknown" ||
		requestDescribeTagValue(client.describeRequests[0].Tag, createOperationTagKey) != operation.id {
		t.Fatalf("reconcile query did not use immutable operation identity: %+v", client.describeRequests)
	}
	if requestTagValue(client.runRequests[0].Tag, createOperationTagKey) != operation.id {
		t.Fatalf("RunInstances operation tag does not match %q", operation.id)
	}
	if requestTagValue(client.runRequests[0].Tag, createFingerprintTagKey) != operation.fingerprint {
		t.Fatalf("RunInstances fingerprint tag does not match %q", operation.fingerprint)
	}
}

func TestCreateOperationEmptyReconcileThenRestartRetriesSameToken(t *testing.T) {
	useFastCreateReconcile(t)
	firstClient := &fakeCreateECSClient{runErrors: []error{context.DeadlineExceeded}}
	firstProvider := newCreateTestProvider(firstClient)
	first, err := createOperationForRequest("sandbox-restart", "fingerprint")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := firstProvider.runInstanceForCreateOperation(context.Background(), "sandbox-restart", createTestRequest("sandbox-restart", "fingerprint"), first); err == nil {
		t.Fatal("expected the empty bounded reconcile to preserve an unknown outcome")
	}

	secondClient := &fakeCreateECSClient{runResponses: []*ecs.RunInstancesResponse{successfulRunInstances("i-retried")}}
	secondProvider := newCreateTestProvider(secondClient)
	second, err := createOperationForRequest("sandbox-restart", "fingerprint")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := secondProvider.runInstanceForCreateOperation(context.Background(), "sandbox-restart", createTestRequest("sandbox-restart", "fingerprint"), second); err != nil {
		t.Fatal(err)
	}
	if first.clientToken != second.clientToken ||
		tea.StringValue(firstClient.runRequests[0].ClientToken) != tea.StringValue(secondClient.runRequests[0].ClientToken) {
		t.Fatalf("provider restart changed ClientToken: first=%q second=%q", first.clientToken, second.clientToken)
	}
}

func TestCreateOperationChangedParametersUsesSameTokenAndFailsClosed(t *testing.T) {
	status := 400
	mismatch := &tea.SDKError{StatusCode: &status, Code: tea.String("IdempotentParameterMismatch")}
	client := &fakeCreateECSClient{
		runResponses: []*ecs.RunInstancesResponse{successfulRunInstances("i-original"), nil},
		runErrors:    []error{nil, mismatch},
	}
	p := newCreateTestProvider(client)
	first, err := createOperationForRequest("sandbox-parameters", "fingerprint-one")
	if err != nil {
		t.Fatal(err)
	}
	second, err := createOperationForRequest("sandbox-parameters", "fingerprint-two")
	if err != nil {
		t.Fatal(err)
	}
	if first.clientToken != second.clientToken || first.id != second.id {
		t.Fatalf("same sandbox changed operation identity: first=%+v second=%+v", first, second)
	}
	if first.fingerprint == second.fingerprint {
		t.Fatal("changed request did not change the reconciliation fingerprint")
	}
	if _, err := p.runInstanceForCreateOperation(context.Background(), "sandbox-parameters", createTestRequest("sandbox-parameters", first.fingerprint), first); err != nil {
		t.Fatal(err)
	}
	_, err = p.runInstanceForCreateOperation(context.Background(), "sandbox-parameters", createTestRequest("sandbox-parameters", second.fingerprint), second)
	if err == nil {
		t.Fatal("IdempotentParameterMismatch was accepted")
	}
	var sdkErr *tea.SDKError
	if !errors.As(err, &sdkErr) || tea.StringValue(sdkErr.Code) != "IdempotentParameterMismatch" {
		t.Fatalf("changed request error = %v", err)
	}
	if len(client.runRequests) != 2 || tea.StringValue(client.runRequests[0].ClientToken) != tea.StringValue(client.runRequests[1].ClientToken) {
		t.Fatal("same sandbox parameter mismatch used different ClientTokens")
	}
}

func TestCreateOperationNewSandboxGetsNewToken(t *testing.T) {
	first, err := createOperationForRequest("sandbox-old", "fingerprint")
	if err != nil {
		t.Fatal(err)
	}
	second, err := createOperationForRequest("sandbox-recreated", "fingerprint")
	if err != nil {
		t.Fatal(err)
	}
	if first.clientToken == second.clientToken || first.id == second.id {
		t.Fatalf("new CRI sandbox reused create identity: first=%+v second=%+v", first, second)
	}
}

func TestCreateOperationReconcileIsBounded(t *testing.T) {
	useFastCreateReconcile(t)
	operation, err := createOperationForRequest("sandbox-bounded", "fingerprint")
	if err != nil {
		t.Fatal(err)
	}
	client := &fakeCreateECSClient{runErrors: []error{context.DeadlineExceeded}}
	p := newCreateTestProvider(client)
	started := time.Now()
	_, err = p.runInstanceForCreateOperation(context.Background(), "sandbox-bounded", createTestRequest("sandbox-bounded", "fingerprint"), operation)
	if err == nil || !strings.Contains(err.Error(), "outcome remains unknown") {
		t.Fatalf("bounded reconcile error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("reconcile exceeded its bound: %v", elapsed)
	}
	if len(client.describeRequests) < 1 {
		t.Fatal("unknown RunInstances outcome was not reconciled")
	}
}

func TestCreateOperationReconcileRejectsIdentityMismatch(t *testing.T) {
	operation, err := createOperationForRequest("sandbox-identity", "fingerprint")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name        string
		sandboxID   string
		fingerprint string
		operationID string
	}{
		{name: "sandbox", sandboxID: "other-sandbox", fingerprint: operation.fingerprint, operationID: operation.id},
		{name: "operation", sandboxID: "sandbox-identity", fingerprint: operation.fingerprint, operationID: strings.Repeat("a", 32)},
		{name: "fingerprint", sandboxID: "sandbox-identity", fingerprint: "other-fingerprint", operationID: operation.id},
		{name: "missing fingerprint", sandboxID: "sandbox-identity", operationID: operation.id},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			total := int32(1)
			client := &fakeCreateECSClient{
				runErrors:     []error{context.DeadlineExceeded},
				describeTotal: &total,
				describeInstances: []*ecs.DescribeInstancesResponseBodyInstancesInstance{
					describedCreateInstance("i-mismatch", test.sandboxID, test.fingerprint, test.operationID),
				},
			}
			p := newCreateTestProvider(client)
			if _, err := p.runInstanceForCreateOperation(context.Background(), "sandbox-identity", createTestRequest("sandbox-identity", operation.fingerprint), operation); err == nil || !strings.Contains(err.Error(), "tag") {
				t.Fatalf("identity mismatch error = %v", err)
			}
		})
	}
}

func TestCreateRequestFingerprintIncludesVolumes(t *testing.T) {
	request := &ecs.RunInstancesRequest{ImageId: tea.String("image-one")}
	first, err := createRequestFingerprint(request, []provider.CloudVolume{{DiskID: "d-one"}})
	if err != nil {
		t.Fatal(err)
	}
	second, err := createRequestFingerprint(request, []provider.CloudVolume{{DiskID: "d-two"}})
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("volume parameter change did not change create fingerprint")
	}
}

func TestCreateOperationRejectsEmptySandboxID(t *testing.T) {
	if _, err := createOperationForRequest("", "fingerprint"); err == nil {
		t.Fatal("empty sandbox ID was accepted")
	}
}
