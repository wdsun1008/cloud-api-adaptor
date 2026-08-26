// (C) Copyright Confidential Containers Contributors
// SPDX-License-Identifier: Apache-2.0

package alibabacloud

import (
	"errors"
	"testing"

	"github.com/alibabacloud-go/tea/tea"
	vpc "github.com/alibabacloud-go/vpc-20160428/v6/client"
)

type fakeVPCClient struct {
	*vpc.Client
	describeCalls int
	describeError error
	vpcID         string
}

func (f *fakeVPCClient) DescribeVSwitchAttributes(*vpc.DescribeVSwitchAttributesRequest) (*vpc.DescribeVSwitchAttributesResponse, error) {
	f.describeCalls++
	if f.describeError != nil {
		return nil, f.describeError
	}
	return &vpc.DescribeVSwitchAttributesResponse{
		Body: &vpc.DescribeVSwitchAttributesResponseBody{VpcId: tea.String(f.vpcID)},
	}, nil
}

func TestEnsureVpcIDUsesExplicitConfiguration(t *testing.T) {
	client := &fakeVPCClient{describeError: errors.New("DescribeVSwitchAttributes must not run")}
	p := &alibabaCloudProvider{
		vpcClient: client, serviceConfig: &Config{VpcID: "vpc-explicit", VswitchID: "vsw-test", Region: "cn-hangzhou"},
	}
	if err := p.ensureVpcID(); err != nil {
		t.Fatal(err)
	}
	if client.describeCalls != 0 || p.serviceConfig.VpcID != "vpc-explicit" {
		t.Fatalf("explicit VPC triggered discovery: calls=%d config=%+v", client.describeCalls, p.serviceConfig)
	}
}

func TestEnsureVpcIDDiscoversMissingConfiguration(t *testing.T) {
	client := &fakeVPCClient{vpcID: "vpc-discovered"}
	p := &alibabaCloudProvider{
		vpcClient: client, serviceConfig: &Config{VswitchID: "vsw-test", Region: "cn-hangzhou"},
	}
	if err := p.ensureVpcID(); err != nil {
		t.Fatal(err)
	}
	if client.describeCalls != 1 || p.serviceConfig.VpcID != "vpc-discovered" {
		t.Fatalf("VPC discovery result: calls=%d config=%+v", client.describeCalls, p.serviceConfig)
	}
}

func TestEnsureVpcIDPropagatesDiscoveryFailure(t *testing.T) {
	client := &fakeVPCClient{describeError: errors.New("VPC endpoint unavailable")}
	p := &alibabaCloudProvider{
		vpcClient: client, serviceConfig: &Config{VswitchID: "vsw-test", Region: "cn-hangzhou"},
	}
	if err := p.ensureVpcID(); err == nil {
		t.Fatal("VPC discovery failure was ignored")
	}
	if client.describeCalls != 1 {
		t.Fatalf("DescribeVSwitchAttributes calls = %d, want 1", client.describeCalls)
	}
}
