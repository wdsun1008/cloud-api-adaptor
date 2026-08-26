// (C) Copyright Confidential Containers Contributors
// SPDX-License-Identifier: Apache-2.0

package alibabacloud

import (
	"flag"
	"testing"
)

func TestManagerVPCIDFromEnvironment(t *testing.T) {
	alibabacloudcfg = Config{}
	t.Cleanup(func() { alibabacloudcfg = Config{} })
	t.Setenv("VPC_ID", "vpc-from-environment")

	flags := flag.NewFlagSet("test", flag.ContinueOnError)
	(&Manager{}).ParseCmd(flags)
	if alibabacloudcfg.VpcID != "vpc-from-environment" {
		t.Fatalf("VpcID = %q, want VPC_ID environment value", alibabacloudcfg.VpcID)
	}

	if err := flags.Set("vpc-id", "vpc-from-flag"); err != nil {
		t.Fatal(err)
	}
	if alibabacloudcfg.VpcID != "vpc-from-flag" {
		t.Fatalf("VpcID = %q, want flag override", alibabacloudcfg.VpcID)
	}
}
