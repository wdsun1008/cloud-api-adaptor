// (C) Copyright IBM Corp. 2022.
// SPDX-License-Identifier: Apache-2.0

package wireguard

import (
	"testing"

	"github.com/confidential-containers/cloud-api-adaptor/src/cloud-api-adaptor/pkg/podnetwork/tunneler"
	"github.com/confidential-containers/cloud-api-adaptor/src/cloud-api-adaptor/pkg/podnetwork/tuntest"
)

func TestWireGuard(t *testing.T) {

	networkConfig := &tunneler.NetworkConfig{
		TunnelType: "wireguard",
		WireGuard: tunneler.WireGuardConfig{
			Port: 51820,
		},
	}

	tuntest.RunTunnelTest(t, "wireguard", NewWorkerNodeTunneler, NewPodNodeTunneler, networkConfig)
}
