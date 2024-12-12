// (C) Copyright Confidential Containers Contributors
// SPDX-License-Identifier: Apache-2.0

package tunneler

import "strings"

const DefaultNetworkNamespaceName = "peerpods"

type TunnelerConfigurator interface {
	Tunneler
	Initialize(*NetworkConfig) error
	Configure(*Config) error
}

type NetworkConfig struct {
	TunnelType          string
	HostInterface       string
	Namespace           string
	VXLAN               VXLANConfig
	WireGuard           WireGuardConfig
	ExternalNetViaPodVM bool
	PodSubnetCIDRs      SubnetCIDRs
}

type VXLANConfig struct {
	Port  int
	MinID int
}

type WireGuardConfig struct {
	Port int
	MTU  int
}

type SubnetCIDRs []string

func (i *SubnetCIDRs) String() string {
	return strings.Join(*i, ", ")
}

func (i *SubnetCIDRs) Set(value string) error {
	parts := strings.Split(value, ",")

	for _, part := range parts {
		*i = append(*i, strings.TrimSpace(part))
	}
	return nil
}
