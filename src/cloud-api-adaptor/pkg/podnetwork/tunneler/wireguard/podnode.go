// (C) Copyright IBM Corp. 2022.
// SPDX-License-Identifier: Apache-2.0

package wireguard

import (
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"time"

	"github.com/confidential-containers/cloud-api-adaptor/src/cloud-api-adaptor/pkg/podnetwork/tunneler"
	"github.com/confidential-containers/cloud-api-adaptor/src/cloud-api-adaptor/pkg/util/netops"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	hostVethName = "veth0"
)

type podNodeTunneler struct {
}

func NewPodNodeTunneler() (tunneler.Tunneler, error) {
	return &podNodeTunneler{}, nil
}

func (t *podNodeTunneler) Setup(nsPath string, podNodeIPs []netip.Addr, config *tunneler.Config) error {

	podVethName := config.InterfaceName
	if podVethName == "" {
		return errors.New("InterfaceName is not specified")
	}

	nodeAddr := config.WorkerNodeIP

	if !nodeAddr.IsValid() {
		return fmt.Errorf("WorkerNodeIP is not specified: %#v", config.WorkerNodeIP)
	}

	podAddr := config.PodIP
	if !podAddr.IsValid() {
		return fmt.Errorf("PodIP is not specified: %#v", config.PodIP)
	}

	hostNS, err := netops.OpenCurrentNamespace()
	if err != nil {
		return fmt.Errorf("failed to get host network namespace: %w", err)
	}
	defer hostNS.Close()

	podNS, err := netops.OpenNamespace(nsPath)
	if err != nil {
		return fmt.Errorf("failed to get a pod network namespace: %s: %w", nsPath, err)
	}
	defer podNS.Close()

	// Create a WireGuard interface using a server private key that is generated at the worker node, and
	// transferred via cloud-init user data
	privateKey, err := wgtypes.ParseKey(config.WireGuard.ServerPrivateKey)
	if err != nil {
		return err
	}
	if _, err := createWireGuardInterface(hostNS, wireguardInterfaceName, config.WireGuard.Port, config.WireGuard.MTU, privateKey); err != nil {
		return err
	}

	// Add the public key of the worker node as a WireGuard peer
	if err := addWireGuardClientPeer(hostNS, wireguardInterfaceName, config.WireGuard.ClientPublicKey); err != nil {
		return err
	}

	// Create a virtual Ethernet (veth) pair between the host and podns network namespaces.
	//
	// One end of this pair will reside in the podns namespace, serving as the network interface (eth0) where the PodIP
	// address is assigned. The other end (veth0) is located in the host network namespace, enabling packet exchange
	// with the WireGuard tunnel (wg0) via policy-based routing.
	//
	//                  ┌──────────────────────────────┐
	//                  │ Peer Pod VM                  │
	//                  │           ┌───────────┐      │
	//                  │           │ podns     │      │
	//                  │           │  ┌─────┐  │      │
	//                  │           │  │eth0 │  │      │
	//                  │           │  └──┬──┘  │      │
	//                  │           └─────┼─────┘      │
	//                  │              ┌──┴──┐         │
	//   ┌────────────┐ │              │veth0│         │
	//   │ Worker Node│ |              └─▲─┬─┘         │
	//   │            │ │                │ │ Routing   │
	//   │  ┌──────┐  │ │   ┌──────┐   ┌─┴─▼─┐         │
	//   │  │ eth0 │  │ │   │ eth0 │   │ wg0 │         │
	//   │  └──┬───┘  │ │   └──┬───┘   └─────┘         │
	//   └─────┼──────┘ └──────┼───────────────────────┘
	//         │               │
	//  ───────┴───────────────┴────────────────────────

	hostVeth, podVeth, err := createVethPair(hostNS, podNS, hostVethName, config.InterfaceName, config.MTU)
	if err != nil {
		return err
	}

	// Set HW address of the pod network interface (eth0)
	if err := podVeth.SetHardwareAddr(config.PodHwAddr); err != nil {
		return fmt.Errorf("failed to set pod HW address %s on %s: %w", config.PodHwAddr, podVethName, err)
	}

	// Set the PodIP to the pod network interface (eth0)
	if err := podVeth.AddAddr(podAddr); err != nil {
		return fmt.Errorf("failed to add pod IP %s to %s on %s: %w", podAddr, podVethName, nsPath, err)
	}

	// Enable routing in the host network namespace
	if err := sysctlSet(hostNS, "net.ipv4.ip_forward", "1"); err != nil {
		return err
	}

	// Enable Proxy ARP on veth0 to reply ARP requests coming from eth0 on podns
	//
	// WireGuard encapsulates L3 packets. This means that ARP packets are not transferred to the worker node.
	// The veth0 interface needs to reply to ARP requests on behalf of the worker node by using proxy ARP.
	// Enabling proxy ARP requires at least one IP address assigned to the interface, so we use the default
	// gateway address on podns for veth0. Note that the source IP address of an ARP reply packet is set to
	// this address.

	var dummyIP netip.Prefix
	for _, route := range config.Routes {
		gw := route.GW
		dst := route.Dst
		if gw.IsValid() && dst.Bits() == 0 {
			// GW is defined, and Dst is "0.0.0.0/0"
			dummyIP = mask32(gw)
			break
		}
	}
	if !dummyIP.IsValid() {
		return errors.New("failed to find a default gateway")
	}

	// ip addr add <dummyIP>/32 dev <peerpod veth>
	if err := hostVeth.AddAddr(dummyIP); err != nil {
		return err
	}

	// The IP address assigned to veth0 is a dummy address, and veth0 should not receive packets to this address
	// locally. Instead, it should forward them to wg0. We can accomplish this behavior by deleting the local route
	// to this address. This configuration must be after the interface is up
	//
	// ip route delete <dummyIP>/32 dev veth0 table local
	if err := hostNS.RouteDel(&netops.Route{
		Destination: dummyIP,
		Device:      hostVethName,
		Type:        unix.RTN_LOCAL,
		Protocol:    unix.RTPROT_KERNEL,
		Table:       unix.RT_TABLE_LOCAL,
	}); err != nil {
		return err
	}

	// Set kernel parameters for enabling proxy ARP
	if err := sysctlSet(hostNS, fmt.Sprintf("net.ipv4.conf.%s.proxy_arp", hostVethName), "1"); err != nil {
		return err
	}
	if err := sysctlSet(hostNS, fmt.Sprintf("net.ipv4.neigh.%s.proxy_delay", hostVethName), "0"); err != nil {
		return err
	}

	// Policy-based routing is used to exchange packets between veth0 and wg0
	//
	// We define two routing tables (1000 and 1001) dedicated for exchanging packets between
	// the two interfaces. These dedicated routing tables will not interfere the routing tables that
	// are originally set in the host network namespace of the peer pod VM.
	//
	// Table 1000 is used for all packets coming from wg0, and table 1001 is used for all packets
	// coming from veth0. These tables are not applied to packets coming from the other interfaces.
	//
	// Routing tables and rules will be set as follows.
	//
	// # ip rule show
	// 0:	from all lookup local          <-- Default rule set by kernel
	// 100:	from all iif wg0 lookup 1000   <-- Rule added by agent-protocol-forwarder
	// 100:	from all iif veth0 lookup 1001 <-- Rule added by agent-protocol-forwarder
	// 32766:	from all lookup main       <-- Default rule set by kernel
	// 32767:	from all lookup default    <-- Default rule set by kernel
	//
	// # ip route show table 1000
	// default dev veth0 scope link <-- All packets from wg0 are forwarded to veth0
	//
	// # ip route show table 1001
	// default dev wg0 scope link <-- All packets from veth0 are forwarded to veth0

	// ip route add table 1000 default dev veth0
	if err := hostNS.RouteAdd(&netops.Route{
		Destination: netops.DefaultPrefix,
		Table:       tableInbound,
		Device:      hostVethName,
	}); err != nil && !os.IsExist(err) {
		return fmt.Errorf("failed to add a route for inbound tunnel traffic: %w", err)
	}

	// ip rule add iif wg0 table 1000 prio 100
	if err := hostNS.RuleAdd(&netops.Rule{
		IifName:  wireguardInterfaceName,
		Table:    tableInbound,
		Priority: rulePriority,
	}); err != nil && !os.IsExist(err) {
		return fmt.Errorf("failed to add a routing policy rule for inbound tunnel traffic: %w", err)
	}

	// ip route add table 1001 default dev wg0
	if err := hostNS.RouteAdd(&netops.Route{
		Destination: netops.DefaultPrefix,
		Table:       tableOutbound,
		Device:      wireguardInterfaceName,
	}); err != nil && !os.IsExist(err) {
		return fmt.Errorf("failed to add a route for outbound tunnel traffic: %w", err)
	}

	// ip rule add iif veth0 table 1001  prio 100
	if err := hostNS.RuleAdd(&netops.Rule{
		IifName:  hostVethName,
		Table:    tableOutbound,
		Priority: rulePriority,
	}); err != nil && !os.IsExist(err) {
		return fmt.Errorf("failed to add a routing policy rule for outbound tunnel traffic: %w", err)
	}

	if len(config.Neighbors) > 0 {
		// Certain CNI plugins, such as EKS CNI, set permanent ARP entries. To accommodate this, we utilize
		// a macvlan interface to forward packets to the hardware address specified by such a ARP entry.
		// However, this configuration leads to asymmetric routing, as illustrated in the diagram below.
		// We need to disable the Reverse Path filter (rp_filter) to allow such asymmetric routing.
		//
		//  ┌───────────────────────────────────┐
		//  │ Peer Pod VM                       │
		//  │           ┌───────────┐           │
		//  │           │ podns     │           │
		//  │           │  ┌─────┐  │           │
		//  │           │  │eth0 │  │           │
		//  │           │  └──┬──┘  │           │
		//  │           └─────┼─────┘           │
		//  │              ┌──┴──┐   ┌────────┐ │
		//  │              │veth0├───┤macvlan0│ │
		//  |              └──▲──┘   └────┬───┘ │
		//  │                 │           │     │
		//  │   ┌──────┐   ┌──┴──┐        │     │
		//  │   │ eth0 │   │ wg0 │◄───────┘     │
		//  │   └──┬───┘   └─────┘              │
		//  └──────┼────────────────────────────┘
		//         │
		//  ───────┴─────────────────────────────

		for i, n := range config.Neighbors {
			name := fmt.Sprintf("macvlan%d", i)
			hwAddr := n.HardwareAddr

			macvlan, err := hostNS.LinkAdd(name, &netops.Macvlan{
				Parent: hostVeth,
			})
			if err != nil {
				return fmt.Errorf("failed to add a macvlan interface for neighbor %s: %w", hwAddr, err)
			}

			// Sleep is necessary here for some reason otherwise hwAddr and rp_filter are not correctly updated
			time.Sleep(1 * time.Second)

			if err := macvlan.SetHardwareAddr(hwAddr); err != nil {
				return fmt.Errorf("failed to set HW address %q to macvlan interface %s: %w", hwAddr, name, err)
			}
			if err := macvlan.SetUp(); err != nil {
				return err
			}

			// ip rule add iif <macvlan> table 1001 prio 100
			if err := hostNS.RuleAdd(&netops.Rule{
				IifName:  name,
				Table:    tableOutbound,
				Priority: rulePriority,
			}); err != nil && !os.IsExist(err) {
				return fmt.Errorf("failed to add a routing policy rule for inbound tunnel traffic: %w", err)
			}

			if err := sysctlSet(hostNS, fmt.Sprintf("net.ipv4.conf.%s.rp_filter", name), "0"); err != nil {
				return err
			}
		}
		if err := sysctlSet(hostNS, "net.ipv4.conf.all.rp_filter", "0"); err != nil {
			return err
		}
	}

	return nil
}

func (t *podNodeTunneler) Teardown(nsPath, hostInterface string, config *tunneler.Config) error {

	hostNS, err := netops.OpenCurrentNamespace()
	if err != nil {
		logger.Printf("error during teardown: %v", err)
	} else {
		link, err := hostNS.LinkFind(wireguardInterfaceName)
		if err == nil {
			if err := link.Delete(); err != nil {
				logger.Printf("error during teardown: %v", err)
			}
		} else if !errors.Is(err, fs.ErrNotExist) {
			logger.Printf("error during teardown: %v", err)
		}

		hostNS.Close()
	}

	podNS, err := netops.OpenNamespace(nsPath)
	if err != nil {
		logger.Printf("error during teardown: %v", err)
	} else {
		removeVethPair(podNS, config.InterfaceName)
		podNS.Close()
	}

	return nil
}
