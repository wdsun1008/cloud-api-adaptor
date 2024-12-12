// (C) Copyright Confidential Containers Contributors
// SPDX-License-Identifier: Apache-2.0

package wireguard

import (
	"errors"
	"fmt"
	"io/fs"
	"log"
	"math"
	"math/rand/v2"
	"net/netip"
	"path/filepath"
	"sync"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/confidential-containers/cloud-api-adaptor/src/cloud-api-adaptor/pkg/podnetwork/tunneler"
	"github.com/confidential-containers/cloud-api-adaptor/src/cloud-api-adaptor/pkg/util/netops"
)

//
// ┌────────────────────────────────────┐
// │ Worker Node VM                     │
// │    ┌────────────────────────┐      │
// │    │ pod NS                 │      │
// │    │ ┌─────┐Routing┌─────┐  │      │
// │    │ │eth0 │◄──────│veth0│  │      │
// │    │ │(CNI)│──────►│     │  │      │
// │    │ └─────┘       └──┬──┘  │      │
// │    └──────────────────┼─────┘      │
// │          ┌────────────┼──────────┐ │
// │          │ peerpod NS │          │ │
// │          │        ┌───┴───┐      │ │
// │          │        │ppvethX│      │ │
// |          |        └──▲─┬──┘      | │
// │          │           │ │ Routing │ │   ┌────────────┐
// │          │         ┌─┴─▼─┐       │ │   │ Peer Pod VM│
// │ ┌──────┐ │         │ wg0 │       │ │   │  ┌──────┐  │
// │ │ eth0 │ │         └─────┘       │ │   │  │ eth0 │  │
// │ └──┬───┘ └───────────────────────┘ │   │  └──┬───┘  │
// └────┼───────────────────────────────┘   └─────┼──────┘
//      │                                         │
// ─────┴─────────────────────────────────────────┴───────

var logger = log.New(log.Writer(), "[tunneler/wireguard] ", log.LstdFlags|log.Lmsgprefix)

const (
	peerpodVethPrefix = "ppveth"
	podVethName       = "veth0"
	tableWireGuard    = 1000
	tablePeerPodMin   = 1001
	tablePeerPodMax   = 2000
)

type workerNodeTunneler struct {
	namespaceName    string
	interfaceName    string
	port             int
	mtu              int
	clientPrivateKey wgtypes.Key
	mutex            sync.Mutex
}

// NewWorkerNodeTunneler returns a new WorkerNodeTunneler for WireGuard tunneler
func NewWorkerNodeTunneler() (tunneler.Tunneler, error) {

	return &workerNodeTunneler{}, nil
}

// Initialize is called to initialize the WireGuard tunneler when Cloud API Adaptor starts
func (t *workerNodeTunneler) Initialize(n *tunneler.NetworkConfig) error {

	t.mutex.Lock()
	defer t.mutex.Unlock()

	// Generate a WireGuard private key for the worker node
	clientPrivateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return err
	}

	// Initialize variables
	t.interfaceName = wireguardInterfaceName
	t.port = n.WireGuard.Port
	t.namespaceName = n.Namespace
	t.clientPrivateKey = clientPrivateKey

	// Open the host network namespace
	hostNS, err := netops.OpenCurrentNamespace()
	if err != nil {
		return fmt.Errorf("failed to get current network namespace: %w", err)
	}
	defer hostNS.Close()

	// Ensure that the "peerpods" network namespace exists on the worker node
	ppNS, err := ensurePeerPodNamespace(t.namespaceName)
	if err != nil {
		return err
	}
	defer ppNS.Close()

	// Clear old routing tables if any
	if err := clearRoutingRules(ppNS); err != nil {
		return fmt.Errorf("failed to clear old routing tables on %s: %w", ppNS.Path(), err)
	}

	link, err := ppNS.LinkFind(t.interfaceName)
	if err == nil {
		// Old WireGuard interface is found. Delete it.
		if err := link.Delete(); err != nil {
			return err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	// Generate a temporary interface name to avoid conflicts with the existing interface names on the host network namespace
	temporaryName, err := generateInterfaceName(hostNS, t.interfaceName)
	if err != nil {
		return err
	}

	// Set up a new WireGuard interface
	wgLink, err := createWireGuardInterface(hostNS, temporaryName, t.port, n.WireGuard.MTU, t.clientPrivateKey)
	if err != nil {
		return fmt.Errorf("failed to create a new WireGuard interface on %s: %w", ppNS.Path(), err)
	}

	// Get MTU
	mtu, err := wgLink.GetMTU()
	if err != nil {
		return fmt.Errorf("failed to get MTU of interface %s on %s: %w", t.interfaceName, ppNS.Path(), err)
	}
	t.mtu = mtu

	// Change the network namespace of the interface from the host to the peer pods network namespace
	if err := wgLink.SetNamespace(ppNS); err != nil {
		return err
	}

	// Change the interface name from the temporary one to the fixed name
	if err := wgLink.SetName(t.interfaceName); err != nil {
		return err
	}

	if err := wgLink.SetUp(); err != nil {
		return err
	}

	// Ensure routing table rules for pod traffic to peer pod VMs
	if err := ensureCommonRoutingRules(ppNS, t.interfaceName); err != nil {
		return fmt.Errorf("failed to add routing table rules for outbound tunnel traffic: %w", err)
	}

	return nil
}

// Configure is called to prepare a tunneler configuration for a newly requested peer pod VM
func (t *workerNodeTunneler) Configure(config *tunneler.Config) (err error) {

	t.mutex.Lock()
	defer t.mutex.Unlock()

	serverPrivateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return err
	}

	clientPublicKey := t.clientPrivateKey.PublicKey()

	config.WireGuard = &tunneler.WireGuard{
		Port:             t.port,
		MTU:              t.mtu,
		ServerPrivateKey: serverPrivateKey.String(),
		ClientPublicKey:  clientPublicKey.String(),
	}

	// Adjust MTU
	if t.mtu < config.MTU {
		config.MTU = t.mtu
	}

	return nil
}

// Setup is called to set up networking for a newly requested peer pod VM
func (t *workerNodeTunneler) Setup(nsPath string, podNodeIPs []netip.Addr, config *tunneler.Config) error {

	t.mutex.Lock()
	defer t.mutex.Unlock()

	if len(podNodeIPs) == 0 {
		return fmt.Errorf("pod node has no IPs")
	}

	// First IP address is used
	peerIP := podNodeIPs[0]
	podIP := config.PodIP.Addr()

	// Open the host network namespace
	hostNS, err := netops.OpenCurrentNamespace()
	if err != nil {
		return fmt.Errorf("failed to get current network namespace: %w", err)
	}
	defer hostNS.Close()

	// Open the pod network namespace
	podNS, err := netops.OpenNamespace(nsPath)
	if err != nil {
		return fmt.Errorf("failed to get the network namespace: %s: %w", nsPath, err)
	}
	defer podNS.Close()

	defaultGW, err := findDefaultGateway(podNS)
	if err != nil {
		return err
	}

	// Open the "peerpods" network namespace
	ppNS, err := ensurePeerPodNamespace(t.namespaceName)
	if err != nil {
		return err
	}
	defer ppNS.Close()

	ppVethName, err := generateInterfaceName(ppNS, peerpodVethPrefix)
	if err != nil {
		return err
	}

	ppvVeth, podVeth, err := createVethPair(ppNS, podNS, ppVethName, podVethName, config.MTU)
	if err != nil {
		return fmt.Errorf("failed to create a veth pair between %s and %s: %w", ppNS.Path(), podNS.Path(), err)
	}

	if err := addWireGuardRoutingRule(podNS, config.InterfaceName, ppvVeth, podIP); err != nil {
		return fmt.Errorf("failed to add inbound routing rules for a new peer pod %q on %q: %w", peerIP, podNS.Path(), err)
	}

	if err := addPeerPodRoutingRule(ppNS, t.interfaceName, ppvVeth, podVeth, podIP, defaultGW); err != nil {
		return fmt.Errorf("failed to add outbound routing rules for a new peer pod %q to %q on %q: %w", peerIP, t.interfaceName, ppNS.Path(), err)
	}

	if err := addWireGuardServerPeer(ppNS, t.interfaceName, peerIP, t.port, podIP, config.WireGuard.ServerPrivateKey); err != nil {
		return fmt.Errorf("failed to add a WireGuard peer %q to %q on %q: %w", peerIP, t.interfaceName, ppNS.Path(), err)
	}

	return nil
}

// Teardown is called when a peer pod VM is requested to be deleted
func (t *workerNodeTunneler) Teardown(nsPath, hostInterface string, config *tunneler.Config) error {

	t.mutex.Lock()
	defer t.mutex.Unlock()

	// Try to remove as many resources as possible

	ppNSPath := filepath.Join("/run/netns", t.namespaceName)
	ppNS, err := netops.OpenNamespace(ppNSPath)
	if err != nil {
		logger.Print(err)
	} else {
		removeWireGuardPeer(ppNS, t.interfaceName, config.PodIP.Addr())
		removeRoutingRule(ppNS, config.PodIP.Addr())
		ppNS.Close()
	}

	podNS, err := netops.OpenNamespace(nsPath)
	if err != nil {
		logger.Print(err)
	} else {
		removeVethPair(podNS, podVethName)
		podNS.Close()
	}

	return nil
}

func generateInterfaceName(ns netops.Namespace, prefix string) (string, error) {

	r := rand.Int32N(1000000)

	ifName := fmt.Sprintf("%s%06d", prefix, r)
	list, err := ns.LinkList()
	if err != nil {
		return "", err
	}

	for range 1 + len(list) {
		var found bool
		for _, l := range list {
			if l.Name() == ifName {
				found = true
				break
			}
		}
		if !found {
			return ifName, nil
		}
	}

	return "", fmt.Errorf("failed to generate a new interface name on namespace %s", ns.Path())
}

func ensurePeerPodNamespace(peerpodNamespaceName string) (netops.Namespace, error) {

	_, err := netops.CreateNamedNamespace(peerpodNamespaceName)
	if err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, fmt.Errorf("failed to create network namespace %q: %w", peerpodNamespaceName, err)
	}
	ppNSPath := filepath.Join("/run/netns", peerpodNamespaceName)
	ppNS, err := netops.OpenNamespace(ppNSPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open network namespace: %s: %w", peerpodNamespaceName, err)
	}
	if err := sysctlSet(ppNS, "net.ipv4.ip_forward", "1"); err != nil {
		return nil, err
	}

	return ppNS, nil
}

// ensureCommonRoutingRules ensure routing table rules for pod traffic to peer pod VMs
func ensureCommonRoutingRules(ppNS netops.Namespace, interfaceName string) error {

	// ip route add table <table ID> default dev <tunnel interface>
	if err := ppNS.RouteAdd(&netops.Route{
		Table:       tableInbound,
		Destination: netops.DefaultPrefix,
		Device:      interfaceName,
	}); err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("failed to add a route for inbound tunnel traffic: %w", err)
	}

	// ip rule add not iif <tunnel interface> table  <table ID>  prio 100
	if err := ppNS.RuleAdd(&netops.Rule{
		Invert:   true,
		IifName:  interfaceName,
		Table:    tableInbound,
		Priority: rulePriority,
	}); err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("failed to add a routing policy rule for inbound tunnel traffic: %w", err)
	}

	return nil
}

// clearRoutingRules clears stale routing tables that are configured by the previous invocation of Cloud API Adaptor
func clearRoutingRules(ns netops.Namespace) error {

	allRoutes, err := ns.RouteList(&netops.Route{TableUnspec: true})
	if err != nil {
		return err
	}

	for _, route := range allRoutes {
		id := route.Table
		if !(id == tableInbound || (tablePeerPodMin <= id && id <= tablePeerPodMax)) {
			continue
		}

		if err := ns.RouteDel(route); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}

		if err := ns.RuleDel(&netops.Rule{Table: id}); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}

	allRules, err := ns.RuleList(&netops.Rule{})
	if err != nil {
		return err
	}

	for _, rule := range allRules {
		id := rule.Table

		if !(id == tableInbound || (tablePeerPodMin <= id && id <= tablePeerPodMax)) {
			continue
		}

		if err := ns.RuleDel(rule); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}

	return nil
}

// findAvailableTableID finds an routing table ID that is not already used
func findAvailableTableID(ppNS netops.Namespace) (int, error) {

	allRoutes, err := ppNS.RouteList(&netops.Route{TableUnspec: true})
	if err != nil {
		return 0, err
	}

	// Find a smallest unused table ID in the range
outer:
	for id := tablePeerPodMin; id <= tablePeerPodMax; id++ {
		for _, route := range allRoutes {
			if route.Table == id {
				continue outer
			}
		}
		// This table ID is not used in any of the routes
		return id, nil
	}

	return 0, fmt.Errorf("failed to find available routing table ID")
}

// addWireGuardRoutingRule updates routing table rules for a new peer pod
func addWireGuardRoutingRule(podNS netops.Namespace, podInterfaceName string, ppVeth netops.Link, podIP netip.Addr) error {

	ppVethMAC, err := ppVeth.GetHardwareAddr()
	if err != nil {
		return err
	}

	nNeigh := netops.Neighbor{
		IP:           podIP,
		Dev:          podVethName,
		HardwareAddr: ppVethMAC,
		State:        netops.NeighborStatePermanent,
	}

	if err := podNS.NeighborAdd(&nNeigh); err != nil {
		return fmt.Errorf("failed to add an ARP entry: %s dev %s lladdr %s on network namespace %s: %w", podIP, podVethName, ppVethMAC, podNS.Path(), err)
	}

	if err := podNS.RuleDel(&netops.Rule{
		Table:    0,
		Priority: 0,
	}); err != nil {
		return err
	}

	// ip route add <podIP>/32 dev <pod veth>
	if err := podNS.RouteAdd(&netops.Route{
		Destination: mask32(podIP),
		Device:      podVethName,
	}); err != nil {
		return err
	}

	if err := sysctlSet(podNS, "net.ipv4.ip_forward", "1"); err != nil {
		return err
	}

	// Enable proxy ARP
	if err := sysctlSet(podNS, fmt.Sprintf("net.ipv4.conf.%s.proxy_arp", podInterfaceName), "1"); err != nil {
		return err
	}
	if err := sysctlSet(podNS, fmt.Sprintf("net.ipv4.neigh.%s.proxy_delay", podInterfaceName), "0"); err != nil {
		return err
	}

	return nil
}

// addPeerPodRoutingRule updates routing table rules for a new peer pod
func addPeerPodRoutingRule(ppNS netops.Namespace, tunnelInterfaceName string, ppVeth, podVeth netops.Link, podIP, defaultGW netip.Addr) error {

	ppVethName := ppVeth.Name()

	podVethMAC, err := podVeth.GetHardwareAddr()
	if err != nil {
		return err
	}

	nNeigh := netops.Neighbor{
		IP:           defaultGW,
		Dev:          ppVethName,
		HardwareAddr: podVethMAC,
		State:        netops.NeighborStatePermanent,
	}

	if err := ppNS.NeighborAdd(&nNeigh); err != nil {
		return fmt.Errorf("failed to add an ARP entry: %s dev %s lladdr %s on network namespace %s: %w", defaultGW, ppVethName, podVethMAC, ppNS.Path(), err)
	}

	// Search an routing table ID that is not already used
	tableID, err := findAvailableTableID(ppNS)
	if err != nil {
		return err
	}

	if err := ppNS.RouteAdd(&netops.Route{
		Destination: mask32(defaultGW),
		Table:       tableID,
		Device:      ppVethName,
	}); err != nil {
		return err
	}

	// ip route add table <table ID> default dev <peer pod veth>
	if err := ppNS.RouteAdd(&netops.Route{
		Destination: netops.DefaultPrefix,
		Gateway:     defaultGW,
		Table:       tableID,
		Device:      ppVethName,
	}); err != nil {
		return err
	}

	// ip rule add iif <tunnel interface> from <pod IP>/32 table <table ID> prio 100
	if err := ppNS.RuleAdd(&netops.Rule{
		Table:    tableID,
		IifName:  tunnelInterfaceName,
		Src:      mask32(podIP),
		Priority: rulePriority,
	}); err != nil {
		return err
	}

	return nil
}

func removeRoutingRule(ppNS netops.Namespace, podIP netip.Addr) {

	rules, err := ppNS.RuleList(&netops.Rule{
		Src: mask32(podIP),
	})
	if err != nil {
		logger.Printf("removeRoutingRule: %v", err)
	}

	// The number of rules here should be one, but we remove all of found rules here.
	for _, rule := range rules {

		tableID := rule.Table

		if err := ppNS.RuleDel(rule); err != nil {
			logger.Printf("removeRoutingRule: %v", err)
		}

		if err := ppNS.RouteDel(&netops.Route{
			Destination: netops.DefaultPrefix,
			Table:       tableID,
		}); err != nil {
			logger.Printf("removeRoutingRule: %v", err)
		}
	}
}

func findDefaultGateway(ns netops.Namespace) (gw netip.Addr, err error) {

	routes, err := ns.RouteList(&netops.Route{Destination: netops.DefaultPrefix})
	if err != nil {
		return gw, fmt.Errorf("failed to get routes on namespace %q: %w", ns.Path(), err)
	}

	var priority = math.MaxInt

	for _, r := range routes {
		if r.Destination.Bits() == 0 && r.Priority < priority {
			gw = r.Gateway
			priority = r.Priority
		}
	}

	if !gw.IsValid() {
		return gw, fmt.Errorf("failed to identify the default gateway on network namespace %q", ns.Path())
	}

	return gw, nil
}
