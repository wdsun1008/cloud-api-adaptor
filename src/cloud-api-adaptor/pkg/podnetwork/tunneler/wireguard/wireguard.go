// (C) Copyright Confidential Containers Contributors
// SPDX-License-Identifier: Apache-2.0

package wireguard

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/confidential-containers/cloud-api-adaptor/src/cloud-api-adaptor/pkg/util/netops"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	tableInbound  = 1000
	tableOutbound = 1001
	rulePriority  = 100
)

// createWireGuardInterface creates a WireGuard interface with a private key
func createWireGuardInterface(ns netops.Namespace, interfaceName string, port, mtu int, privateKey wgtypes.Key) (netops.Link, error) {

	// Create a new WireGuard interface
	wgLink, err := ns.LinkAdd(interfaceName, &netops.WireGuard{})
	if err != nil {
		return nil, err
	}

	if mtu > 0 {
		if err := wgLink.SetMTU(mtu); err != nil {
			return nil, err
		}
	}

	// Bring the interface up
	if err := wgLink.SetUp(); err != nil {
		return nil, err
	}

	// Configures the listen port and private key of the WireGuard interface
	wgConfig := &wgtypes.Config{
		ListenPort:   &port,
		PrivateKey:   &privateKey,
		ReplacePeers: true,
	}

	if err := configureWireGuardDevice(ns, interfaceName, wgConfig); err != nil {
		return nil, err
	}

	return wgLink, nil
}

// addWireGuardServerPeer adds a WireGuard peer with the public key of a peer pod VM to the WireGuard interface on the worker node
func addWireGuardServerPeer(ns netops.Namespace, interfaceName string, peerIP netip.Addr, port int, podIP netip.Addr, serverKey string) error {

	// wg set wg0 peer <public key> allowed-ips <pod IP>/32 persistent-keepalive 25 endpoint <peer pod VM IP>:<port>

	serverPrivateKey, err := wgtypes.ParseKey(serverKey)
	if err != nil {
		return err
	}

	var interval = persistentKeepaliveInterval

	wgConfig := &wgtypes.Config{
		ReplacePeers: false,
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey: serverPrivateKey.PublicKey(),
				Endpoint: &net.UDPAddr{
					IP:   toIP(peerIP),
					Port: port,
				},
				PersistentKeepaliveInterval: &interval,
				ReplaceAllowedIPs:           true,
				AllowedIPs:                  []net.IPNet{toIPNet32(podIP)},
			},
		},
	}

	return configureWireGuardDevice(ns, interfaceName, wgConfig)
}

// addWireGuardClientPeer adds a WireGuard peer with the public key of the worker node to the WireGuard interface on the peer pod VM
func addWireGuardClientPeer(ns netops.Namespace, interfaceName string, clientKey string) error {

	// wg set wg0 peer <public key> allowed-ips 0.0.0.0/0

	clientPublicKey, err := wgtypes.ParseKey(clientKey)
	if err != nil {
		return err
	}

	allowAll := toIPNet(netops.DefaultPrefix)

	wgConfig := &wgtypes.Config{
		ReplacePeers: true,
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey:         clientPublicKey,
				ReplaceAllowedIPs: true,
				AllowedIPs:        []net.IPNet{allowAll},
			},
		},
	}

	return configureWireGuardDevice(ns, interfaceName, wgConfig)
}

// removeWireGuardPeer removes a WireGuard peer on a peer pod VM from the WireGuard interface on the worker node
func removeWireGuardPeer(ns netops.Namespace, interfaceName string, podIP netip.Addr) {

	err := ns.Run(func() error {

		wgClient, err := wgctrl.New()
		if err != nil {
			return err
		}
		defer wgClient.Close()

		dev, err := wgClient.Device(interfaceName)
		if err != nil {
			return err
		}

		// Search all peers, and find one with the given PodIP
		for _, peer := range dev.Peers {
			for _, ipNet := range peer.AllowedIPs {
				if toAddr(ipNet.IP) != podIP {
					continue
				}

				wgConfig := &wgtypes.Config{
					Peers: []wgtypes.PeerConfig{
						{
							PublicKey: peer.PublicKey,
							Remove:    true,
						},
					},
				}
				if err := configureWireGuardDevice(ns, interfaceName, wgConfig); err != nil {
					return err
				}
				return nil
			}
		}
		return fmt.Errorf("WireGuard peer for podIP %s not found", podIP)
	})
	if err != nil {
		logger.Printf("failed to remove WireGuard peer for podIP %s: %v", podIP, err)
		return
	}
}

func configureWireGuardDevice(ns netops.Namespace, interfaceName string, wgConfig *wgtypes.Config) error {

	return ns.Run(func() error {

		wgClient, err := wgctrl.New()
		if err != nil {
			return err
		}
		defer wgClient.Close()

		return wgClient.ConfigureDevice(interfaceName, *wgConfig)
	})
}
