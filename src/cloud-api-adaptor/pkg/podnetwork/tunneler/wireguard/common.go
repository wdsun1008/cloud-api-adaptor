// (C) Copyright Confidential Containers Contributors
// SPDX-License-Identifier: Apache-2.0

package wireguard

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/confidential-containers/cloud-api-adaptor/src/cloud-api-adaptor/pkg/util/netops"
	"github.com/containerd/containerd/mount"
)

const (
	DefaultWireGuardPort        = 51820
	wireguardInterfaceName      = "wg0"
	persistentKeepaliveInterval = 25 * time.Second
)

func mask32(ip netip.Addr) netip.Prefix {
	return netip.PrefixFrom(ip, ip.BitLen())
}

func toAddr(ip net.IP) netip.Addr {
	addr, _ := netip.AddrFromSlice(ip)
	return addr
}

func toIP(ip netip.Addr) net.IP {
	return ip.AsSlice()
}

func toIPNet(prefix netip.Prefix) net.IPNet {
	addr := prefix.Addr()
	return net.IPNet{
		IP:   toIP(addr),
		Mask: net.CIDRMask(prefix.Bits(), addr.BitLen()),
	}
}

func toIPNet32(ip netip.Addr) net.IPNet {
	bits := ip.BitLen()
	return net.IPNet{
		IP:   toIP(ip),
		Mask: net.CIDRMask(bits, bits),
	}
}

// sysctlSet sets a kernel parameter under /proc/sys on ns
func sysctlSet(ns netops.Namespace, key string, value string) error {

	err := ns.Run(func() error {

		keyPath := strings.Replace(key, ".", "/", -1)

		bytes, err := os.ReadFile(filepath.Join("/proc/sys", keyPath))
		if err != nil {
			return err
		}
		currentValue := string(bytes[0 : len(bytes)-1]) // Trim the trailing newline
		if currentValue == value {
			// No need to update
			return nil
		}

		// In a Kubernetes pod, the proc filesystem is mounted as a read-only filesystem.
		// We temporarily mount the proc filesystem, and change a kernel parameter under /proc/sys.

		f := func(root string) error {
			return os.WriteFile(filepath.Join(root, "sys", keyPath), []byte(value), 0o666)
		}

		m := []mount.Mount{
			{
				Type:    "proc",
				Source:  "proc",
				Options: []string{"rw"},
			},
		}

		return mount.WithTempMount(context.Background(), m, f)
	})
	if err != nil {
		return fmt.Errorf("failed to set sysctl parameter %q to %q: %w", key, value, err)
	}
	return nil
}

func createVethPair(ns1, ns2 netops.Namespace, name1, name2 string, mtu int) (veth1, veth2 netops.Link, err error) {

	veth1, err = ns1.LinkAdd(name1, &netops.VEth{
		PeerNamespace: ns2,
		PeerName:      name2,
	})
	if err != nil {
		return nil, nil, err
	}

	// ip link set <veth1> mtu <MTU>
	if err := veth1.SetMTU(mtu); err != nil {
		return nil, nil, err
	}

	// ip link set <veth1> up
	if err := veth1.SetUp(); err != nil {
		return nil, nil, err
	}

	veth2, err = ns2.LinkFind(name2)
	if err != nil {
		return nil, nil, err
	}

	// ip link set <veth2> mtu <MTU>
	if err := veth2.SetMTU(mtu); err != nil {
		return nil, nil, err
	}

	// ip link set <pveth2> up
	if err := veth2.SetUp(); err != nil {
		return nil, nil, err
	}

	return veth1, veth2, nil
}

func removeVethPair(ns netops.Namespace, name string) {

	link, err := ns.LinkFind(name)
	if err != nil {
		logger.Print(err)
	}

	if err := link.Delete(); err != nil {
		logger.Print(err)
	}
}
