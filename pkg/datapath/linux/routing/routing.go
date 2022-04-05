// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package linuxrouting

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	iputil "github.com/cilium/cilium/pkg/ip"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "linux-routing")
)

func check(e error) {
	if e != nil {
		fmt.Errorf("error: %s", e)
	}
}

// Configure sets up the rules and routes needed when running in ENI or
// Azure IPAM mode.
// These rules and routes direct egress traffic out of the interface and
// ingress traffic back to the endpoint (`ip`). The compat flag controls which
// egress priority to consider when deleting the egress rules (see
// option.Config.EgressMultiHomeIPRuleCompat).
//
// ip: The endpoint IP address to direct traffic out / from interface.
// info: The interface routing info used to create rules and routes.
// mtu: The interface MTU.
func (info *RoutingInfo) Configure(ip net.IP, mtu int, compat bool) error {
	prgname := filepath.Base(os.Args[0])
	var filename string
	if prgname == "cilium-agent" {
		filename = "/host/opt/cni/bin/" + prgname + ".log"
	} else {
		filename = "/opt/cni/bin/" + prgname + ".log"
	}
	f, err := os.OpenFile(filename,
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	check(err)
	defer f.Close()
	w := bufio.NewWriter(f)

	_, err = fmt.Fprintf(w, "%s MW routing.Configure, routingInfo: %s\n", time.Now(), info)

	if ip.To4() == nil {
		log.WithFields(logrus.Fields{
			"endpointIP": ip,
		}).Warning("Unable to configure rules and routes because IP is not an IPv4 address")
		return errors.New("IP not compatible")
	}

	ifindex, err := retrieveIfIndexFromMAC(info.MasterIfMAC, mtu)
	if err != nil {
		return fmt.Errorf("unable to find ifindex for interface MAC: %s", err)
	}

	ipWithMask := net.IPNet{
		IP:   ip,
		Mask: net.CIDRMask(32, 32),
	}
	_, err = fmt.Fprintf(w, "%s MW Configure ipWithMask, ip: %s,mask: %s\n", time.Now(), ipWithMask.IP, ipWithMask.Mask)

	// On ingress, route all traffic to the endpoint IP via the main routing
	// table. Egress rules are created in a per-ENI routing table.
	_, err = fmt.Fprintf(w, "%s MW Configure Ingress Routes, Priority: %s,To: %s, Table: %s\n", time.Now(), linux_defaults.RulePriorityIngress, ipWithMask.IP, route.MainTable)
	if err := route.ReplaceRule(route.Rule{
		Priority: linux_defaults.RulePriorityIngress,
		To:       &ipWithMask,
		Table:    route.MainTable,
	}); err != nil {
		return fmt.Errorf("unable to install ip rule: %s", err)
	}

	var egressPriority, tableID int

	if compat {
		egressPriority = linux_defaults.RulePriorityEgress
		tableID = ifindex
	} else {
		egressPriority = linux_defaults.RulePriorityEgressv2
		tableID = computeTableIDFromIfaceNumber(info.InterfaceNumber)
	}

	_, err = fmt.Fprintf(w, "%s MW Configure Egress Routes, egressPriority: %s,tableID: %s, compat: %s\n", time.Now(), egressPriority, tableID, compat)

	if info.Masquerade {
		_, err = fmt.Fprintf(w, "%s MW Masquerading true\n", time.Now())
		// Lookup a VPC specific table for all traffic from an endpoint to the
		// CIDR configured for the VPC on which the endpoint has the IP on.

		for _, cidr := range info.IPv4CIDRs {
			_, err = fmt.Fprintf(w, "%s MW info.Masquerade=true - egressPriority: %s, ipWithMask: %s, cidr: %s, tableID: %s\n", time.Now(), egressPriority, ipWithMask, cidr, tableID)
			if err := route.ReplaceRule(route.Rule{
				Priority: egressPriority,
				From:     &ipWithMask,
				To:       &cidr,
				Table:    tableID,
			}); err != nil {
				return fmt.Errorf("unable to install ip rule: %s", err)
			}
		}
	} else {
		// Lookup a VPC specific table for all traffic from an endpoint.
		_, err = fmt.Fprintf(w, "%s MW info.Masquerade=false - egressPriority: %s, ipWithMask: %s, tableID: %s\n", time.Now(), egressPriority, ipWithMask, tableID)
		if err := route.ReplaceRule(route.Rule{
			Priority: egressPriority,
			From:     &ipWithMask,
			Table:    tableID,
		}); err != nil {
			return fmt.Errorf("unable to install ip rule: %s", err)
		}
	}

	// Nexthop route to the VPC or subnet gateway
	//
	// Note: This is a /32 route to avoid any L2. The endpoint does no L2
	// either.
	if err := netlink.RouteReplace(&netlink.Route{
		LinkIndex: ifindex,
		Dst:       &net.IPNet{IP: info.IPv4Gateway, Mask: net.CIDRMask(32, 32)},
		Scope:     netlink.SCOPE_LINK,
		Table:     tableID,
	}); err != nil {
		return fmt.Errorf("unable to add L2 nexthop route: %s", err)
	}
	_, err = fmt.Fprintf(w, "%s MW Nexthop route - LinkIndex: %s, Dst: %s, Scope: %s, Table: %s\n", time.Now(), ifindex, &net.IPNet{IP: info.IPv4Gateway, Mask: net.CIDRMask(32, 32)}, netlink.SCOPE_LINK, tableID)

	// Default route to the VPC or subnet gateway
	if err := netlink.RouteReplace(&netlink.Route{
		Dst:   &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
		Table: tableID,
		Gw:    info.IPv4Gateway,
	}); err != nil {
		return fmt.Errorf("unable to add L2 nexthop route: %s", err)
	}
	_, err = fmt.Fprintf(w, "%s MW Default route - Dst: %s, Table: %s, Gw: %s\n", time.Now(), &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}, tableID, info.IPv4Gateway)
	w.Flush()
	return nil
}

// Delete removes the ingress and egress rules that control traffic for
// endpoints. Note that the routes referenced by the rules are not deleted as
// they can be reused when another endpoint is created on the same node. The
// compat flag controls which egress priority to consider when deleting the
// egress rules (see option.Config.EgressMultiHomeIPRuleCompat).
//
// Note that one or more IPs may share the same route table, as identified by
// the interface number of the corresponding device. This function only removes
// the ingress and egress rules to disconnect the per-ENI egress routes from a
// specific local IP, and does not remove the corresponding route table as
// other IPs may still be using that table.
//
// The search for both the ingress & egress rule corresponding to this IP is a
// best-effort based on the respective priority that Cilium uses, which we
// assume full control over. The search for the ingress rule is more likely to
// succeed (albeit very rarely that egress deletion fails) because we are able
// to perform a narrower search on the rule because we know it references the
// main routing table. Due to multiple routing CIDRs, there might be more than
// one egress rule. Deletion of any rule only proceeds if the rule matches
// the IP & priority. If more than one rule matches, then deletion is skipped.
func Delete(ip net.IP, compat bool) error {
	if ip.To4() == nil {
		log.WithFields(logrus.Fields{
			"endpointIP": ip,
		}).Warning("Unable to delete rules because IP is not an IPv4 address")
		return errors.New("IP not compatible")
	}
	ipWithMask := net.IPNet{
		IP:   ip,
		Mask: net.CIDRMask(32, 32),
	}

	scopedLog := log.WithFields(logrus.Fields{
		"ip": ipWithMask.String(),
	})

	// Ingress rules
	ingress := route.Rule{
		Priority: linux_defaults.RulePriorityIngress,
		To:       &ipWithMask,
		Table:    route.MainTable,
	}
	if err := deleteRule(ingress); err != nil {
		return fmt.Errorf("unable to delete ingress rule from main table with ip %s: %v", ipWithMask.String(), err)
	}

	scopedLog.WithField("rule", ingress).Debug("Deleted ingress rule")

	priority := linux_defaults.RulePriorityEgressv2
	if compat {
		priority = linux_defaults.RulePriorityEgress
	}

	// Egress rules
	if info := node.GetRouterInfo(); info != nil && option.Config.IPAM == ipamOption.IPAMENI {
		ipv4CIDRs := info.GetIPv4CIDRs()
		cidrs := make([]*net.IPNet, 0, len(ipv4CIDRs))
		for i := range ipv4CIDRs {
			cidrs = append(cidrs, &ipv4CIDRs[i])
		}
		// Coalesce CIDRs into minimum set needed for route rules
		// This code here mirrors interfaceAdd() in cilium-cni/interface.go
		// and must be kept in sync when modified
		routingCIDRs, _ := iputil.CoalesceCIDRs(cidrs)
		for _, cidr := range routingCIDRs {
			egress := route.Rule{
				Priority: priority,
				From:     &ipWithMask,
				To:       cidr,
			}
			if err := deleteRule(egress); err != nil {
				return fmt.Errorf("unable to delete egress rule with ip %s: %w", ipWithMask.String(), err)
			}
			scopedLog.WithField(logfields.Rule, egress).Debug("Deleted egress rule")
		}
	} else {
		egress := route.Rule{
			Priority: priority,
			From:     &ipWithMask,
		}
		if err := deleteRule(egress); err != nil {
			return fmt.Errorf("unable to delete egress rule with ip %s: %w", ipWithMask.String(), err)
		}
		scopedLog.WithField(logfields.Rule, egress).Debug("Deleted egress rule")
	}

	return nil
}

// SetupRules installs routing rules based on the passed attributes. It accounts
// for option.Config.EgressMultiHomeIPRuleCompat while configuring the rules.
func SetupRules(from, to *net.IPNet, mac string, ifaceNum int) error {
	var (
		prio    int
		tableId int
	)

	if option.Config.EgressMultiHomeIPRuleCompat {
		prio = linux_defaults.RulePriorityEgress
		ifindex, err := retrieveIfaceIdxFromMAC(mac)
		if err != nil {
			return fmt.Errorf("unable to find ifindex for interface MAC: %w", err)
		}
		tableId = ifindex
	} else {
		prio = linux_defaults.RulePriorityEgressv2
		tableId = computeTableIDFromIfaceNumber(ifaceNum)
	}
	return route.ReplaceRule(route.Rule{
		Priority: prio,
		From:     from,
		To:       to,
		Table:    tableId,
	})
}

// RetrieveIfaceNameFromMAC finds the corresponding device name for a
// given MAC address.
func RetrieveIfaceNameFromMAC(mac string) (string, error) {
	iface, err := retrieveIfaceFromMAC(mac)
	if err != nil {
		err = fmt.Errorf("failed to get iface name with MAC %w", err)
		return "", err
	}
	return iface.Attrs().Name, nil
}

func deleteRule(r route.Rule) error {
	rules, err := route.ListRules(netlink.FAMILY_V4, &r)
	if err != nil {
		return err
	}

	length := len(rules)
	switch {
	case length > 1:
		log.WithFields(logrus.Fields{
			"candidates": rules,
			"rule":       r,
		}).Warning("Found too many rules matching, skipping deletion")
		return errors.New("unexpected number of rules found to delete")
	case length == 1:
		return route.DeleteRule(r)
	}

	log.WithFields(logrus.Fields{
		"rule": r,
	}).Warning("No rule matching found")

	return errors.New("no rule found to delete")
}

// retrieveIfIndexFromMAC finds the corresponding device index (ifindex) for a
// given MAC address, excluding Linux slave devices. This is useful for
// creating rules and routes in order to specify the table. When the ifindex is
// found, the device is brought up and its MTU is set.
func retrieveIfIndexFromMAC(mac mac.MAC, mtu int) (int, error) {
	var link netlink.Link

	links, err := netlink.LinkList()
	if err != nil {
		return -1, fmt.Errorf("unable to list interfaces: %w", err)
	}

	for _, l := range links {
		// Linux slave devices have the same MAC address as their master
		// device, but we want the master device.
		if l.Attrs().RawFlags&unix.IFF_SLAVE != 0 {
			continue
		}
		if l.Attrs().HardwareAddr.String() == mac.String() {
			if link != nil {
				return -1, fmt.Errorf("several interfaces found with MAC %s: %s and %s", mac, link.Attrs().Name, l.Attrs().Name)
			}
			link = l
		}
	}

	if link == nil {
		return -1, fmt.Errorf("interface with MAC %s not found", mac)
	}

	if err = netlink.LinkSetMTU(link, mtu); err != nil {
		return -1, fmt.Errorf("unable to change MTU of link %s to %d: %w", link.Attrs().Name, mtu, err)
	}
	if err = netlink.LinkSetUp(link); err != nil {
		return -1, fmt.Errorf("unable to up link %s: %w", link.Attrs().Name, err)
	}

	return link.Attrs().Index, nil
}

// computeTableIDFromIfaceNumber returns a computed per-ENI route table ID for the given
// ENI interface number.
func computeTableIDFromIfaceNumber(num int) int {
	return linux_defaults.RouteTableInterfacesOffset + num
}

// retrieveIfaceIdxFromMAC finds the corresponding interface index for a
// given MAC address.
// It returns -1 as the index for error conditions.
func retrieveIfaceIdxFromMAC(mac string) (int, error) {
	iface, err := retrieveIfaceFromMAC(mac)
	if err != nil {
		err = fmt.Errorf("failed to get iface index with MAC %w", err)
		return -1, err
	}
	return iface.Attrs().Index, nil
}

// retrieveIfaceFromFromMAC finds the corresponding interface for a
// given MAC address.
func retrieveIfaceFromMAC(mac string) (link netlink.Link, err error) {
	var links []netlink.Link

	links, err = netlink.LinkList()
	if err != nil {
		err = fmt.Errorf("unable to list interfaces: %w", err)
		return
	}
	for _, l := range links {
		if l.Attrs().HardwareAddr.String() == mac {
			link = l
			return
		}
	}

	err = fmt.Errorf("interface with MAC not found")
	return
}
