// Copyright 2019 Authors of Cilium
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

package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
  "path/filepath"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	linuxrouting "github.com/cilium/cilium/pkg/datapath/linux/routing"
	"github.com/cilium/cilium/pkg/ip"

	"github.com/containernetworking/cni/pkg/types/current"
)

func checkerr(e error) {
	if e != nil {
		fmt.Errorf("error: %s", e)
	}
}

func interfaceAdd(ipConfig *current.IPConfig, ipam *models.IPAMAddressResponse, conf models.DaemonConfigurationStatus) error {
  prgname := filepath.Base(os.Args[0])
  filename := "/tmp/"+prgname+".log"
  f, err := os.OpenFile(filename,
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	checkerr(err)
	defer f.Close()
	w := bufio.NewWriter(f)

	// If the gateway IP is not available, it is already set up
	_, err = fmt.Fprintf(w, "%s MW interfaceAdd, ipam.Gateway: %s\n", time.Now(), ipam.Gateway)
	if ipam.Gateway == "" {
		_, err = fmt.Fprintf(w, "%s MW interfaceAdd, ipam.Gateway is empty: %s\n", time.Now(), ipam.Gateway)
		return nil
	}


	var masq bool
	if ipConfig.Version == "4" {
		masq = conf.MasqueradeProtocols.IPV4
	} else if ipConfig.Version == "6" {
		masq = conf.MasqueradeProtocols.IPV6
	} else {
		return fmt.Errorf("Invalid IPConfig version: %s", ipConfig.Version)
	}

	allCIDRs := make([]*net.IPNet, 0, len(ipam.Cidrs))
	_, err = fmt.Fprintf(w, "%s MW interfaceAdd, allCIDRs: %s\n", time.Now(), allCIDRs)

	for _, cidrString := range ipam.Cidrs {
		_, err = fmt.Fprintf(w, "%s MW interfaceAdd, ipam.Cidrs loop, processing cidrString: %s\n", time.Now(), cidrString)
		_, cidr, err := net.ParseCIDR(cidrString)
		if err != nil {
			return fmt.Errorf("invalid CIDR '%s': %s", cidrString, err)
		}
		allCIDRs = append(allCIDRs, cidr)
	}

	_, err = fmt.Fprintf(w, "%s MW interfaceAdd, allCIDRs result after loop: %s\n", time.Now(), allCIDRs)
	// Coalesce CIDRs into minimum set needed for route rules
	// The routes set up here will be cleaned up by linuxrouting.Delete.
	// Therefore the code here should be kept in sync with the deletion code.
	ipv4CIDRs, _ := ip.CoalesceCIDRs(allCIDRs)
	_, err = fmt.Fprintf(w, "%s MW interfaceAdd, ipv4CIDRs: %s\n", time.Now(), ipv4CIDRs)
	cidrs := make([]string, 0, len(ipv4CIDRs))
	for _, cidr := range ipv4CIDRs {
		_, err = fmt.Fprintf(w, "%s MW interfaceAdd, ipv4CIDRs loop appending cidr: %s to existing ipv4CIDRs\n", time.Now(), cidr)
		cidrs = append(cidrs, cidr.String())
	}
	_, err = fmt.Fprintf(w, "%s MW interfaceAdd, routingInfo.cidrs: %s\n", time.Now(), cidrs)
	routingInfo, err := linuxrouting.NewRoutingInfo(
		ipam.Gateway,
		cidrs,
		ipam.MasterMac,
		ipam.InterfaceNumber,
		masq,
	)
	_, err = fmt.Fprintf(w, "%s MW interfaceAdd, routingInfo: %s\n", time.Now(), routingInfo)
	if err != nil {
		return fmt.Errorf("unable to parse routing info: %v", err)
	}

	if err := routingInfo.Configure(
		ipConfig.Address.IP,
		int(conf.DeviceMTU),
		conf.EgressMultiHomeIPRuleCompat,
	); err != nil {
		return fmt.Errorf("unable to install ip rules and routes: %s", err)
	}

	w.Flush()
	return nil
}
