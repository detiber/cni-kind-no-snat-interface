// Copyright 2016 CNI authors
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

// This is a "meta-plugin". It reads in its own netconf, it does not create
// any network interface but just changes the network sysctl.

package main

import (
	"fmt"
	"net"

	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/coreos/go-iptables/iptables"
)

const kindPostRoutingChainName = "KIND-MASQ-AGENT"

func generateFilterRule(privChainName string) []string {
	return []string{"-m", "comment", "--comment", "CNI firewall plugin rules", "-j", privChainName}
}

func generateAdminRule(adminChainName string) []string {
	return []string{"-m", "comment", "--comment", "CNI firewall plugin admin overrides", "-j", adminChainName}
}

func cleanupRules(ipt *iptables.IPTables, privChainName string, rules [][]string) {
	for _, rule := range rules {
		ipt.Delete("nat", privChainName, rule...)
	}
}

func protoForIP(ip net.IPNet) iptables.Protocol {
	if ip.IP.To4() != nil {
		return iptables.ProtocolIPv4
	}
	return iptables.ProtocolIPv6
}

func (ib *iptablesBackend) addRules(conf *FirewallNetConf, result *current.Result, ipt *iptables.IPTables, proto iptables.Protocol) error {
	// TODO: Create chain
	// TODO: insert postrouting rule for chain before kindPostRoutingChainName
	// TODO: all rules for int/route combinations should be appended to our chain
	// TODO: rules we create should have a target of "RETURN"

	rules := make([][]string, 0)
	for _, route := range result.Routes {
		if protoForIP(route.Dst) == proto {
			rules = append(rules, getRules(result.Interfaces, route)...)
		}
	}

	if len(rules) > 0 {
		// Clean up on any errors
		var err error
		defer func() {
			if err != nil {
				cleanupRules(ipt, kindPostRoutingChainName, rules)
			}
		}()

		for _, rule := range rules {
			err = ipt.AppendUnique("nat", kindPostRoutingChainName, rule...)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (ib *iptablesBackend) delRules(conf *FirewallNetConf, result *current.Result, ipt *iptables.IPTables, proto iptables.Protocol) error {
	rules := make([][]string, 0)
	for _, ip := range result.IPs {
		if protoForIP(ip.Address) == proto {
			rules = append(rules, getRules(result.Interfaces, route)...)
		}
	}

	if len(rules) > 0 {
		cleanupRules(ipt, kindPostRoutingChainName, rules)
	}

	return nil
}

func (ib *iptablesBackend) checkRules(conf *FirewallNetConf, result *current.Result, ipt *iptables.IPTables, proto iptables.Protocol) error {
	rules := make([][]string, 0)
	for _, ip := range result.IPs {
		if protoForIP(ip.Address) == proto {
			rules = append(rules, getRules(result.Interfaces, route)...)
		}
	}

	if len(rules) <= 0 {
		return nil
	}

	// Ensure our filter rule exists in the POSTROUTING chain
	privRule := generateFilterRule(kindPostRoutingChainName)
	privExists, err := ipt.Exists("nat", "POSTROUTING", privRule...)
	if err != nil {
		return err
	}
	if !privExists {
		return fmt.Errorf("expected %v rule %v not found", "POSTROUTING", privRule)
	}

	// Ensure our admin override chain rule exists in our private chain
	adminRule := generateAdminRule(ib.adminChainName)
	adminExists, err := ipt.Exists("nat", kindPostRoutingChainName, adminRule...)
	if err != nil {
		return err
	}
	if !adminExists {
		return fmt.Errorf("expected %v rule %v not found", kindPostRoutingChainName, adminRule)
	}

	// ensure rules for this IP address exist
	for _, rule := range rules {
		// Ensure our rule exists in our private chain
		exists, err := ipt.Exists("nat", kindPostRoutingChainName, rule...)
		if err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("expected rule %v not found", rule)
		}
	}

	return nil
}

func findProtos(conf *FirewallNetConf) []iptables.Protocol {
	protos := []iptables.Protocol{iptables.ProtocolIPv4, iptables.ProtocolIPv6}
	if conf.PrevResult != nil {
		// If PrevResult is given, scan all IP addresses to figure out
		// which IP versions to use
		protos = []iptables.Protocol{}
		result, _ := current.NewResultFromResult(conf.PrevResult)
		for _, addr := range result.IPs {
			if addr.Address.IP.To4() != nil {
				protos = append(protos, iptables.ProtocolIPv4)
			} else {
				protos = append(protos, iptables.ProtocolIPv6)
			}
		}
	}
	return protos
}

type iptablesBackend struct {
	protos map[iptables.Protocol]*iptables.IPTables
	ifName string
}

// iptablesBackend implements the FirewallBackend interface
var _ FirewallBackend = &iptablesBackend{}

func newIptablesBackend(conf *FirewallNetConf) (FirewallBackend, error) {

	backend := &iptablesBackend{
		protos: make(map[iptables.Protocol]*iptables.IPTables),
	}

	for _, proto := range []iptables.Protocol{iptables.ProtocolIPv4, iptables.ProtocolIPv6} {
		ipt, err := iptables.NewWithProtocol(proto)
		if err != nil {
			return nil, fmt.Errorf("could not initialize iptables protocol %v: %v", proto, err)
		}
		backend.protos[proto] = ipt
	}

	return backend, nil
}

func (ib *iptablesBackend) Add(conf *FirewallNetConf, result *current.Result) error {
	for proto, ipt := range ib.protos {
		if err := ib.addRules(conf, result, ipt, proto); err != nil {
			return err
		}
	}
	return nil
}

func (ib *iptablesBackend) Del(conf *FirewallNetConf, result *current.Result) error {
	for proto, ipt := range ib.protos {
		ib.delRules(conf, result, ipt, proto)
	}
	return nil
}

func (ib *iptablesBackend) Check(conf *FirewallNetConf, result *current.Result) error {
	for proto, ipt := range ib.protos {
		if err := ib.checkRules(conf, result, ipt, proto); err != nil {
			return err
		}
	}
	return nil
}
