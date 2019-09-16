package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/utils/buildversion"
	"github.com/vishvananda/netlink"
	"net"
)

func parseNetConf(bytes []byte) (*types.NetConf, error) {
	conf := &types.NetConf{}
	if err := json.Unmarshal(bytes, conf); err != nil {
		return nil, fmt.Errorf("failed to parse network config: %v", err)
	}

	if conf.RawPrevResult != nil {
		if err := version.ParsePrevResult(conf); err != nil {
			return nil, fmt.Errorf("failed to parse prevResult: %v", err)
		}
		if _, err := current.NewResultFromResult(conf.PrevResult); err != nil { // PrevResult is also a current.Result
			return nil, fmt.Errorf("failed to convert result to current version: %v", err)
		}
	}
	return conf, nil
}

func cmdAdd(args *skel.CmdArgs) error {
	conf, err := parseNetConf(args.StdinData)
	if err != nil {
		return err
	}

	var v4Addr, v6Addr *net.IPNet

	args.IfName = "mylo"
	err = ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error {
		dummy := &netlink.Dummy{
			LinkAttrs: netlink.LinkAttrs{
				Name: args.IfName,
			},
		}
		err := netlink.LinkAdd(dummy)
		if err != nil {
			return err
		}

		link, err := netlink.LinkByName(args.IfName)
		if err != nil {
			return err
		}

		err = netlink.LinkSetUp(link)
		if err != nil {
			return err
		}

		v4Addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
		if err != nil {
			return err // not tested
		}
		if len(v4Addrs) != 0 {
			v4Addr = v4Addrs[0].IPNet
			for _, addr := range v4Addrs {
				if !addr.IP.IsLoopback() {
					return fmt.Errorf("loopback interface found with non-loopback address %q", addr.IP)
				}
			}
		}

		v6Addrs, err := netlink.AddrList(link, netlink.FAMILY_V6)
		if err != nil {
			return err // not tested
		}
		if len(v6Addrs) != 0 {
			v6Addr = v6Addrs[0].IPNet
			// sanity check that this is a loopback address
			for _, addr := range v4Addrs {
				if !addr.IP.IsLoopback() {
					return fmt.Errorf("loopback interface found with non-loopback address %q", addr.IP)
				}
			}
		}

		return nil
	})
	if err != nil {
		return err
	}

	var result types.Result
	if conf.PrevResult != nil {
		result = conf.PrevResult
	} else {
		loopbackInterface := &current.Interface{Name: args.IfName, Mac: "00:00:00:00:00:00", Sandbox: args.Netns}
		r := &current.Result{
			CNIVersion: conf.CNIVersion,
			Interfaces: []*current.Interface{loopbackInterface},
			IPs:        nil,
		}

		if v4Addr != nil {
			r.IPs = append(r.IPs, &current.IPConfig{
				Version:   "4",
				Interface: current.Int(0),
				Address:   *v4Addr,
			})
		}

		if v6Addr != nil {
			r.IPs = append(r.IPs, &current.IPConfig{
				Version:   "6",
				Interface: current.Int(0),
				Address:   *v6Addr,
			})
		}

		result = r
	}
	return types.PrintResult(result, conf.CNIVersion)
}

func cmdCheck(args *skel.CmdArgs) error {
	args.IfName = "mylo"

	return ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error {
		link, err := netlink.LinkByName(args.IfName)
		if err != nil {
			return err
		}

		if link.Attrs().Flags&net.FlagUp != net.FlagUp {
			return errors.New("loopback interface is down")
		}

		return nil
	})
}

func cmdDel(args *skel.CmdArgs) error {
	if args.Netns == "" {
		return nil
	}
	args.IfName = "lo" // ignore config, this only works for loopback
	err := ns.WithNetNSPath(args.Netns, func(ns.NetNS) error {
		link, err := netlink.LinkByName(args.IfName)
		if err != nil {
			return err // not tested
		}

		err = netlink.LinkSetDown(link)
		if err != nil {
			return err // not tested
		}

		return nil
	})
	if err != nil {
		return err // not tested
	}

	return nil
}

func main() {
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.All, buildversion.BuildString("myloopback"))
}
