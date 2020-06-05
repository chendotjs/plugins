// Copyright 2015 CNI authors
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
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
	"github.com/containernetworking/plugins/plugins/ipam/host-local/backend/allocator"
	"github.com/containernetworking/plugins/plugins/ipam/host-local/backend/disk"
	"github.com/containernetworking/plugins/plugins/ipam/host-local/logger"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"

	"k8s.io/klog/v2"
)

func main() {
	klog.InitFlags(nil)
	flag.Set("logtostderr", "false")
	flag.Set("log_file", "/var/log/cce/host-local.log")
	flag.Parse()
	defer klog.Flush()

	if e := skel.PluginMainWithError(cmdAdd, cmdCheck, cmdDel, version.All, bv.BuildString("host-local")); e != nil {
		klog.Flush()
		if err := e.Print(); err != nil {
			log.Print("Error writing error JSON to stdout: ", err)
		}
		os.Exit(1)
	}
}

func loadNetConf(bytes []byte) (*types.NetConf, string, error) {
	n := &types.NetConf{}
	if err := json.Unmarshal(bytes, n); err != nil {
		return nil, "", fmt.Errorf("failed to load netconf: %v", err)
	}
	return n, n.CNIVersion, nil
}

func cmdCheck(args *skel.CmdArgs) error {

	ipamConf, _, err := allocator.LoadIPAMConfig(args.StdinData, args.Args)
	if err != nil {
		return err
	}

	// Look to see if there is at least one IP address allocated to the container
	// in the data dir, irrespective of what that address actually is
	store, err := disk.New(ipamConf.Name, ipamConf.DataDir)
	if err != nil {
		return err
	}
	defer store.Close()

	containerIpFound := store.FindByID(args.ContainerID, args.IfName)
	if containerIpFound == false {
		return fmt.Errorf("host-local: Failed to find address added by container %v", args.ContainerID)
	}

	return nil
}

func cmdAdd(args *skel.CmdArgs) error {
	ctx := logger.NewContext()
	logger.Infof(ctx, "-----------cmdAdd begins----------")
	defer logger.Infof(ctx, "-----------cmdAdd ends----------")
	logger.Infof(ctx, "***** cmdAdd: containerID: %v, netns: %v, ifName: %v, args: %v, path: %v",
		args.ContainerID, args.Netns, args.IfName, args.Args, args.Path)
	logger.Infof(ctx, "***** cmdAdd: stdinData: %v", string(args.StdinData))

	ipamConf, confVersion, err := allocator.LoadIPAMConfig(args.StdinData, args.Args)
	if err != nil {
		logger.Errorf(ctx, "failed to allocator.LoadIPAMConfig: %v", err)
		return err
	}

	result := &current.Result{}

	if ipamConf.ResolvConf != "" {
		dns, err := parseResolvConf(ipamConf.ResolvConf)
		if err != nil {
			return err
		}
		result.DNS = *dns
	}

	store, err := disk.New(ipamConf.Name, ipamConf.DataDir)
	if err != nil {
		logger.Errorf(ctx, "failed to disk.New: %v", err)
		return err
	}
	defer func() {
		if err := store.Close(); err != nil {
			logger.Errorf(ctx, "failed to close Store: %v", err)
		}
	}()

	// Keep the allocators we used, so we can release all IPs if an error
	// occurs after we start allocating
	allocs := []*allocator.IPAllocator{}

	// Store all requested IPs in a map, so we can easily remove ones we use
	// and error if some remain
	requestedIPs := map[string]net.IP{} //net.IP cannot be a key

	for _, ip := range ipamConf.IPArgs {
		requestedIPs[ip.String()] = ip
	}

	for idx, rangeset := range ipamConf.Ranges {
		allocator := allocator.NewIPAllocator(&rangeset, store, idx)

		// Check to see if there are any custom IPs requested in this range.
		var requestedIP net.IP
		for k, ip := range requestedIPs {
			if rangeset.Contains(ip) {
				requestedIP = ip
				delete(requestedIPs, k)
				break
			}
		}

		ipConf, err := allocator.Get(ctx, args.ContainerID, args.IfName, requestedIP)
		if err != nil {
			logger.Errorf(ctx, "failed to get allocated IP for container %v: %v", args.ContainerID, err)
			// Deallocate all already allocated IPs
			for _, alloc := range allocs {
				if err := alloc.Release(ctx, args.ContainerID, args.IfName); err != nil {
					logger.Errorf(ctx, "rollback: failed to release allocated IP for container %v: %v", args.ContainerID, err)
				}
			}
			return fmt.Errorf("failed to allocate for range %d: %v", idx, err)
		}
		logger.Infof(ctx, "get allocated IP for container %v successfully: %+v", args.ContainerID, *ipConf)

		allocs = append(allocs, allocator)

		result.IPs = append(result.IPs, ipConf)
	}

	// If an IP was requested that wasn't fulfilled, fail
	if len(requestedIPs) != 0 {
		for _, alloc := range allocs {
			_ = alloc.Release(ctx, args.ContainerID, args.IfName)
		}
		errstr := "failed to allocate all requested IPs:"
		for _, ip := range requestedIPs {
			errstr = errstr + " " + ip.String()
		}
		return fmt.Errorf(errstr)
	}

	result.Routes = ipamConf.Routes

	if data, err := json.MarshalIndent(result, "", "  "); err == nil {
		logger.Infof(ctx, "cmdAdd result data: %s", string(data))
	}

	return types.PrintResult(result, confVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	ctx := logger.NewContext()
	logger.Infof(ctx, "-----------cmdDel begins----------")
	defer logger.Infof(ctx, "-----------cmdDel ends----------")
	logger.Infof(ctx, "***** cmdDel: containerID: %v, netns: %v, ifName: %v, args: %v, path: %v",
		args.ContainerID, args.Netns, args.IfName, args.Args, args.Path)
	logger.Infof(ctx, "***** cmdDel: stdinData: %v", string(args.StdinData))
	ipamConf, _, err := allocator.LoadIPAMConfig(args.StdinData, args.Args)
	if err != nil {
		return err
	}

	store, err := disk.New(ipamConf.Name, ipamConf.DataDir)
	if err != nil {
		logger.Errorf(ctx, "failed to disk.New: %v", err)
		return err
	}
	defer func() {
		if err := store.Close(); err != nil {
			logger.Errorf(ctx, "failed to close Store: %v", err)
		}
	}()

	// Loop through all ranges, releasing all IPs, even if an error occurs
	var errors []string
	for idx, rangeset := range ipamConf.Ranges {
		ipAllocator := allocator.NewIPAllocator(&rangeset, store, idx)

		err := ipAllocator.Release(ctx, args.ContainerID, args.IfName)
		if err != nil {
			logger.Errorf(ctx, "failed to release for container %v: %v", args.ContainerID, err)
			errors = append(errors, err.Error())
		}
	}

	if errors != nil {
		return fmt.Errorf(strings.Join(errors, ";"))
	}
	return nil
}
