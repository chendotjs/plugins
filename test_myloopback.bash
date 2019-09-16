#!/usr/bin/env bash
# cni conf with prevResult
sudo -E CNI_PATH=$GOPATH/src/github.com/containernetworking/plugins/bin CNI_COMMAND=ADD CNI_NETNS=/var/run/netns/ns CNI_IFNAME=loop CNI_CONTAINERID=pod-123 ./bin/myloopback < plugins/main/loopback/prevResult.json

