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

package disk

import (
	"context"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/containernetworking/plugins/plugins/ipam/host-local/backend"
	"github.com/containernetworking/plugins/plugins/ipam/host-local/logger"
)

const lastIPFilePrefix = "last_reserved_ip."
const LineBreak = "\r\n"

var defaultDataDir = "/var/lib/cni/networks"

// Store is a simple disk-backed store that creates one file per IP
// address in a given directory. The contents of the file are the container ID.
type Store struct {
	*FileLock
	dataDir string
}

// Store implements the Store interface
var _ backend.Store = &Store{}

func New(network, dataDir string) (*Store, error) {
	if dataDir == "" {
		dataDir = defaultDataDir
	}
	dir := filepath.Join(dataDir, network)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}

	lk, err := NewFileLock(dir)
	if err != nil {
		return nil, err
	}
	return &Store{lk, dir}, nil
}

func (s *Store) Reserve(ctx context.Context, id string, ifname string, ip net.IP, rangeID string) (bool, error) {
	fname := GetEscapedPath(s.dataDir, ip.String())

	logger.Infof(ctx, "Reserve: try to open file %v for container %v", fname, id)
	f, err := os.OpenFile(fname, os.O_RDWR|os.O_EXCL|os.O_CREATE, 0644)
	if os.IsExist(err) {
		logger.Warningf(ctx, "Reserve: file %s exists for container %v: %v", fname, id, err)
		return false, nil
	}
	if err != nil {
		logger.Errorf(ctx, "Reserve: failed to open file %v for container %v: %v", fname, id, err)
		return false, err
	}
	logger.Infof(ctx, "Reserve: open file %v for container %v successfully", fname, id)

	logger.Infof(ctx, "Reserve: try to write file %v for container %v", fname, id)
	if _, err := f.WriteString(strings.TrimSpace(id) + LineBreak + ifname); err != nil {
		logger.Errorf(ctx, "Reserve: failed to write file %v for container %v: %v", fname, id, err)
		if err := f.Close(); err != nil {
			logger.Errorf(ctx, "Reserve: rollback: failed to close file %v for container %v: %v", fname, id, err)
		}
		if err := os.Remove(f.Name()); err != nil {
			logger.Errorf(ctx, "Reserve: rollback: failed to remove file %v for container %v: %v", fname, id, err)
		}
		return false, err
	}
	logger.Infof(ctx, "Reserve: write file %v for container %v successfully", fname, id)

	logger.Infof(ctx, "Reserve: try to close file %v for container %v", fname, id)
	if err := f.Close(); err != nil {
		logger.Errorf(ctx, "Reserve: failed to close file %v for container %v: %v", fname, id, err)
		if err := os.Remove(f.Name()); err != nil {
			logger.Errorf(ctx, "Reserve: rollback: failed to remove file %v for container %v: %v", fname, id, err)
		}
		return false, err
	}
	logger.Infof(ctx, "Reserve: close file %v for container %v successfully", fname, id)

	// store the reserved ip in lastIPFile
	ipfile := GetEscapedPath(s.dataDir, lastIPFilePrefix+rangeID)
	err = ioutil.WriteFile(ipfile, []byte(ip.String()), 0644)
	if err != nil {
		logger.Errorf(ctx, "Reserve: failed to write last_reserved_ip file %v for container %v: %v", ipfile, id, err)
		return false, err
	}

	logger.Infof(ctx, "Reserve: reserve file %v for container %v successfully", fname, id)
	return true, nil
}

// LastReservedIP returns the last reserved IP if exists
func (s *Store) LastReservedIP(rangeID string) (net.IP, error) {
	ipfile := GetEscapedPath(s.dataDir, lastIPFilePrefix+rangeID)
	data, err := ioutil.ReadFile(ipfile)
	if err != nil {
		return nil, err
	}
	return net.ParseIP(string(data)), nil
}

func (s *Store) Release(ip net.IP) error {
	return os.Remove(GetEscapedPath(s.dataDir, ip.String()))
}

func (s *Store) FindByKey(id string, ifname string, match string) (bool, error) {
	found := false

	err := filepath.Walk(s.dataDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		data, err := ioutil.ReadFile(path)
		if err != nil {
			return nil
		}
		if strings.TrimSpace(string(data)) == match {
			found = true
		}
		return nil
	})
	return found, err

}

func (s *Store) FindByID(id string, ifname string) bool {
	s.Lock()
	defer s.Unlock()

	found := false
	match := strings.TrimSpace(id) + LineBreak + ifname
	found, err := s.FindByKey(id, ifname, match)

	// Match anything created by this id
	if !found && err == nil {
		match := strings.TrimSpace(id)
		found, err = s.FindByKey(id, ifname, match)
	}

	return found
}

func (s *Store) ReleaseByKey(ctx context.Context, id string, ifname string, match string) (bool, error) {
	found := false
	err := filepath.Walk(s.dataDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			if err != nil {
				logger.Errorf(ctx, "ReleaseByKey: error open path %v for container %v: %v", path, id, err)
			}
			return nil
		}
		data, err := ioutil.ReadFile(path)
		if err != nil {
			logger.Errorf(ctx, "ReleaseByKey: error read file %v for container %v: %v", path, id, err)
			return nil
		}
		if strings.TrimSpace(string(data)) == match {
			logger.Infof(ctx, "ReleaseByKey: find file %v for container %v", path, id)
			if err := os.Remove(path); err != nil {
				logger.Errorf(ctx, "ReleaseByKey: failed to remove file %v for container %v: %v", path, id, err)
				return nil
			}
			found = true
		}
		return nil
	})
	logger.Infof(ctx, "ReleaseByKey: returns found %v and err %v", found, err)
	return found, err

}

// N.B. This function eats errors to be tolerant and
// release as much as possible
func (s *Store) ReleaseByID(ctx context.Context, id string, ifname string) error {
	found := false
	match := strings.TrimSpace(id) + LineBreak + ifname
	found, err := s.ReleaseByKey(ctx, id, ifname, match)

	// For backwards compatibility, look for files written by a previous version
	if !found && err == nil {
		match := strings.TrimSpace(id)
		found, err = s.ReleaseByKey(ctx, id, ifname, match)
	}
	return err
}

// GetByID returns the IPs which have been allocated to the specific ID
func (s *Store) GetByID(id string, ifname string) []net.IP {
	var ips []net.IP

	match := strings.TrimSpace(id) + LineBreak + ifname
	// matchOld for backwards compatibility
	matchOld := strings.TrimSpace(id)

	// walk through all ips in this network to get the ones which belong to a specific ID
	_ = filepath.Walk(s.dataDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		data, err := ioutil.ReadFile(path)
		if err != nil {
			return nil
		}
		if strings.TrimSpace(string(data)) == match || strings.TrimSpace(string(data)) == matchOld {
			_, ipString := filepath.Split(path)
			if ip := net.ParseIP(ipString); ip != nil {
				ips = append(ips, ip)
			}
		}
		return nil
	})

	return ips
}

func GetEscapedPath(dataDir string, fname string) string {
	if runtime.GOOS == "windows" {
		fname = strings.Replace(fname, ":", "_", -1)
	}
	return filepath.Join(dataDir, fname)
}
