/*
 * Copyright 2022 The OpenYurt Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package libreswan

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/openyurtio/raven-controller-manager/pkg/ravencontroller/apis/raven/v1alpha1"
	"github.com/vdobler/ht/errorlist"
	"k8s.io/klog/v2"

	"github.com/openyurtio/raven/cmd/agent/app/config"
	netlinkutil "github.com/openyurtio/raven/pkg/networkengine/util/netlink"
	"github.com/openyurtio/raven/pkg/networkengine/vpndriver"
	"github.com/openyurtio/raven/pkg/types"
)

const (
	IPSecEncapLen = 64

	// DriverName specifies name of libreswan VPN backend driver.
	DriverName = "libreswan"
)

var _ vpndriver.Driver = (*libreswan)(nil)

// can be modified for testing.
var whackCmd = whackCmdFn
var findCentralGw = vpndriver.FindCentralGwFn

func init() {
	vpndriver.RegisterDriver(DriverName, New)
}

const (
	SecretFile string = "/etc/ipsec.d/raven.secrets"
)

type libreswan struct {
	connections map[string]*vpndriver.Connection
	nodeName    types.NodeName
}

func (l *libreswan) Init() error {
	// Ensure secrets file
	_, err := os.Stat(SecretFile)
	if err == nil {
		if err := os.Remove(SecretFile); err != nil {
			return err
		}
	}
	file, err := os.Create(SecretFile)
	if err != nil {
		klog.Errorf("fail to create secrets file: %v", err)
		return err
	}
	defer file.Close()

	psk := vpndriver.GetPSK()
	fmt.Fprintf(file, "%%any %%any : PSK \"%s\"\n", psk)

	return l.runPluto()
}

func New(cfg *config.Config) (vpndriver.Driver, error) {
	return &libreswan{
		connections: make(map[string]*vpndriver.Connection),
		nodeName:    types.NodeName(cfg.NodeName),
	}, nil
}

func (l *libreswan) Apply(network *types.Network, routeDriverMTUFn func(*types.Network) (int, error)) (err error) {
	errList := errorlist.List{}
	if network.LocalEndpoint == nil || len(network.RemoteEndpoints) == 0 {
		klog.Info("no local gateway or remote gateway is found, cleaning vpn connections")
		return l.Cleanup()
	}
	if network.LocalEndpoint.NodeName != l.nodeName {
		klog.Infof("the current node is not gateway node, cleaning vpn connections")
		return l.Cleanup()
	}

	desiredConnections := l.computeDesiredConnections(network)
	if len(desiredConnections) == 0 {
		klog.Infof("no desired connections, cleaning vpn connections")
		return l.Cleanup()
	}

	// remove unwanted connections
	for connName := range l.connections {
		if _, ok := desiredConnections[connName]; !ok {
			err := l.whackDelConnection(connName)
			if err != nil {
				errList = errList.Append(err)
				klog.ErrorS(err, "error disconnecting endpoint", "connectionName", connName)
				continue
			}
			delete(l.connections, connName)
		}
	}

	// add new connections
	for name, connection := range desiredConnections {
		err := l.connectToEndpoint(name, connection)
		errList = errList.Append(err)
	}

	return errList.AsError()
}

func (l *libreswan) MTU() (int, error) {
	mtu, err := vpndriver.DefaultMTU()
	if err != nil {
		return 0, err
	}
	return mtu - IPSecEncapLen, nil
}

func (l *libreswan) whackConnectToEndpoint(connectionName string, connection *vpndriver.Connection) error {
	args := make([]string, 0)
	leftID := fmt.Sprintf("@%s-%s-%s", connection.LocalEndpoint.PrivateIP, connection.LocalSubnet, connection.RemoteSubnet)
	rightID := fmt.Sprintf("@%s-%s-%s", connection.RemoteEndpoint.PrivateIP, connection.RemoteSubnet, connection.LocalSubnet)
	//TODO Configure "--forceencaps" only when necessary.
	//  "--forceencaps" is not necessary for endpoints that are not behind NAT device.
	args = append(args, "--psk", "--encrypt", "--forceencaps", "--name", connectionName,
		// local
		"--id", leftID,
		"--host", connection.LocalEndpoint.String(),
		"--client", connection.LocalSubnet,
		"--ikeport", "4500",

		"--to",

		// remote
		"--id", rightID,
		"--host", connection.RemoteEndpoint.PublicIP,
		"--client", connection.RemoteSubnet,
		"--ikeport", "4500")

	if err := whackCmd(args...); err != nil {
		return err
	}
	if !connection.LocalEndpoint.Central {
		if err := whackCmd("--route", "--name", connectionName); err != nil {
			return err
		}
		if err := whackCmd("--initiate", "--asynchronous", "--name", connectionName); err != nil {
			return err
		}
	}
	return nil
}

// getEndpointResolver returns a function that resolve the left subnets and the Endpoint that should connect to.
func (l *libreswan) getEndpointResolver(network *types.Network, centralGw *types.Endpoint) func(remoteGw *types.Endpoint) (leftSubnets []string, connectTo *types.Endpoint) {
	forwardGateways := make(map[types.GatewayName]struct{})
	for forward := range centralGw.Forwards {
		forwardGateways[types.GatewayName(forward.From)] = struct{}{}
	}

	snForwards := make(map[types.GatewayName][]string)
	for _, remoteEndpoints := range network.RemoteEndpoints {
		for _, ep := range remoteEndpoints {
			if _, ok := forwardGateways[ep.GatewayName]; ok {
				snForwards[ep.GatewayName] = append(snForwards[ep.GatewayName], ep.Subnets...)
			}
		}
	}
	return func(remoteGw *types.Endpoint) (leftSubnets []string, connectTo *types.Endpoint) {
		leftSubnets = network.LocalEndpoint.Subnets

		if centralGw.NodeName == l.nodeName {
			// If the local gateway is the central gateway,
			// in order to forward traffic from other NATed gateway to the NATed remoteGw,
			// append all subnets of other NATed gateways into left subnets.
			for gwName, v := range snForwards {
				if gwName != remoteGw.GatewayName {
					leftSubnets = append(leftSubnets, v...)
				}
			}
			return leftSubnets, remoteGw
		}

		// If both local and remote are not central gateway, connects to central gateway to forward traffic.
		if !network.LocalEndpoint.Central && !remoteGw.Central {
			if _, ok := centralGw.Forwards[v1alpha1.Forward{From: string(network.LocalEndpoint.GatewayName), To: string(remoteGw.GatewayName)}]; ok {
				return leftSubnets, centralGw
			}
			return []string{}, nil
		}

		return leftSubnets, remoteGw
	}
}

func (l *libreswan) computeDesiredConnections(network *types.Network) map[string]*vpndriver.Connection {
	centralGws := findCentralGw(network)

	// This is the desired connection calculated from given *types.Network
	desiredConns := make(map[string]*vpndriver.Connection)

	leftEndpoint := network.LocalEndpoint
	for _, remoteGws := range network.RemoteEndpoints {
		for _, rightEndpoint := range remoteGws {
			for _, centralGw := range centralGws {
				resolveEndpoint := l.getEndpointResolver(network, centralGw)
				leftSubnets, connectTo := resolveEndpoint(rightEndpoint)
				for _, leftSubnet := range leftSubnets {
					for _, rightSubnet := range rightEndpoint.Subnets {
						name := connectionName(leftEndpoint.PrivateIP, connectTo.PrivateIP, leftSubnet, rightSubnet)
						desiredConns[name] = &vpndriver.Connection{
							LocalEndpoint:  leftEndpoint.Copy(),
							RemoteEndpoint: connectTo.Copy(),
							LocalSubnet:    leftSubnet,
							RemoteSubnet:   rightSubnet,
						}
					}
				}
			}
		}
	}

	return desiredConns
}

func whackCmdFn(args ...string) error {
	var err error
	var output []byte
	for i := 0; i < 5; i++ {
		cmd := exec.Command("/usr/libexec/ipsec/whack", args...)
		output, err = cmd.CombinedOutput()
		if err == nil {
			klog.InfoS("whacking with", "args", args, "output", string(output))
			break
		}
		time.Sleep(1 * time.Second)
	}
	if err != nil {
		return fmt.Errorf("error whacking with %v: %v", args, err)
	}
	return nil
}

func (l *libreswan) whackDelConnection(conn string) error {
	return whackCmd("--delete", "--name", conn)
}

func connectionName(localID, remoteID, leftSubnet, rightSubnet string) string {
	return fmt.Sprintf("%s-%s-%s-%s", localID, remoteID, leftSubnet, rightSubnet)
}

func (l *libreswan) Cleanup() error {
	errList := errorlist.List{}
	for name := range l.connections {
		if err := l.whackDelConnection(name); err != nil {
			errList = errList.Append(err)
			klog.ErrorS(err, "fail to delete connection", "connectionName", name)
		}
	}
	l.connections = make(map[string]*vpndriver.Connection)
	err := netlinkutil.XfrmPolicyFlush()
	errList = errList.Append(err)
	return errList.AsError()
}

func (l *libreswan) runPluto() error {
	klog.Info("starting pluto")

	cmd := exec.Command("/usr/local/bin/pluto")

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Pdeathsig: syscall.SIGTERM,
	}

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Start()
	if err != nil {
		return fmt.Errorf("error start pluto: %v", err)
	}

	go func() {
		klog.Fatalf("pluto exited: %v", cmd.Wait())
	}()

	for i := 0; i < 5; i++ {
		_, err = os.Stat("/run/pluto/pluto.ctl")
		if err == nil {
			klog.Info("start pluto successfully")
			break
		}
		time.Sleep(1 * time.Second)
	}
	if err != nil {
		return fmt.Errorf("failed to stat the control socket: %v", err)
	}
	return nil
}

func (l *libreswan) connectToEndpoint(name string, connection *vpndriver.Connection) errorlist.List {
	errList := errorlist.List{}
	if _, ok := l.connections[name]; ok {
		klog.InfoS("skipping connect because connection already exists", "connectionName", name)
		return errList
	}
	err := l.whackConnectToEndpoint(name, connection)
	if err != nil {
		errList = errList.Append(err)
		klog.ErrorS(err, "error connect connection", "connectionName", name)
		return errList
	}
	l.connections[name] = connection
	return errList
}
