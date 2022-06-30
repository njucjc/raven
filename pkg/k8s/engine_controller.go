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

package k8s

import (
	"context"
	"reflect"
	"time"

	"github.com/EvilSuperstars/go-cidrman"
	"github.com/openyurtio/raven-controller-manager/pkg/ravencontroller/apis/raven/v1alpha1"
	ravenclientset "github.com/openyurtio/raven-controller-manager/pkg/ravencontroller/client/clientset/versioned"
	raveninformer "github.com/openyurtio/raven-controller-manager/pkg/ravencontroller/client/informers/externalversions"
	ravenlister "github.com/openyurtio/raven-controller-manager/pkg/ravencontroller/client/listers/raven/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"github.com/openyurtio/raven/pkg/networkengine/routedriver"
	"github.com/openyurtio/raven/pkg/networkengine/vpndriver"
	"github.com/openyurtio/raven/pkg/types"
	"github.com/openyurtio/raven/pkg/utils"
)

const (
	maxRetries = 30
)

type EngineController struct {
	nodeName  string
	nodeInfos map[types.NodeName]*v1alpha1.NodeInfo
	network   *types.Network
	// lastSeenNetwork tracks the last seen Network.
	lastSeenNetwork *types.Network

	ravenClient   *ravenclientset.Clientset
	ravenInformer raveninformer.SharedInformerFactory

	gatewayLister ravenlister.GatewayLister
	hasSynced     func() bool
	queue         workqueue.RateLimitingInterface

	routeDriver routedriver.Driver
	vpnDriver   vpndriver.Driver
}

func NewEngineController(nodeName string, ravenClient *ravenclientset.Clientset,
	routeDriver routedriver.Driver, vpnDriver vpndriver.Driver) (*EngineController, error) {
	ctr := &EngineController{
		nodeName:    nodeName,
		ravenClient: ravenClient,
		queue:       workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
		routeDriver: routeDriver,
		vpnDriver:   vpnDriver,
	}

	ravenInformer := raveninformer.NewSharedInformerFactory(ctr.ravenClient, 24*time.Hour)
	ravenInformer.Raven().V1alpha1().Gateways().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    ctr.addGateway,
		UpdateFunc: ctr.updateGateway,
		DeleteFunc: ctr.deleteGateway,
	})
	ctr.ravenInformer = ravenInformer
	ctr.gatewayLister = ravenInformer.Raven().V1alpha1().Gateways().Lister()
	ctr.hasSynced = ravenInformer.Raven().V1alpha1().Gateways().Informer().HasSynced

	return ctr, nil
}

func (c *EngineController) Start(stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()
	c.ravenInformer.Start(stopCh)
	if !cache.WaitForCacheSync(stopCh, c.hasSynced) {
		klog.Errorf("failed to wait for cache sync")
		return
	}
	go wait.Until(c.worker, time.Second, stopCh)
	klog.Info("engine controller successfully start")
}

func (c *EngineController) worker() {
	for c.processNextWorkItem() {
	}
}

func (c *EngineController) enqueue(obj *v1alpha1.Gateway) {
	c.queue.Add(obj.Name)
}

func (c *EngineController) processNextWorkItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)

	err := c.sync()
	c.handleEventErr(err, key)

	return true
}

func getMergedSubnets(nodeInfo []v1alpha1.NodeInfo) []string {
	subnets := make([]string, 0)
	for _, n := range nodeInfo {
		subnets = append(subnets, n.Subnet)
	}
	subnets, _ = cidrman.MergeCIDRs(subnets)
	return subnets
}

// sync syncs full state according to the gateway list.
func (c *EngineController) sync() error {
	gws, err := c.gatewayLister.List(labels.Everything())
	if err != nil {
		return err
	}
	// As we are going to rebuild a full state, so cleanup before proceeding.
	c.network = &types.Network{
		LocalEndpoint:   nil,
		RemoteEndpoints: make(map[types.GatewayName][]*types.Endpoint),
		LocalNodeInfo:   make(map[types.NodeName]*v1alpha1.NodeInfo),
		RemoteNodeInfo:  make(map[types.NodeName]*v1alpha1.NodeInfo),
	}
	c.nodeInfos = make(map[types.NodeName]*v1alpha1.NodeInfo)

	for _, gw := range gws {
		// try to update public IP if empty.
		for _, aep := range gw.Status.ActiveEndpoints {
			if aep.Endpoint.PublicIP == "" {
				err := c.configGatewayPublicIP(gw.Name, aep)
				if err != nil {
					klog.ErrorS(err, "error config gateway public ip", "gateway", klog.KObj(gw))
				}
			}
		}
		if !c.shouldHandleGateway(gw) {
			continue
		}
		c.syncNodeInfo(gw)
	}
	for _, gw := range gws {
		if !c.shouldHandleGateway(gw) {
			continue
		}
		c.syncGateway(gw)
	}
	if reflect.DeepEqual(c.network, c.lastSeenNetwork) {
		klog.Info("network not changed, skip to process")
		return nil
	}
	nw := c.network.Copy()
	klog.InfoS("applying network", "localEndpoint", nw.LocalEndpoint, "remoteEndpoint", nw.RemoteEndpoints)
	err = c.vpnDriver.Apply(nw, c.routeDriver.MTU)
	if err != nil {
		return err
	}
	err = c.routeDriver.Apply(nw, c.vpnDriver.MTU)
	if err != nil {
		return err
	}

	// Only update lastSeenNetwork when all operations succeeded.
	c.lastSeenNetwork = c.network
	return nil
}

func (c *EngineController) syncNodeInfo(gw *v1alpha1.Gateway) {
	for _, aep := range gw.Status.ActiveEndpoints {
		for _, v := range aep.Nodes {
			c.nodeInfos[types.NodeName(v.NodeName)] = v.DeepCopy()
		}
	}
}

func (c *EngineController) syncGateway(gw *v1alpha1.Gateway) {
	isLocalGateway := false
	for _, aep := range gw.Status.ActiveEndpoints {
		for _, v := range aep.Nodes {
			if v.NodeName == c.nodeName {
				isLocalGateway = true
				break
			}
		}
		if isLocalGateway {
			break
		}
	}

	for _, aep := range gw.Status.ActiveEndpoints {
		subnets := getMergedSubnets(aep.Nodes)
		cfg := make(map[string]string)
		for k := range aep.Endpoint.Config {
			cfg[k] = aep.Endpoint.Config[k]
		}
		var nodeInfo *v1alpha1.NodeInfo
		if nodeInfo = c.nodeInfos[types.NodeName(aep.Endpoint.NodeName)]; nodeInfo == nil {
			klog.Errorf("node %s is found in Endpoint but not existed in NodeInfo", aep.Endpoint.NodeName)
			return
		}
		ep := &types.Endpoint{
			GatewayName: types.GatewayName(gw.Name),
			NodeName:    types.NodeName(aep.Endpoint.NodeName),
			Subnets:     subnets,
			PrivateIP:   nodeInfo.PrivateIP,
			PublicIP:    aep.Endpoint.PublicIP,
			Central:     gw.Status.Central,
			Forwards:    make(map[v1alpha1.Forward]struct{}),
			Config:      cfg,
		}
		for _, forward := range aep.Forwards {
			ep.Forwards[forward] = struct{}{}
		}

		if !isLocalGateway {
			c.network.RemoteEndpoints[ep.GatewayName] = append(c.network.RemoteEndpoints[ep.GatewayName], ep)
			for _, v := range aep.Nodes {
				c.network.RemoteNodeInfo[types.NodeName(v.NodeName)] = v.DeepCopy()
			}
		} else {
			isLocalActiveEndpoint := false
			for _, v := range aep.Nodes {
				if v.NodeName == c.nodeName {
					c.network.LocalEndpoint = ep
					isLocalActiveEndpoint = true
					break
				}
			}
			for _, v := range aep.Nodes {
				if isLocalActiveEndpoint {
					c.network.LocalNodeInfo[types.NodeName(v.NodeName)] = v.DeepCopy()
				}
			}
		}
	}
}

func (c *EngineController) handleEventErr(err error, event interface{}) {
	if err == nil {
		c.queue.Forget(event)
		return
	}
	if c.queue.NumRequeues(event) < maxRetries {
		klog.Infof("error syncing event %v: %v", event, err)
		c.queue.AddRateLimited(event)
		return
	}

	utilruntime.HandleError(err)
	klog.Infof("dropping event %q out of the queue: %v", event, err)
	c.queue.Forget(event)
}

func (c *EngineController) shouldHandleGateway(gateway *v1alpha1.Gateway) bool {
	if len(gateway.Status.ActiveEndpoints) == 0 {
		klog.InfoS("no active endpoints, waiting for sync", "gateway", klog.KObj(gateway))
		return false
	}
	for _, aep := range gateway.Status.ActiveEndpoints {
		if aep.Endpoint.PublicIP == "" {
			klog.InfoS("no public IP for gateway active endpoint, waiting for sync", "active endpoint", aep, "gateway", klog.KObj(gateway))
			return false
		}
	}
	return true
}

func (c *EngineController) configGatewayPublicIP(gwName string, aep *v1alpha1.ActiveEndpoint) error {
	if aep.Endpoint.NodeName != c.nodeName {
		return nil
	}
	publicIP, err := utils.GetPublicIP()
	if err != nil {
		return err
	}
	// retry to update public ip of localGateway
	err = retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		// get localGateway from api server
		apiGw, err := c.ravenClient.RavenV1alpha1().Gateways().Get(context.Background(), gwName, v1.GetOptions{})
		if err != nil {
			return err
		}
		for k, v := range apiGw.Spec.Endpoints {
			if v.NodeName == c.nodeName {
				apiGw.Spec.Endpoints[k].PublicIP = publicIP
				_, err = c.ravenClient.RavenV1alpha1().Gateways().Update(context.Background(), apiGw, v1.UpdateOptions{})
				return err
			}
		}
		return nil
	})
	return err
}

func (c *EngineController) addGateway(obj interface{}) {
	gw := obj.(*v1alpha1.Gateway)
	klog.V(4).InfoS("adding gateway", "gateway", klog.KObj(gw))
	c.enqueue(gw)
}

func (c *EngineController) updateGateway(oldObj interface{}, newObj interface{}) {
	oldGw := oldObj.(*v1alpha1.Gateway)
	newGw := newObj.(*v1alpha1.Gateway)
	if oldGw.ResourceVersion == newGw.ResourceVersion {
		klog.InfoS("skip handle update gateway", "gateway", klog.KObj(newGw))
		return
	}
	klog.V(4).InfoS("updating gateway", "gateway", klog.KObj(newGw))
	c.enqueue(newGw)
}

func (c *EngineController) deleteGateway(obj interface{}) {
	gw := obj.(*v1alpha1.Gateway)
	klog.InfoS("deleting gateway", "gateway", klog.KObj(gw))
	c.enqueue(gw)
}
