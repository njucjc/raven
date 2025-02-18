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

package app

import (
	"context"
	"fmt"

	"github.com/lorenzosaino/go-sysctl"
	"k8s.io/klog/v2"

	"github.com/openyurtio/raven/cmd/agent/app/config"
	"github.com/openyurtio/raven/cmd/agent/app/options"
	ravenengine "github.com/openyurtio/raven/pkg/engine"
	"github.com/openyurtio/raven/pkg/features"
	"github.com/spf13/cobra"
)

// NewRavenAgentCommand creates a new raven agent command
func NewRavenAgentCommand(ctx context.Context) *cobra.Command {
	agentOptions := &options.AgentOptions{}
	cmd := &cobra.Command{
		Short: fmt.Sprintf("Launch %s", "raven-agent"),
		RunE: func(c *cobra.Command, args []string) error {
			if err := agentOptions.Validate(); err != nil {
				return err
			}
			cfg, err := agentOptions.Config()
			if err != nil {
				return err
			}
			if err := Run(ctx, cfg.Complete()); err != nil {
				return err
			}
			return nil
		},
		Args: cobra.NoArgs,
	}

	agentOptions.AddFlags(cmd.Flags())
	features.DefaultMutableFeatureGate.AddFlag(cmd.Flags())
	return cmd
}

// Run starts the raven-agent
func Run(ctx context.Context, cfg *config.CompletedConfig) error {
	klog.Info("Start raven agent")
	defer klog.Info("Stop raven agent")
	if err := disableICMPRedirect(); err != nil {
		return err
	}
	engine := ravenengine.NewEngine(ctx, cfg.Config)
	engine.Start()
	return nil
}

func disableICMPRedirect() error {
	obj := "net.ipv4.conf.all.send_redirects"
	val, err := sysctl.Get(obj)
	if err != nil {
		klog.ErrorS(err, "failed to sysctl get", obj)
		return err
	}
	if val != "0" {
		err = sysctl.Set(obj, "0")
		if err != nil {
			klog.ErrorS(err, "failed to sysctl set", obj)
			return err
		}
	}
	return nil
}
