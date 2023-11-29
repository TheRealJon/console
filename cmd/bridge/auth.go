package main

import (
	"os"

	authopts "github.com/openshift/console/cmd/bridge/config/auth"
	"github.com/openshift/console/pkg/flags"
	"github.com/openshift/console/pkg/server"
	"k8s.io/klog"
)

func applyAuth(srv *server.Server, authOptions *authopts.AuthOptions) {
	err := authOptions.Complete(k8sAuth)
	if err != nil {
		klog.Fatalf("failed to complete authentication options: %v", err)
		os.Exit(1)
	}

	caCertFilePath := caFile
	if k8sMode == flags.K8sModeInCluster {
		caCertFilePath = k8sInClusterCA
	}

	if err := authOptions.ApplyTo(srv, caCertFilePath.String()); err != nil {
		klog.Fatalf("failed to apply configuration to server: %v", err)
		os.Exit(1)
	}
}
