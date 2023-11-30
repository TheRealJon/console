package bridge

import (
	"os"

	"github.com/openshift/console/pkg/flags"
	"k8s.io/klog"
)

func (b *Bridge) applyAuth() {
	err := b.AuthOptions.Complete(b.K8sAuth)
	if err != nil {
		klog.Fatalf("failed to complete authentication options: %v", err)
		os.Exit(1)
	}

	caCertFilePath := b.CaFile
	if b.K8sMode == flags.K8sModeInCluster {
		caCertFilePath = k8sInClusterCA
	}

	if err := b.AuthOptions.ApplyTo(b.Handler, caCertFilePath.String()); err != nil {
		klog.Fatalf("failed to apply configuration to server: %v", err)
		os.Exit(1)
	}
}
