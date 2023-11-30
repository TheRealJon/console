package bridge

import (
	"runtime"

	"github.com/openshift/console/pkg/flags"
)

func (b *Bridge) applyArchAndOS() {
	// if !in-cluster (dev) we should not pass these values to the frontend
	// is used by catalog-utils.ts
	if b.K8sMode == flags.K8sModeInCluster {
		b.Server.GOARCH = runtime.GOARCH
		b.Server.GOOS = runtime.GOOS
	}
}
