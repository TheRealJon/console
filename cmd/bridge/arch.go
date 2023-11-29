package main

import (
	"runtime"

	"github.com/openshift/console/pkg/flags"
	"github.com/openshift/console/pkg/server"
)

func applyArchAndOS(srv *server.Server) {
	// if !in-cluster (dev) we should not pass these values to the frontend
	// is used by catalog-utils.ts
	if k8sMode == flags.K8sModeInCluster {
		srv.GOARCH = runtime.GOARCH
		srv.GOOS = runtime.GOOS
	}
}
