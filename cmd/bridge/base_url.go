package main

import "github.com/openshift/console/pkg/server"

func applyBaseURL(srv *server.Server) {
	baseAddress.Path = basePath.String()
	srv.BaseURL = baseAddress.Get()
}
