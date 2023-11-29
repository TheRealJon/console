package main

import (
	"os"

	authopts "github.com/openshift/console/cmd/bridge/config/auth"
	"github.com/openshift/console/pkg/auth"
	"github.com/openshift/console/pkg/flags"
	"github.com/openshift/console/pkg/server"
	"k8s.io/klog"
)

func getK8sAuthServiceAccountBearerToken() string {
	if k8sMode == flags.K8sModeInCluster {
		k8sAuthServiceAccountBearerToken, err := os.ReadFile(k8sInClusterBearerToken)
		if err != nil {
			klog.Fatalf("Error inferring Kubernetes config from environment: %v", err)
		}
		return string(k8sAuthServiceAccountBearerToken)
	}
	return ""
}

func applyBearerToken(srv *server.Server, authOptions *authopts.AuthOptions) {
	k8sAuthServiceAccountBearerToken := getK8sAuthServiceAccountBearerToken()
	switch k8sAuth {
	case flags.K8sAuthServiceAccount:
		flags.FatalIfFailed(flags.ValidateFlagIs("k8s-mode", k8sMode.String(), "in-cluster"))
		srv.StaticUser = &auth.User{
			Token: k8sAuthServiceAccountBearerToken,
		}
		srv.ServiceAccountToken = k8sAuthServiceAccountBearerToken
	case flags.K8sAuthBearerToken:
		flags.FatalIfFailed(flags.ValidateFlagNotEmpty("k8s-auth-bearer-token", k8sAuthBearerToken))

		srv.StaticUser = &auth.User{
			Token: k8sAuthBearerToken,
		}
		srv.ServiceAccountToken = k8sAuthBearerToken
	case flags.K8sAuthOIDC, flags.K8sAuthOpenShift:
		flags.FatalIfFailed(flags.ValidateFlagIs("user-auth", authOptions.AuthType.String(), "oidc", "openshift"))
		srv.ServiceAccountToken = k8sAuthServiceAccountBearerToken
	}
}
