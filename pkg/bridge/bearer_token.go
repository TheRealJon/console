package bridge

import (
	"os"

	"github.com/openshift/console/pkg/auth"
	"github.com/openshift/console/pkg/flags"
	"k8s.io/klog"
)

func (b *Bridge) getK8sAuthServiceAccountBearerToken() string {
	if b.K8sMode == flags.K8sModeInCluster {
		k8sAuthServiceAccountBearerToken, err := os.ReadFile(k8sInClusterBearerToken)
		if err != nil {
			klog.Fatalf("Error inferring Kubernetes config from environment: %v", err)
		}
		return string(k8sAuthServiceAccountBearerToken)
	}
	return ""
}

func (b *Bridge) applyBearerToken() {
	k8sAuthServiceAccountBearerToken := b.getK8sAuthServiceAccountBearerToken()
	switch b.K8sAuth {
	case flags.K8sAuthServiceAccount:
		flags.FatalIfFailed(flags.ValidateFlagIs("k8s-mode", b.K8sMode.String(), "in-cluster"))
		b.Handler.StaticUser = &auth.User{
			Token: k8sAuthServiceAccountBearerToken,
		}
		b.Handler.ServiceAccountToken = k8sAuthServiceAccountBearerToken
	case flags.K8sAuthBearerToken:
		flags.FatalIfFailed(flags.ValidateFlagNotEmpty("k8s-auth-bearer-token", b.K8sAuthBearerToken))

		b.Handler.StaticUser = &auth.User{
			Token: b.K8sAuthBearerToken,
		}
		b.Handler.ServiceAccountToken = b.K8sAuthBearerToken
	case flags.K8sAuthOIDC, flags.K8sAuthOpenShift:
		flags.FatalIfFailed(flags.ValidateFlagIs("user-auth", b.AuthOptions.AuthType.String(), "oidc", "openshift"))
		b.Handler.ServiceAccountToken = k8sAuthServiceAccountBearerToken
	}
}
