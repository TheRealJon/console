package bridge

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/url"
	"os"

	"github.com/openshift/console/pkg/flags"
	"github.com/openshift/console/pkg/proxy"
	oscrypto "github.com/openshift/library-go/pkg/crypto"
	"k8s.io/klog"
)

func (b *Bridge) getTLSConfig(file string) *tls.Config {
	switch b.K8sMode {
	case flags.K8sModeInCluster:
		if file == "" {
			return nil
		}
		certPEM, err := os.ReadFile(file)
		if err != nil {
			klog.Fatalf("failed to read %s file: %v", file, err)
		}
		rootCAs := x509.NewCertPool()
		if !rootCAs.AppendCertsFromPEM(certPEM) {
			klog.Fatalf("no CA found for %s", file)
		}
		return oscrypto.SecureTLSConfig(&tls.Config{
			RootCAs: rootCAs,
		})
	case flags.K8sModeOffCluster:
		return oscrypto.SecureTLSConfig(&tls.Config{
			InsecureSkipVerify: b.K8sModeOffClusterSkipVerifyTLS,
		})
	default:
		return nil
	}
}

func (b *Bridge) getProxyEndpoint(inClusterEndpoint *url.URL, offClusterEndpoint *url.URL) *url.URL {
	switch b.K8sMode {
	case flags.K8sModeInCluster:
		return inClusterEndpoint
	case flags.K8sModeOffCluster:
		return offClusterEndpoint
	default:
		return nil
	}
}

func (b *Bridge) applyK8sProxyConfig() {
	b.Handler.K8sProxyConfig = &proxy.Config{
		TLSClientConfig:         b.getTLSConfig(k8sInClusterCA),
		Endpoint:                b.getProxyEndpoint(inClusterK8sEndpoint, b.K8sModeOffClusterEndpoint.Get()),
		UseProxyFromEnvironment: b.K8sMode == flags.K8sModeOffCluster,
	}
}

func (b *Bridge) applyThanosProxyConfigs(tlsConfig *tls.Config) {
	offClusterThanosEndpoint := withAPIPath(b.K8sModeOffClusterThanos.Get())
	b.Handler.ThanosProxyConfig = &proxy.Config{
		TLSClientConfig: tlsConfig,
		Endpoint:        b.getProxyEndpoint(inClusterThanosEndpoint, offClusterThanosEndpoint),
	}
	b.Handler.ThanosTenancyProxyConfig = &proxy.Config{
		TLSClientConfig: tlsConfig,
		Endpoint:        b.getProxyEndpoint(inClusterThanosTenancyEndpoint, offClusterThanosEndpoint),
	}
	b.Handler.ThanosTenancyProxyForRulesConfig = &proxy.Config{
		TLSClientConfig: tlsConfig,
		Endpoint:        b.getProxyEndpoint(inClusterThanosTenancyForRulesEndpoint, offClusterThanosEndpoint),
	}
}

func (b *Bridge) applyAlertManagerProxyConfigs(tlsConfig *tls.Config) {
	var inClusterAlertManagerUserWorkloadEndpoint = &url.URL{Scheme: "https", Host: b.AlertmanagerUserWorkloadHost, Path: "/api"}
	var inClusterAlertManagerTenancyEndpoint = &url.URL{Scheme: "https", Host: b.AlertmanagerTenancyHost, Path: "/api"}
	offClusterAlertManagerEndpoint := withAPIPath(b.K8sModeOffClusterAlertmanager.Get())
	b.Handler.AlertManagerProxyConfig = &proxy.Config{
		TLSClientConfig: tlsConfig,
		Endpoint:        b.getProxyEndpoint(inClusterAlertManagerEndpoint, offClusterAlertManagerEndpoint),
	}
	b.Handler.AlertManagerUserWorkloadProxyConfig = &proxy.Config{
		TLSClientConfig: tlsConfig,
		Endpoint:        b.getProxyEndpoint(inClusterAlertManagerUserWorkloadEndpoint, offClusterAlertManagerEndpoint),
	}
	b.Handler.AlertManagerTenancyProxyConfig = &proxy.Config{
		TLSClientConfig: tlsConfig,
		Endpoint:        b.getProxyEndpoint(inClusterAlertManagerTenancyEndpoint, offClusterAlertManagerEndpoint),
	}
}

func (b *Bridge) applyGitOpsProxyConfig(tlsConfig *tls.Config) {
	offClusterGitOpsEndpoint := b.K8sModeOffClusterGitOps.Get()
	b.Handler.GitOpsProxyConfig = &proxy.Config{
		TLSClientConfig: tlsConfig,
		Endpoint:        b.getProxyEndpoint(inClusterGitOpsEndpoint, offClusterGitOpsEndpoint),
	}
}

func (b *Bridge) applyServiceProxyConfigs() {
	serviceProxyTLSConfig := b.getTLSConfig(b.ServiceCAFile.String())
	if serviceProxyTLSConfig != nil {
		b.Handler.ServiceClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: serviceProxyTLSConfig,
			},
		}
		b.applyThanosProxyConfigs(serviceProxyTLSConfig)
		b.applyAlertManagerProxyConfigs(serviceProxyTLSConfig)
		b.applyGitOpsProxyConfig(serviceProxyTLSConfig)
		b.Handler.TerminalProxyTLSConfig = serviceProxyTLSConfig
		b.Handler.PluginsProxyTLSConfig = serviceProxyTLSConfig
	}
}

func (b *Bridge) applyKubeAPIServerURL() {
	apiServerEndpoint := b.K8sPublicEndpoint.String()
	if apiServerEndpoint == "" {
		apiServerEndpoint = b.Handler.K8sProxyConfig.Endpoint.String()
	}
	b.Handler.KubeAPIServerURL = apiServerEndpoint
}

func (b *Bridge) applyK8sClient() {
	b.Handler.K8sClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: b.Handler.K8sProxyConfig.TLSClientConfig,
		},
	}
}

func (b *Bridge) applyClusterManagementProxyConfig() {
	b.Handler.ClusterManagementProxyConfig = &proxy.Config{
		TLSClientConfig: oscrypto.SecureTLSConfig(&tls.Config{}),
		Endpoint: &url.URL{
			Scheme: "https",
			Host:   "api.openshift.com",
			Path:   "/",
		},
	}
}

func (b *Bridge) applyProxyConfigs() {
	b.applyK8sProxyConfig()
	b.applyServiceProxyConfigs()
	b.applyKubeAPIServerURL()
	b.applyK8sClient()
	b.applyClusterManagementProxyConfig()
}

func withAPIPath(endpoint *url.URL) *url.URL {
	endpoint.Path += "/api"
	return endpoint
}
