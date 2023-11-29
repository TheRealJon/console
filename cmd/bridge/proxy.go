package main

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/url"
	"os"

	"github.com/openshift/console/pkg/flags"
	"github.com/openshift/console/pkg/proxy"
	"github.com/openshift/console/pkg/server"
	oscrypto "github.com/openshift/library-go/pkg/crypto"
	"k8s.io/klog"
)

var inClusterK8sEndpoint = &url.URL{Scheme: "https", Host: "kubernetes.default.svc"}
var inClusterThanosEndpoint = &url.URL{Scheme: "https", Host: openshiftThanosHost, Path: "/api"}
var inClusterThanosTenancyEndpoint = &url.URL{Scheme: "https", Host: openshiftThanosTenancyHost, Path: "/api"}
var inClusterThanosTenancyForRulesEndpoint = &url.URL{Scheme: "https", Host: openshiftThanosTenancyForRulesHost, Path: "/api"}
var inClusterAlertManagerEndpoint = &url.URL{Scheme: "https", Host: openshiftAlertManagerHost, Path: "/api"}
var inClusterAlertManagerUserWorkloadEndpoint = &url.URL{Scheme: "https", Host: alertmanagerUserWorkloadHost, Path: "/api"}
var inClusterAlertManagerTenancyEndpoint = &url.URL{Scheme: "https", Host: alertmanagerTenancyHost, Path: "/api"}
var inClusterGitOpsEndpoint = &url.URL{Scheme: "https", Host: openshiftGitOpsHost}

func getTLSConfig(file string) *tls.Config {
	switch k8sMode {
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
			InsecureSkipVerify: k8sModeOffClusterSkipVerifyTLS,
		})
	default:
		return nil
	}
}

func withAPIPath(endpoint *url.URL) *url.URL {
	endpoint.Path += "/api"
	return endpoint
}

func getProxyEndpoint(inClusterEndpoint *url.URL, offClusterEndpoint *url.URL) *url.URL {
	switch k8sMode {
	case flags.K8sModeInCluster:
		return inClusterEndpoint
	case flags.K8sModeOffCluster:
		return offClusterEndpoint
	default:
		return nil
	}
}

func applyK8sProxyConfig(srv *server.Server) {
	srv.K8sProxyConfig = &proxy.Config{
		TLSClientConfig:         getTLSConfig(k8sInClusterCA),
		Endpoint:                getProxyEndpoint(inClusterK8sEndpoint, k8sModeOffClusterEndpoint.Get()),
		UseProxyFromEnvironment: k8sMode == flags.K8sModeOffCluster,
	}
}

func applyThanosProxyConfigs(srv *server.Server, tlsConfig *tls.Config) {
	offClusterThanosEndpoint := withAPIPath(k8sModeOffClusterThanos.Get())
	srv.ThanosProxyConfig = &proxy.Config{
		TLSClientConfig: tlsConfig,
		Endpoint:        getProxyEndpoint(inClusterThanosEndpoint, offClusterThanosEndpoint),
	}
	srv.ThanosTenancyProxyConfig = &proxy.Config{
		TLSClientConfig: tlsConfig,
		Endpoint:        getProxyEndpoint(inClusterThanosTenancyEndpoint, offClusterThanosEndpoint),
	}
	srv.ThanosTenancyProxyForRulesConfig = &proxy.Config{
		TLSClientConfig: tlsConfig,
		Endpoint:        getProxyEndpoint(inClusterThanosTenancyForRulesEndpoint, offClusterThanosEndpoint),
	}
}

func applyAlertManagerProxyConfigs(srv *server.Server, tlsConfig *tls.Config) {
	offClusterAlertManagerEndpoint := withAPIPath(k8sModeOffClusterAlertmanager.Get())
	srv.AlertManagerProxyConfig = &proxy.Config{
		TLSClientConfig: tlsConfig,
		Endpoint:        getProxyEndpoint(inClusterAlertManagerEndpoint, offClusterAlertManagerEndpoint),
	}
	srv.AlertManagerUserWorkloadProxyConfig = &proxy.Config{
		TLSClientConfig: tlsConfig,
		Endpoint:        getProxyEndpoint(inClusterAlertManagerUserWorkloadEndpoint, offClusterAlertManagerEndpoint),
	}
	srv.AlertManagerTenancyProxyConfig = &proxy.Config{
		TLSClientConfig: tlsConfig,
		Endpoint:        getProxyEndpoint(inClusterAlertManagerTenancyEndpoint, offClusterAlertManagerEndpoint),
	}
}

func applyGitOpsProxyConfig(srv *server.Server, tlsConfig *tls.Config) {
	offClusterGitOpsEndpoint := k8sModeOffClusterGitOps.Get()
	srv.GitOpsProxyConfig = &proxy.Config{
		TLSClientConfig: tlsConfig,
		Endpoint:        getProxyEndpoint(inClusterGitOpsEndpoint, offClusterGitOpsEndpoint),
	}
}

func applyServiceProxyConfigs(srv *server.Server) {
	serviceProxyTLSConfig := getTLSConfig(serviceCAFile.String())
	if serviceProxyTLSConfig != nil {
		srv.ServiceClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: serviceProxyTLSConfig,
			},
		}
		applyThanosProxyConfigs(srv, serviceProxyTLSConfig)
		applyAlertManagerProxyConfigs(srv, serviceProxyTLSConfig)
		applyGitOpsProxyConfig(srv, serviceProxyTLSConfig)
		srv.TerminalProxyTLSConfig = serviceProxyTLSConfig
		srv.PluginsProxyTLSConfig = serviceProxyTLSConfig
	}
}

func applyKubeAPIServerURL(srv *server.Server) {
	apiServerEndpoint := k8sPublicEndpoint.String()
	if apiServerEndpoint == "" {
		apiServerEndpoint = srv.K8sProxyConfig.Endpoint.String()
	}
	srv.KubeAPIServerURL = apiServerEndpoint
}

func applyK8sClient(srv *server.Server) {
	srv.K8sClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: srv.K8sProxyConfig.TLSClientConfig,
		},
	}
}

func applyClusterManagementProxyConfig(srv *server.Server) {
	srv.ClusterManagementProxyConfig = &proxy.Config{
		TLSClientConfig: oscrypto.SecureTLSConfig(&tls.Config{}),
		Endpoint: &url.URL{
			Scheme: "https",
			Host:   "api.openshift.com",
			Path:   "/",
		},
	}
}

func applyProxyConfigs(srv *server.Server) {
	applyK8sProxyConfig(srv)
	applyServiceProxyConfigs(srv)
	applyKubeAPIServerURL(srv)
	applyK8sClient(srv)
	applyClusterManagementProxyConfig(srv)
}
