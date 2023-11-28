package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"runtime"

	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"

	authopts "github.com/openshift/console/cmd/bridge/config/auth"
	"github.com/openshift/console/pkg/auth"
	"github.com/openshift/console/pkg/flags"
	"github.com/openshift/console/pkg/knative"
	"github.com/openshift/console/pkg/proxy"
	"github.com/openshift/console/pkg/server"
	"github.com/openshift/console/pkg/serverconfig"
	oscrypto "github.com/openshift/library-go/pkg/crypto"

	"k8s.io/klog"
)

func main() {
	fs := flag.NewFlagSet("bridge", flag.ExitOnError)
	initFlags(fs)
	klog.InitFlags(fs)
	defer klog.Flush()
	authOptions := authopts.NewAuthOptions()
	authOptions.AddFlags(fs)

	cfg, err := serverconfig.Parse(fs, os.Args[1:], "BRIDGE")
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	if err := serverconfig.Validate(fs); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	authOptions.ApplyConfig(&cfg.Auth)

	baseURL, err := flags.ValidateFlagIsURL("base-address", fBaseAddress, true)
	flags.FatalIfFailed(err)

	if !strings.HasPrefix(fBasePath, "/") || !strings.HasSuffix(fBasePath, "/") {
		flags.FatalIfFailed(flags.NewInvalidFlagError("base-path", "value must start and end with slash"))
	}
	baseURL.Path = fBasePath

	documentationBaseURL := &url.URL{}
	if fDocumentationBaseURL != "" {
		if !strings.HasSuffix(fDocumentationBaseURL, "/") {
			flags.FatalIfFailed(flags.NewInvalidFlagError("documentation-base-url", "value must end with slash"))
		}
		documentationBaseURL, err = flags.ValidateFlagIsURL("documentation-base-url", fDocumentationBaseURL, false)
		flags.FatalIfFailed(err)
	}

	alertManagerPublicURL, err := flags.ValidateFlagIsURL("alermanager-public-url", fAlermanagerPublicURL, true)
	flags.FatalIfFailed(err)

	grafanaPublicURL, err := flags.ValidateFlagIsURL("grafana-public-url", fGrafanaPublicURL, true)
	flags.FatalIfFailed(err)

	prometheusPublicURL, err := flags.ValidateFlagIsURL("prometheus-public-url", fPrometheusPublicURL, true)
	flags.FatalIfFailed(err)

	thanosPublicURL, err := flags.ValidateFlagIsURL("thanos-public-url", fThanosPublicURL, true)
	flags.FatalIfFailed(err)

	branding := fBranding
	if branding == "origin" {
		branding = "okd"
	}
	switch branding {
	case "okd":
	case "openshift":
	case "ocp":
	case "online":
	case "dedicated":
	case "azure":
	case "rosa":
	default:
		flags.FatalIfFailed(flags.NewInvalidFlagError("branding", "value must be one of okd, openshift, ocp, online, dedicated, azure, or rosa"))
	}

	if fCustomLogoFile != "" {
		if _, err := os.Stat(fCustomLogoFile); err != nil {
			klog.Fatalf("could not read logo file: %v", err)
		}
	}

	if len(consolePluginsFlags) > 0 {
		klog.Infoln("The following console plugins are enabled:")
		for pluginName := range consolePluginsFlags {
			klog.Infof(" - %s\n", pluginName)
		}
	}

	i18nNamespaces := []string{}
	if fI18NamespacesFlags != "" {
		for _, str := range strings.Split(fI18NamespacesFlags, ",") {
			str = strings.TrimSpace(str)
			if str == "" {
				flags.FatalIfFailed(flags.NewInvalidFlagError("i18n-namespaces", "list must contain name of i18n namespaces separated by comma"))
			}
			i18nNamespaces = append(i18nNamespaces, str)
		}
	}

	nodeArchitectures := []string{}
	if fNodeArchitectures != "" {
		for _, str := range strings.Split(fNodeArchitectures, ",") {
			str = strings.TrimSpace(str)
			if str == "" {
				flags.FatalIfFailed(flags.NewInvalidFlagError("node-architectures", "list must contain name of node architectures separated by comma"))
			}
			nodeArchitectures = append(nodeArchitectures, str)
		}
	}

	nodeOperatingSystems := []string{}
	if fNodeOperatingSystems != "" {
		for _, str := range strings.Split(fNodeOperatingSystems, ",") {
			str = strings.TrimSpace(str)
			if str == "" {
				flags.FatalIfFailed(flags.NewInvalidFlagError("node-operating-systems", "list must contain name of node architectures separated by comma"))
			}
			nodeOperatingSystems = append(nodeOperatingSystems, str)
		}
	}

	srv := &server.Server{
		PublicDir:                    fPublicDir,
		BaseURL:                      baseURL,
		Branding:                     branding,
		CustomProductName:            fCustomProductName,
		CustomLogoFile:               fCustomLogoFile,
		ControlPlaneTopology:         fControlPlaneTopology,
		StatuspageID:                 fStatuspageID,
		DocumentationBaseURL:         documentationBaseURL,
		AlertManagerUserWorkloadHost: fAlertmanagerUserWorkloadHost,
		AlertManagerTenancyHost:      fAlertmanagerTenancyHost,
		AlertManagerPublicURL:        alertManagerPublicURL,
		GrafanaPublicURL:             grafanaPublicURL,
		PrometheusPublicURL:          prometheusPublicURL,
		ThanosPublicURL:              thanosPublicURL,
		LoadTestFactor:               fLoadTestFactor,
		DevCatalogCategories:         fDevCatalogCategories,
		DevCatalogTypes:              fDevCatalogTypes,
		UserSettingsLocation:         fUserSettingsLocation,
		EnabledConsolePlugins:        consolePluginsFlags,
		I18nNamespaces:               i18nNamespaces,
		PluginProxy:                  fPluginProxy,
		QuickStarts:                  fQuickStarts,
		AddPage:                      fAddPage,
		ProjectAccessClusterRoles:    fProjectAccessClusterRoles,
		Perspectives:                 fPerspectives,
		Telemetry:                    telemetryFlags,
		ReleaseVersion:               fReleaseVersion,
		NodeArchitectures:            nodeArchitectures,
		NodeOperatingSystems:         nodeOperatingSystems,
		K8sMode:                      fK8sMode,
		CopiedCSVsDisabled:           fCopiedCSVsDisabled,
	}

	completedAuthnOptions, err := authOptions.Complete(fK8sAuth)
	if err != nil {
		klog.Fatalf("failed to complete authentication options: %v", err)
		os.Exit(1)
	}

	// if !in-cluster (dev) we should not pass these values to the frontend
	// is used by catalog-utils.ts
	if fK8sMode == "in-cluster" {
		srv.GOARCH = runtime.GOARCH
		srv.GOOS = runtime.GOOS
	}

	if fLogLevel != "" {
		klog.Warningf("DEPRECATED: --log-level is now deprecated, use verbosity flag --v=Level instead")
	}

	var (
		// Hold on to raw certificates so we can render them in kubeconfig files.
		k8sCertPEM []byte
	)

	var (
		k8sAuthServiceAccountBearerToken string
	)

	var k8sEndpoint *url.URL
	switch fK8sMode {
	case "in-cluster":
		k8sEndpoint = &url.URL{Scheme: "https", Host: "kubernetes.default.svc"}
		var err error
		k8sCertPEM, err = ioutil.ReadFile(k8sInClusterCA)
		if err != nil {
			klog.Fatalf("Error inferring Kubernetes config from environment: %v", err)
		}
		rootCAs := x509.NewCertPool()
		if !rootCAs.AppendCertsFromPEM(k8sCertPEM) {
			klog.Fatal("No CA found for the API server")
		}
		tlsConfig := oscrypto.SecureTLSConfig(&tls.Config{
			RootCAs: rootCAs,
		})

		bearerToken, err := ioutil.ReadFile(k8sInClusterBearerToken)
		if err != nil {
			klog.Fatalf("failed to read bearer token: %v", err)
		}

		srv.K8sProxyConfig = &proxy.Config{
			TLSClientConfig: tlsConfig,
			HeaderBlacklist: []string{"Cookie", "X-CSRFToken"},
			Endpoint:        k8sEndpoint,
		}

		k8sAuthServiceAccountBearerToken = string(bearerToken)

		// If running in an OpenShift cluster, set up a proxy to the prometheus-k8s service running in the openshift-monitoring namespace.
		if fServiceCAFile != "" {
			serviceCertPEM, err := ioutil.ReadFile(fServiceCAFile)
			if err != nil {
				klog.Fatalf("failed to read service-ca.crt file: %v", err)
			}
			serviceProxyRootCAs := x509.NewCertPool()
			if !serviceProxyRootCAs.AppendCertsFromPEM(serviceCertPEM) {
				klog.Fatal("no CA found for Kubernetes services")
			}
			serviceProxyTLSConfig := oscrypto.SecureTLSConfig(&tls.Config{
				RootCAs: serviceProxyRootCAs,
			})

			srv.ServiceClient = &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: serviceProxyTLSConfig,
				},
			}

			srv.ThanosProxyConfig = &proxy.Config{
				TLSClientConfig: serviceProxyTLSConfig,
				HeaderBlacklist: []string{"Cookie", "X-CSRFToken"},
				Endpoint:        &url.URL{Scheme: "https", Host: openshiftThanosHost, Path: "/api"},
			}
			srv.ThanosTenancyProxyConfig = &proxy.Config{
				TLSClientConfig: serviceProxyTLSConfig,
				HeaderBlacklist: []string{"Cookie", "X-CSRFToken"},
				Endpoint:        &url.URL{Scheme: "https", Host: openshiftThanosTenancyHost, Path: "/api"},
			}
			srv.ThanosTenancyProxyForRulesConfig = &proxy.Config{
				TLSClientConfig: serviceProxyTLSConfig,
				HeaderBlacklist: []string{"Cookie", "X-CSRFToken"},
				Endpoint:        &url.URL{Scheme: "https", Host: openshiftThanosTenancyForRulesHost, Path: "/api"},
			}

			srv.AlertManagerProxyConfig = &proxy.Config{
				TLSClientConfig: serviceProxyTLSConfig,
				HeaderBlacklist: []string{"Cookie", "X-CSRFToken"},
				Endpoint:        &url.URL{Scheme: "https", Host: openshiftAlertManagerHost, Path: "/api"},
			}
			srv.AlertManagerUserWorkloadProxyConfig = &proxy.Config{
				TLSClientConfig: serviceProxyTLSConfig,
				HeaderBlacklist: []string{"Cookie", "X-CSRFToken"},
				Endpoint:        &url.URL{Scheme: "https", Host: fAlertmanagerUserWorkloadHost, Path: "/api"},
			}
			srv.AlertManagerTenancyProxyConfig = &proxy.Config{
				TLSClientConfig: serviceProxyTLSConfig,
				HeaderBlacklist: []string{"Cookie", "X-CSRFToken"},
				Endpoint:        &url.URL{Scheme: "https", Host: fAlertmanagerTenancyHost, Path: "/api"},
			}
			srv.TerminalProxyTLSConfig = serviceProxyTLSConfig
			srv.PluginsProxyTLSConfig = serviceProxyTLSConfig

			srv.GitOpsProxyConfig = &proxy.Config{
				TLSClientConfig: serviceProxyTLSConfig,
				HeaderBlacklist: []string{"Cookie", "X-CSRFToken"},
				Endpoint:        &url.URL{Scheme: "https", Host: openshiftGitOpsHost},
			}
		}

	case "off-cluster":
		k8sEndpoint, err = flags.ValidateFlagIsURL("k8s-mode-off-cluster-endpoint", fK8sModeOffClusterEndpoint, false)
		flags.FatalIfFailed(err)

		serviceProxyTLSConfig := oscrypto.SecureTLSConfig(&tls.Config{
			InsecureSkipVerify: fK8sModeOffClusterSkipVerifyTLS,
		})

		srv.ServiceClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: serviceProxyTLSConfig,
			},
		}

		srv.K8sProxyConfig = &proxy.Config{
			TLSClientConfig:         serviceProxyTLSConfig,
			HeaderBlacklist:         []string{"Cookie", "X-CSRFToken"},
			Endpoint:                k8sEndpoint,
			UseProxyFromEnvironment: true,
		}

		if fK8sModeOffClusterThanos != "" {
			offClusterThanosURL, err := flags.ValidateFlagIsURL("k8s-mode-off-cluster-thanos", fK8sModeOffClusterThanos, false)
			flags.FatalIfFailed(err)

			offClusterThanosURL.Path += "/api"
			srv.ThanosTenancyProxyConfig = &proxy.Config{
				TLSClientConfig: serviceProxyTLSConfig,
				HeaderBlacklist: []string{"Cookie", "X-CSRFToken"},
				Endpoint:        offClusterThanosURL,
			}
			srv.ThanosTenancyProxyForRulesConfig = &proxy.Config{
				TLSClientConfig: serviceProxyTLSConfig,
				HeaderBlacklist: []string{"Cookie", "X-CSRFToken"},
				Endpoint:        offClusterThanosURL,
			}
			srv.ThanosProxyConfig = &proxy.Config{
				TLSClientConfig: serviceProxyTLSConfig,
				HeaderBlacklist: []string{"Cookie", "X-CSRFToken"},
				Endpoint:        offClusterThanosURL,
			}
		}

		if fK8sModeOffClusterAlertmanager != "" {
			offClusterAlertManagerURL, err := flags.ValidateFlagIsURL("k8s-mode-off-cluster-alertmanager", fK8sModeOffClusterAlertmanager, false)
			flags.FatalIfFailed(err)

			offClusterAlertManagerURL.Path += "/api"
			srv.AlertManagerProxyConfig = &proxy.Config{
				TLSClientConfig: serviceProxyTLSConfig,
				HeaderBlacklist: []string{"Cookie", "X-CSRFToken"},
				Endpoint:        offClusterAlertManagerURL,
			}
			srv.AlertManagerTenancyProxyConfig = &proxy.Config{
				TLSClientConfig: serviceProxyTLSConfig,
				HeaderBlacklist: []string{"Cookie", "X-CSRFToken"},
				Endpoint:        offClusterAlertManagerURL,
			}
			srv.AlertManagerUserWorkloadProxyConfig = &proxy.Config{
				TLSClientConfig: serviceProxyTLSConfig,
				HeaderBlacklist: []string{"Cookie", "X-CSRFToken"},
				Endpoint:        offClusterAlertManagerURL,
			}
		}

		srv.TerminalProxyTLSConfig = serviceProxyTLSConfig
		srv.PluginsProxyTLSConfig = serviceProxyTLSConfig

		if fK8sModeOffClusterGitOps != "" {
			offClusterGitOpsURL, err := flags.ValidateFlagIsURL("k8s-mode-off-cluster-gitops", fK8sModeOffClusterGitOps, false)
			flags.FatalIfFailed(err)

			srv.GitOpsProxyConfig = &proxy.Config{
				TLSClientConfig: serviceProxyTLSConfig,
				HeaderBlacklist: []string{"Cookie", "X-CSRFToken"},
				Endpoint:        offClusterGitOpsURL,
			}
		}
	default:
		flags.FatalIfFailed(flags.NewInvalidFlagError("k8s-mode", "must be one of: in-cluster, off-cluster"))
	}

	apiServerEndpoint := fK8sPublicEndpoint
	if apiServerEndpoint == "" {
		apiServerEndpoint = srv.K8sProxyConfig.Endpoint.String()
	}
	srv.KubeAPIServerURL = apiServerEndpoint
	srv.K8sClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: srv.K8sProxyConfig.TLSClientConfig,
		},
	}

	clusterManagementURL, err := url.Parse(clusterManagementURL)
	if err != nil {
		klog.Fatalf("failed to parse %q", clusterManagementURL)
	}
	srv.ClusterManagementProxyConfig = &proxy.Config{
		TLSClientConfig: oscrypto.SecureTLSConfig(&tls.Config{}),
		HeaderBlacklist: []string{"Cookie", "X-CSRFToken"},
		Endpoint:        clusterManagementURL,
	}

	switch fK8sAuth {
	case "service-account":
		flags.FatalIfFailed(flags.ValidateFlagIs("k8s-mode", fK8sMode, "in-cluster"))
		srv.StaticUser = &auth.User{
			Token: k8sAuthServiceAccountBearerToken,
		}
		srv.ServiceAccountToken = k8sAuthServiceAccountBearerToken
	case "bearer-token":
		flags.FatalIfFailed(flags.ValidateFlagNotEmpty("k8s-auth-bearer-token", fK8sAuthBearerToken))

		srv.StaticUser = &auth.User{
			Token: fK8sAuthBearerToken,
		}
		srv.ServiceAccountToken = fK8sAuthBearerToken
	case "oidc", "openshift":
		flags.FatalIfFailed(flags.ValidateFlagIs("user-auth", authOptions.AuthType, "oidc", "openshift"))
		srv.ServiceAccountToken = k8sAuthServiceAccountBearerToken
	default:
		flags.FatalIfFailed(flags.NewInvalidFlagError("k8s-mode", "must be one of: service-account, bearer-token, oidc, openshift"))
	}

	monitoringDashboardHttpClientTransport := &http.Transport{
		TLSClientConfig: srv.K8sProxyConfig.TLSClientConfig,
	}
	if fK8sMode == "off-cluster" {
		monitoringDashboardHttpClientTransport.Proxy = http.ProxyFromEnvironment
	}
	srv.MonitoringDashboardConfigMapLister = server.NewResourceLister(
		srv.ServiceAccountToken,
		&url.URL{
			Scheme: k8sEndpoint.Scheme,
			Host:   k8sEndpoint.Host,
			Path:   k8sEndpoint.Path + "/api/v1/namespaces/openshift-config-managed/configmaps",
			RawQuery: url.Values{
				"labelSelector": {"console.openshift.io/dashboard=true"},
			}.Encode(),
		},
		&http.Client{
			Transport: monitoringDashboardHttpClientTransport,
		},
		nil,
	)

	srv.KnativeEventSourceCRDLister = server.NewResourceLister(
		srv.ServiceAccountToken,
		&url.URL{
			Scheme: k8sEndpoint.Scheme,
			Host:   k8sEndpoint.Host,
			Path:   k8sEndpoint.Path + "/apis/apiextensions.k8s.io/v1/customresourcedefinitions",
			RawQuery: url.Values{
				"labelSelector": {"duck.knative.dev/source=true"},
			}.Encode(),
		},
		&http.Client{
			Transport: &http.Transport{
				TLSClientConfig: srv.K8sProxyConfig.TLSClientConfig,
			},
		},
		knative.EventSourceFilter,
	)

	srv.KnativeChannelCRDLister = server.NewResourceLister(
		srv.ServiceAccountToken,
		&url.URL{
			Scheme: k8sEndpoint.Scheme,
			Host:   k8sEndpoint.Host,
			Path:   k8sEndpoint.Path + "/apis/apiextensions.k8s.io/v1/customresourcedefinitions",
			RawQuery: url.Values{
				"labelSelector": {"duck.knative.dev/addressable=true,messaging.knative.dev/subscribable=true"},
			}.Encode(),
		},
		&http.Client{
			Transport: &http.Transport{
				TLSClientConfig: srv.K8sProxyConfig.TLSClientConfig,
			},
		},
		knative.ChannelFilter,
	)

	caCertFilePath := fCAFile
	if fK8sMode == "in-cluster" {
		caCertFilePath = k8sInClusterCA
	}

	if err := completedAuthnOptions.ApplyTo(srv, k8sEndpoint, apiServerEndpoint, caCertFilePath); err != nil {
		klog.Fatalf("failed to apply configuration to server: %v", err)
		os.Exit(1)
	}

	listenURL, err := flags.ValidateFlagIsURL("listen", fListen, false)
	flags.FatalIfFailed(err)

	switch listenURL.Scheme {
	case "http":
	case "https":
		flags.FatalIfFailed(flags.ValidateFlagNotEmpty("tls-cert-file", fTlSCertFile))
		flags.FatalIfFailed(flags.ValidateFlagNotEmpty("tls-key-file", fTlSKeyFile))
	default:
		flags.FatalIfFailed(flags.NewInvalidFlagError("listen", "scheme must be one of: http, https"))
	}

	httpsrv := &http.Server{
		Addr:    listenURL.Host,
		Handler: srv.HTTPHandler(),
		// Disable HTTP/2, which breaks WebSockets.
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		TLSConfig:    oscrypto.SecureTLSConfig(&tls.Config{}),
	}

	if fRedirectPort != 0 {
		go func() {
			// Listen on passed port number to be redirected to the console
			redirectServer := http.NewServeMux()
			redirectServer.HandleFunc("/", func(res http.ResponseWriter, req *http.Request) {
				redirectURL := &url.URL{
					Scheme:   srv.BaseURL.Scheme,
					Host:     srv.BaseURL.Host,
					RawQuery: req.URL.RawQuery,
					Path:     req.URL.Path,
				}
				http.Redirect(res, req, redirectURL.String(), http.StatusMovedPermanently)
			})
			redirectPort := fmt.Sprintf(":%d", fRedirectPort)
			klog.Infof("Listening on %q for custom hostname redirect...", redirectPort)
			klog.Fatal(http.ListenAndServe(redirectPort, redirectServer))
		}()
	}

	klog.Infof("Binding to %s...", httpsrv.Addr)
	if listenURL.Scheme == "https" {
		klog.Info("using TLS")
		klog.Fatal(httpsrv.ListenAndServeTLS(fTlSCertFile, fTlSKeyFile))
	} else {
		klog.Info("not using TLS")
		klog.Fatal(httpsrv.ListenAndServe())
	}
}
