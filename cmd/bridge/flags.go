package main

import (
	"flag"

	"github.com/openshift/console/pkg/flags"
)

var (
	fK8sModeOffClusterSkipVerifyTLS bool
	fCopiedCSVsDisabled             bool

	fRedirectPort   int
	fLoadTestFactor int

	fAddPage                       string
	fAlermanagerPublicURL          string
	fAlertmanagerTenancyHost       string
	fAlertmanagerUserWorkloadHost  string
	fBaseAddress                   string
	fBasePath                      string
	fBranding                      string
	fCAFile                        string
	fControlPlaneTopology          string
	fCustomLogoFile                string
	fCustomProductName             string
	fDevCatalogCategories          string
	fDevCatalogTypes               string
	fDocumentationBaseURL          string
	fGrafanaPublicURL              string
	fK8sAuth                       string
	fK8sAuthBearerToken            string
	fK8sMode                       string
	fK8sModeOffClusterAlertmanager string
	fK8sModeOffClusterEndpoint     string
	fK8sModeOffClusterGitOps       string
	fK8sModeOffClusterThanos       string
	fK8sPublicEndpoint             string
	fListen                        string
	fLogLevel                      string
	fPerspectives                  string
	fPluginProxy                   string
	fProjectAccessClusterRoles     string
	fPrometheusPublicURL           string
	fPublicDir                     string
	fQuickStarts                   string
	fReleaseVersion                string
	fServiceCAFile                 string
	fStatuspageID                  string
	fThanosPublicURL               string
	fTlSCertFile                   string
	fTlSKeyFile                    string
	fUserSettingsLocation          string

	fI18nNamespaces       = flags.SliceFlag{}
	fNodeArchitectures    = flags.SliceFlag{}
	fNodeOperatingSystems = flags.SliceFlag{}

	consolePluginsFlags = flags.MapFlag{}
	telemetryFlags      = flags.MapFlag{}
)

func initFlags(fs *flag.FlagSet) {
	// Bool flags
	fs.BoolVar(&fCopiedCSVsDisabled, "copied-csvs-disabled", false, "Flag to indicate if OLM copied CSVs are disabled.")
	fs.BoolVar(&fK8sModeOffClusterSkipVerifyTLS, "k8s-mode-off-cluster-skip-verify-tls", false, "DEV ONLY. When true, skip verification of certs presented by k8s API server.")

	// Int flags
	fs.IntVar(&fLoadTestFactor, "load-test-factor", 0, "DEV ONLY. The factor used to multiply k8s API list responses for load testing purposes.")
	fs.IntVar(&fRedirectPort, "redirect-port", 0, "Port number under which the console should listen for custom hostname redirect.")

	// String flags
	fs.String("config", "", "The YAML config file.")
	fs.StringVar(&fAddPage, "add-page", "", "DEV ONLY. Allow add page customization. (JSON as string)")
	fs.StringVar(&fAlermanagerPublicURL, "alermanager-public-url", "", "Public URL of the cluster's AlertManager server.")
	fs.StringVar(&fAlertmanagerTenancyHost, "alermanager-tenancy-host", openshiftAlertManagerTenancyHost, "Location of the tenant-aware Alertmanager service.")
	fs.StringVar(&fAlertmanagerUserWorkloadHost, "alermanager-user-workload-host", openshiftAlertManagerHost, "Location of the Alertmanager service for user-defined alerts.")
	fs.StringVar(&fBaseAddress, "base-address", "", "Format: <http | https>://domainOrIPAddress[:port]. Example: https://openshift.example.com.")
	fs.StringVar(&fBasePath, "base-path", "/", "")
	fs.StringVar(&fBranding, "branding", "okd", "Console branding for the masthead logo and title. One of okd, openshift, ocp, online, dedicated, azure, or rosa. Defaults to okd.")
	fs.StringVar(&fCAFile, "ca-file", "", "PEM File containing trusted certificates of trusted CAs. If not present, the system's Root CAs will be used.")
	fs.StringVar(&fControlPlaneTopology, "control-plane-topology-mode", "", "Defines the topology mode of the control/infra nodes (External | HighlyAvailable | SingleReplica)")
	fs.StringVar(&fCustomLogoFile, "custom-logo-file", "", "Custom product image for console branding.")
	fs.StringVar(&fCustomProductName, "custom-product-name", "", "Custom product name for console branding.")
	fs.StringVar(&fDevCatalogCategories, "developer-catalog-categories", "", "Allow catalog categories customization. (JSON as string)")
	fs.StringVar(&fDevCatalogTypes, "developer-catalog-types", "", "Allow enabling/disabling of sub-catalog types from the developer catalog. (JSON as string)")
	fs.StringVar(&fDocumentationBaseURL, "documentation-base-url", "", "The base URL for documentation links.")
	fs.StringVar(&fGrafanaPublicURL, "grafana-public-url", "", "Public URL of the cluster's Grafana server.")
	fs.StringVar(&fK8sAuth, "k8s-auth", "service-account", "service-account | bearer-token | oidc | openshift")
	fs.StringVar(&fK8sAuthBearerToken, "k8s-auth-bearer-token", "", "Authorization token to send with proxied Kubernetes API requests.")
	fs.StringVar(&fK8sMode, "k8s-mode", "in-cluster", "in-cluster | off-cluster")
	fs.StringVar(&fK8sModeOffClusterAlertmanager, "k8s-mode-off-cluster-alertmanager", "", "DEV ONLY. URL of the cluster's AlertManager server.")
	fs.StringVar(&fK8sModeOffClusterEndpoint, "k8s-mode-off-cluster-endpoint", "", "URL of the Kubernetes API server.")
	fs.StringVar(&fK8sModeOffClusterGitOps, "k8s-mode-off-cluster-gitops", "", "DEV ONLY. URL of the GitOps backend service")
	fs.StringVar(&fK8sModeOffClusterThanos, "k8s-mode-off-cluster-thanos", "", "DEV ONLY. URL of the cluster's Thanos server.")
	fs.StringVar(&fK8sPublicEndpoint, "k8s-public-endpoint", "", "Endpoint to use to communicate to the API server.")
	fs.StringVar(&fListen, "listen", "http://0.0.0.0:9000", "")
	fs.StringVar(&fLogLevel, "log-level", "", "level of logging information by package (pkg=level).")
	fs.StringVar(&fPerspectives, "perspectives", "", "Allow enabling/disabling of perspectives in the console. (JSON as string)")
	fs.StringVar(&fPluginProxy, "plugin-proxy", "", "Defines various service types to which will console proxy plugins requests. (JSON as string)")
	fs.StringVar(&fProjectAccessClusterRoles, "project-access-cluster-roles", "", "The list of Cluster Roles assignable for the project access page. (JSON as string)")
	fs.StringVar(&fPrometheusPublicURL, "prometheus-public-url", "", "Public URL of the cluster's Prometheus server.")
	fs.StringVar(&fPublicDir, "public-dir", "./frontend/public/dist", "directory containing static web assets.")
	fs.StringVar(&fQuickStarts, "quick-starts", "", "Allow customization of available ConsoleQuickStart resources in console. (JSON as string)")
	fs.StringVar(&fReleaseVersion, "release-version", "", "Defines the release version of the cluster")
	fs.StringVar(&fServiceCAFile, "service-ca-file", "", "CA bundle for OpenShift services signed with the service signing certificates.") // See https://github.com/openshift/service-serving-cert-signer
	fs.StringVar(&fStatuspageID, "statuspage-id", "", "Unique ID assigned by statuspage.io page that provides status info.")
	fs.StringVar(&fThanosPublicURL, "thanos-public-url", "", "Public URL of the cluster's Thanos server.")
	fs.StringVar(&fTlSCertFile, "tls-cert-file", "", "TLS certificate. If the certificate is signed by a certificate authority, the certFile should be the concatenation of the server's certificate followed by the CA's certificate.")
	fs.StringVar(&fTlSKeyFile, "tls-key-file", "", "The TLS certificate key.")
	fs.StringVar(&fUserSettingsLocation, "user-settings-location", "configmap", "DEV ONLY. Define where the user settings should be stored. (configmap | localstorage).")

	// Slice flags
	fs.Var(&fI18nNamespaces, "i18n-namespaces", "List of namespaces separated by comma. Example --i18n-namespaces=plugin__acm,plugin__kubevirt")
	fs.Var(&fNodeArchitectures, "node-architectures", "List of node architectures. Example --node-architecture=amd64,arm64")
	fs.Var(&fNodeOperatingSystems, "node-operating-systems", "List of node operating systems. Example --node-operating-system=linux,windows")

	// Map flags
	fs.Var(&consolePluginsFlags, "plugins", "List of plugin entries that are enabled for the console. Each entry consist of plugin-name as a key and plugin-endpoint as a value.")
	fs.Var(&telemetryFlags, "telemetry", "Telemetry configuration that can be used by console plugins. Each entry should be a key=value pair.")

	// Deprecated flags
	fs.String("kubectl-client-id", "", "DEPRECATED: setting this does not do anything.")
	fs.String("kubectl-client-secret", "", "DEPRECATED: setting this does not do anything.")
	fs.String("kubectl-client-secret-file", "", "DEPRECATED: setting this does not do anything.")
}
