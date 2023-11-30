package main

import (
	"flag"

	"github.com/openshift/console/pkg/flags"
)

const (
	defaultBasePath                       = "/"
	defaultBranding                       = "okd"
	defaultCopyCSVsDisabled               = false
	defaultK8sAuth                        = "service-account"
	defaultK8sMode                        = "in-cluster"
	defaultK8sModeOffClusterSkipVerifyTLS = false
	defaultListen                         = "http://0.0.0.0:9000"
	defaultLoadTestFactor                 = 0
	defaultPublicDir                      = "./frontend/public/dist"
	defaultRedirectPort                   = 0
	defaultUserSettingsLocation           = "configmap"
)

var (
	// Bool flags
	copiedCSVsDisabled             bool
	k8sModeOffClusterSkipVerifyTLS bool

	// Int flags
	loadTestFactor int
	redirectPort   int

	// String flags
	alertmanagerTenancyHost      string
	alertmanagerUserWorkloadHost string
	customProductName            string
	devCatalogCategories         string
	devCatalogTypes              string
	k8sAuthBearerToken           string
	perspectives                 string
	pluginProxy                  string
	projectAccessClusterRoles    string
	quickStarts                  string
	releaseVersion               string
	statuspageID                 string

	// JSON flags
	addPage flags.AddPage

	// File flags
	caFile         flags.File
	customLogoFile flags.File
	publicDir      flags.File
	serviceCAFile  flags.File
	tlsCertFile    flags.File
	tlsKeyFile     flags.File

	// Unique string flags
	basePath             flags.BasePath
	branding             flags.Brand
	controlPlaneTopology flags.ControlPlaneTopology
	k8sAuth              flags.K8sAuth
	k8sMode              flags.K8sMode
	userSettingsLocation flags.UserSettingsLocation

	// URL flags
	alermanagerPublicURL          flags.URL
	baseAddress                   flags.URL
	documentationBaseURL          flags.URLWithTrailingSlash
	grafanaPublicURL              flags.URL
	k8sModeOffClusterAlertmanager flags.URL
	k8sModeOffClusterEndpoint     flags.URL
	k8sModeOffClusterGitOps       flags.URL
	k8sModeOffClusterThanos       flags.URL
	k8sPublicEndpoint             flags.URL
	listen                        flags.URL
	prometheusPublicURL           flags.URL
	thanosPublicURL               flags.URL

	// Slice flags
	i18nNamespaces       flags.Slice
	nodeArchitectures    flags.Slice
	nodeOperatingSystems flags.Slice

	// Map flags
	consolePluginsFlags flags.Map
	telemetryFlags      flags.Map
)

func InitFlags() *flag.FlagSet {
	fs := flag.NewFlagSet("bridge", flag.ExitOnError)
	// Bool flags
	fs.BoolVar(&copiedCSVsDisabled, "copied-csvs-disabled", defaultCopyCSVsDisabled, "Flag to indicate if OLM copied CSVs are disabled.")
	fs.BoolVar(&k8sModeOffClusterSkipVerifyTLS, "k8s-mode-off-cluster-skip-verify-tls", defaultK8sModeOffClusterSkipVerifyTLS, "DEV ONLY. When true, skip verification of certs presented by k8s API server.")

	// Int flags
	fs.IntVar(&loadTestFactor, "load-test-factor", defaultLoadTestFactor, "DEV ONLY. The factor used to multiply k8s API list responses for load testing purposes.")
	fs.IntVar(&redirectPort, "redirect-port", defaultRedirectPort, "Port number under which the console should listen for custom hostname redirect.")

	// String flags
	fs.String("config", "", "The YAML config file.")
	fs.StringVar(&alertmanagerTenancyHost, "alermanager-tenancy-host", openshiftAlertManagerTenancyHost, "Location of the tenant-aware Alertmanager service.")
	fs.StringVar(&alertmanagerUserWorkloadHost, "alermanager-user-workload-host", openshiftAlertManagerHost, "Location of the Alertmanager service for user-defined alerts.")
	fs.StringVar(&customProductName, "custom-product-name", "", "Custom product name for console branding.")
	fs.StringVar(&devCatalogCategories, "developer-catalog-categories", "", "Allow catalog categories customization. (JSON as string)")
	fs.StringVar(&devCatalogTypes, "developer-catalog-types", "", "Allow enabling/disabling of sub-catalog types from the developer catalog. (JSON as string)")
	fs.StringVar(&k8sAuthBearerToken, "k8s-auth-bearer-token", "", "Authorization token to send with proxied Kubernetes API requests.")
	fs.StringVar(&perspectives, "perspectives", "", "Allow enabling/disabling of perspectives in the console. (JSON as string)")
	fs.StringVar(&pluginProxy, "plugin-proxy", "", "Defines various service types to which will console proxy plugins requests. (JSON as string)")
	fs.StringVar(&projectAccessClusterRoles, "project-access-cluster-roles", "", "The list of Cluster Roles assignable for the project access page. (JSON as string)")
	fs.StringVar(&quickStarts, "quick-starts", "", "Allow customization of available ConsoleQuickStart resources in console. (JSON as string)")
	fs.StringVar(&releaseVersion, "release-version", "", "Defines the release version of the cluster")
	fs.StringVar(&statuspageID, "statuspage-id", "", "Unique ID assigned by statuspage.io page that provides status info.")

	// JSON Flags
	fs.Var(&addPage, "add-page", "DEV ONLY. Allow add page customization. (JSON as string)")

	// File flags
	fs.Var(&caFile, "ca-file", "PEM File containing trusted certificates of trusted CAs. If not present, the system's Root CAs will be used.")
	fs.Var(&customLogoFile, "custom-logo-file", "Custom product image for console branding.")
	fs.Var(&publicDir, "public-dir", "directory containing static web assets.")
	fs.Var(&serviceCAFile, "service-ca-file", "CA bundle for OpenShift services signed with the service signing certificates.") // See https://github.com/openshift/service-serving-cert-signer
	fs.Var(&tlsCertFile, "tls-cert-file", "TLS certificate. If the certificate is signed by a certificate authority, the certFile should be the concatenation of the server's certificate followed by the CA's certificate.")
	fs.Var(&tlsKeyFile, "tls-key-file", "The TLS certificate key.")

	// Unique string flags
	fs.Var(&basePath, "base-path", "")
	fs.Var(&branding, "branding", "Console branding for the masthead logo and title. One of okd, openshift, ocp, online, dedicated, azure, or rosa. Defaults to okd.")
	fs.Var(&controlPlaneTopology, "control-plane-topology-mode", "Defines the topology mode of the control/infra nodes (External | HighlyAvailable | SingleReplica)")
	fs.Var(&k8sAuth, "k8s-auth", "service-account | bearer-token | oidc | openshift")
	fs.Var(&k8sMode, "k8s-mode", "in-cluster | off-cluster")
	fs.Var(&userSettingsLocation, "user-settings-location", "DEV ONLY. Define where the user settings should be stored. (configmap | localstorage).")

	// URL flags
	fs.Var(&alermanagerPublicURL, "alermanager-public-url", "Public URL of the cluster's AlertManager server.")
	fs.Var(&baseAddress, "base-address", "Format: <http | https>://domainOrIPAddress[:port]. Example: https://openshift.example.com.")
	fs.Var(&documentationBaseURL, "documentation-base-url", "The base URL for documentation links.")
	fs.Var(&grafanaPublicURL, "grafana-public-url", "Public URL of the cluster's Grafana server.")
	fs.Var(&k8sModeOffClusterAlertmanager, "k8s-mode-off-cluster-alertmanager", "DEV ONLY. URL of the cluster's AlertManager server.")
	fs.Var(&k8sModeOffClusterEndpoint, "k8s-mode-off-cluster-endpoint", "URL of the Kubernetes API server.")
	fs.Var(&k8sModeOffClusterGitOps, "k8s-mode-off-cluster-gitops", "DEV ONLY. URL of the GitOps backend service")
	fs.Var(&k8sModeOffClusterThanos, "k8s-mode-off-cluster-thanos", "DEV ONLY. URL of the cluster's Thanos server.")
	fs.Var(&k8sPublicEndpoint, "k8s-public-endpoint", "Endpoint to use to communicate to the API server.")
	fs.Var(&listen, "listen", "")
	fs.Var(&prometheusPublicURL, "prometheus-public-url", "Public URL of the cluster's Prometheus server.")
	fs.Var(&thanosPublicURL, "thanos-public-url", "Public URL of the cluster's Thanos server.")

	// Slice flags
	fs.Var(&i18nNamespaces, "i18n-namespaces", "List of namespaces separated by comma. Example --i18n-namespaces=plugin__acm,plugin__kubevirt")
	fs.Var(&nodeArchitectures, "node-architectures", "List of node architectures. Example --node-architecture=amd64,arm64")
	fs.Var(&nodeOperatingSystems, "node-operating-systems", "List of node operating systems. Example --node-operating-system=linux,windows")

	// Map flags
	fs.Var(&consolePluginsFlags, "plugins", "List of plugin entries that are enabled for the console. Each entry consist of plugin-name as a key and plugin-endpoint as a value.")
	fs.Var(&telemetryFlags, "telemetry", "Telemetry configuration that can be used by console plugins. Each entry should be a key=value pair.")

	// Deprecated flags
	fs.String("kubectl-client-id", "", "DEPRECATED: setting this does not do anything.")
	fs.String("kubectl-client-secret", "", "DEPRECATED: setting this does not do anything.")
	fs.String("kubectl-client-secret-file", "", "DEPRECATED: setting this does not do anything.")
	fs.String("log-level", "", "DEPRECATED: --log-level is now deprecated, use verbosity flag --v=Level instead")

	// Set default values using set functions so that validation is always performed
	basePath.Set(defaultBasePath)
	branding.Set(defaultBranding)
	listen.Set(defaultListen)
	k8sAuth.Set(defaultK8sAuth)
	k8sMode.Set(defaultK8sMode)
	userSettingsLocation.Set(defaultUserSettingsLocation)
	publicDir.Set(defaultPublicDir)
	return fs
}
