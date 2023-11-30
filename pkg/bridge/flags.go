package bridge

import (
	"flag"
)

func (b *Bridge) addFlags(fs *flag.FlagSet) {
	// Bool flags
	fs.BoolVar(&b.CopiedCSVsDisabled, "copied-csvs-disabled", defaultCopyCSVsDisabled, "Flag to indicate if OLM copied CSVs are disabled.")
	fs.BoolVar(&b.K8sModeOffClusterSkipVerifyTLS, "k8s-mode-off-cluster-skip-verify-tls", defaultK8sModeOffClusterSkipVerifyTLS, "DEV ONLY. When true, skip verification of certs presented by k8s API server.")

	// Int flags
	fs.IntVar(&b.LoadTestFactor, "load-test-factor", defaultLoadTestFactor, "DEV ONLY. The factor used to multiply k8s API list responses for load testing purposes.")
	fs.IntVar(&b.RedirectPort, "redirect-port", defaultRedirectPort, "Port number under which the console should listen for custom hostname redirect.")

	// String flags
	fs.String("config", "", "The YAML config file.")
	fs.StringVar(&b.AlertmanagerTenancyHost, "alermanager-tenancy-host", openshiftAlertManagerTenancyHost, "Location of the tenant-aware Alertmanager service.")
	fs.StringVar(&b.AlertmanagerUserWorkloadHost, "alermanager-user-workload-host", openshiftAlertManagerHost, "Location of the Alertmanager service for user-defined alerts.")
	fs.StringVar(&b.CustomProductName, "custom-product-name", "", "Custom product name for console branding.")
	fs.StringVar(&b.K8sAuthBearerToken, "k8s-auth-bearer-token", "", "Authorization token to send with proxied Kubernetes API requests.")
	fs.StringVar(&b.ReleaseVersion, "release-version", "", "Defines the release version of the cluster")
	fs.StringVar(&b.StatuspageID, "statuspage-id", "", "Unique ID assigned by statuspage.io page that provides status info.")

	// JSON Flags
	fs.Var(&b.AddPage, "add-page", "DEV ONLY. Allow add page customization. (JSON as string)")
	fs.Var(&b.DevCatalogCategories, "developer-catalog-categories", "Allow catalog categories customization. (JSON as string)")

	// TODO Create custom flag values for these JSON flags
	fs.StringVar(&b.DevCatalogTypes, "developer-catalog-types", "", "Allow enabling/disabling of sub-catalog types from the developer catalog. (JSON as string)")
	fs.StringVar(&b.Perspectives, "perspectives", "", "Allow enabling/disabling of perspectives in the console. (JSON as string)")
	fs.StringVar(&b.PluginProxy, "plugin-proxy", "", "Defines various service types to which will console proxy plugins requests. (JSON as string)")
	fs.StringVar(&b.ProjectAccessClusterRoles, "project-access-cluster-roles", "", "The list of Cluster Roles assignable for the project access page. (JSON as string)")
	fs.StringVar(&b.QuickStarts, "quick-starts", "", "Allow customization of available ConsoleQuickStart resources in console. (JSON as string)")

	// File flags
	fs.Var(&b.CaFile, "ca-file", "PEM File containing trusted certificates of trusted CAs. If not present, the system's Root CAs will be used.")
	fs.Var(&b.CustomLogoFile, "custom-logo-file", "Custom product image for console branding.")
	fs.Var(&b.PublicDir, "public-dir", "directory containing static web assets.")
	fs.Var(&b.ServiceCAFile, "service-ca-file", "CA bundle for OpenShift services signed with the service signing certificates.") // See https://github.com/openshift/service-serving-cert-signer
	fs.Var(&b.TlsCertFile, "tls-cert-file", "TLS certificate. If the certificate is signed by a certificate authority, the certFile should be the concatenation of the server's certificate followed by the CA's certificate.")
	fs.Var(&b.TlsKeyFile, "tls-key-file", "The TLS certificate key.")

	// Unique string flags
	fs.Var(&b.BasePath, "base-path", "")
	fs.Var(&b.Branding, "branding", "Console branding for the masthead logo and title. One of okd, openshift, ocp, online, dedicated, azure, or rosa. Defaults to okd.")
	fs.Var(&b.ControlPlaneTopology, "control-plane-topology-mode", "Defines the topology mode of the control/infra nodes (External | HighlyAvailable | SingleReplica)")
	fs.Var(&b.K8sAuth, "k8s-auth", "service-account | bearer-token | oidc | openshift")
	fs.Var(&b.K8sMode, "k8s-mode", "in-cluster | off-cluster")
	fs.Var(&b.UserSettingsLocation, "user-settings-location", "DEV ONLY. Define where the user settings should be stored. (configmap | localstorage).")

	// URL flags
	fs.Var(&b.AlermanagerPublicURL, "alermanager-public-url", "Public URL of the cluster's AlertManager server.")
	fs.Var(&b.BaseAddress, "base-address", "Format: <http | https>://domainOrIPAddress[:port]. Example: https://openshift.example.com.")
	fs.Var(&b.DocumentationBaseURL, "documentation-base-url", "The base URL for documentation links.")
	fs.Var(&b.GrafanaPublicURL, "grafana-public-url", "Public URL of the cluster's Grafana server.")
	fs.Var(&b.K8sModeOffClusterAlertmanager, "k8s-mode-off-cluster-alertmanager", "DEV ONLY. URL of the cluster's AlertManager server.")
	fs.Var(&b.K8sModeOffClusterEndpoint, "k8s-mode-off-cluster-endpoint", "URL of the Kubernetes API server.")
	fs.Var(&b.K8sModeOffClusterGitOps, "k8s-mode-off-cluster-gitops", "DEV ONLY. URL of the GitOps backend service")
	fs.Var(&b.K8sModeOffClusterThanos, "k8s-mode-off-cluster-thanos", "DEV ONLY. URL of the cluster's Thanos server.")
	fs.Var(&b.K8sPublicEndpoint, "k8s-public-endpoint", "Endpoint to use to communicate to the API server.")
	fs.Var(&b.Listen, "listen", "")
	fs.Var(&b.PrometheusPublicURL, "prometheus-public-url", "Public URL of the cluster's Prometheus server.")
	fs.Var(&b.ThanosPublicURL, "thanos-public-url", "Public URL of the cluster's Thanos server.")

	// Slice flags
	fs.Var(&b.I18nNamespaces, "i18n-namespaces", "List of namespaces separated by comma. Example --i18n-namespaces=plugin__acm,plugin__kubevirt")
	fs.Var(&b.NodeArchitectures, "node-architectures", "List of node architectures. Example --node-architecture=amd64,arm64")
	fs.Var(&b.NodeOperatingSystems, "node-operating-systems", "List of node operating systems. Example --node-operating-system=linux,windows")

	// Map flags
	fs.Var(&b.ConsolePluginsFlags, "plugins", "List of plugin entries that are enabled for the console. Each entry consist of plugin-name as a key and plugin-endpoint as a value.")
	fs.Var(&b.TelemetryFlags, "telemetry", "Telemetry configuration that can be used by console plugins. Each entry should be a key=value pair.")

	// Deprecated flags
	fs.String("kubectl-client-id", "", "DEPRECATED: setting this does not do anything.")
	fs.String("kubectl-client-secret", "", "DEPRECATED: setting this does not do anything.")
	fs.String("kubectl-client-secret-file", "", "DEPRECATED: setting this does not do anything.")
	fs.String("log-level", "", "DEPRECATED: --log-level is now deprecated, use verbosity flag --v=Level instead")

	// Set default values using set functions so that validation is always performed
	b.BasePath.Set(defaultBasePath)
	b.Branding.Set(defaultBranding)
	b.Listen.Set(defaultListen)
	b.K8sAuth.Set(defaultK8sAuth)
	b.K8sMode.Set(defaultK8sMode)
	b.PublicDir.Set(defaultPublicDir)
	b.UserSettingsLocation.Set(defaultUserSettingsLocation)
}
