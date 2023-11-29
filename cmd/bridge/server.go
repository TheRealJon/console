package main

import (
	authopts "github.com/openshift/console/cmd/bridge/config/auth"
	"github.com/openshift/console/pkg/server"
)

func initServer(authOptions *authopts.AuthOptions) *server.Server {
	srv := &server.Server{
		AddPage:                      addPage,
		AlertManagerPublicURL:        alermanagerPublicURL.Get(),
		AlertManagerTenancyHost:      alertmanagerTenancyHost,
		AlertManagerUserWorkloadHost: alertmanagerUserWorkloadHost,
		Branding:                     branding.String(),
		ControlPlaneTopology:         controlPlaneTopology.String(),
		CopiedCSVsDisabled:           copiedCSVsDisabled,
		CustomLogoFile:               customLogoFile.String(),
		CustomProductName:            customProductName,
		DevCatalogCategories:         devCatalogCategories,
		DevCatalogTypes:              devCatalogTypes,
		DocumentationBaseURL:         documentationBaseURL.Get(),
		EnabledConsolePlugins:        consolePluginsFlags,
		GrafanaPublicURL:             grafanaPublicURL.Get(),
		I18nNamespaces:               []string(i18nNamespaces),
		K8sMode:                      k8sMode.String(),
		LoadTestFactor:               loadTestFactor,
		NodeArchitectures:            []string(nodeArchitectures),
		NodeOperatingSystems:         []string(nodeOperatingSystems),
		Perspectives:                 perspectives,
		PluginProxy:                  pluginProxy,
		ProjectAccessClusterRoles:    projectAccessClusterRoles,
		PrometheusPublicURL:          prometheusPublicURL.Get(),
		PublicDir:                    publicDir.String(),
		QuickStarts:                  quickStarts,
		ReleaseVersion:               releaseVersion,
		StatuspageID:                 statuspageID,
		Telemetry:                    telemetryFlags,
		ThanosPublicURL:              thanosPublicURL.Get(),
		UserSettingsLocation:         userSettingsLocation.String(),
	}
	applyBaseURL(srv)
	applyArchAndOS(srv)
	applyProxyConfigs(srv)
	applyBearerToken(srv, authOptions)
	applyListers(srv)
	applyAuth(srv, authOptions)
	return srv
}
