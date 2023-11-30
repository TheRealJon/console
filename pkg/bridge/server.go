package bridge

import (
	"github.com/openshift/console/pkg/server"
)

func (b *Bridge) buildServer() {
	b.Server = &server.Server{
		AddPage:                      b.AddPage.String(),
		AlertManagerPublicURL:        b.AlermanagerPublicURL.Get(),
		AlertManagerTenancyHost:      b.AlertmanagerTenancyHost,
		AlertManagerUserWorkloadHost: b.AlertmanagerUserWorkloadHost,
		Branding:                     b.Branding.String(),
		ControlPlaneTopology:         b.ControlPlaneTopology.String(),
		CopiedCSVsDisabled:           b.CopiedCSVsDisabled,
		CustomLogoFile:               b.CustomLogoFile.String(),
		CustomProductName:            b.CustomProductName,
		DevCatalogCategories:         b.DevCatalogCategories.String(),
		DevCatalogTypes:              b.DevCatalogTypes,
		DocumentationBaseURL:         b.DocumentationBaseURL.Get(),
		EnabledConsolePlugins:        b.ConsolePluginsFlags,
		GrafanaPublicURL:             b.GrafanaPublicURL.Get(),
		I18nNamespaces:               []string(b.I18nNamespaces),
		K8sMode:                      b.K8sMode.String(),
		LoadTestFactor:               b.LoadTestFactor,
		NodeArchitectures:            []string(b.NodeArchitectures),
		NodeOperatingSystems:         []string(b.NodeOperatingSystems),
		Perspectives:                 b.Perspectives,
		PluginProxy:                  b.PluginProxy,
		ProjectAccessClusterRoles:    b.ProjectAccessClusterRoles,
		PrometheusPublicURL:          b.PrometheusPublicURL.Get(),
		PublicDir:                    b.PublicDir.String(),
		QuickStarts:                  b.QuickStarts,
		ReleaseVersion:               b.ReleaseVersion,
		StatuspageID:                 b.StatuspageID,
		Telemetry:                    b.TelemetryFlags,
		ThanosPublicURL:              b.ThanosPublicURL.Get(),
		UserSettingsLocation:         b.UserSettingsLocation.String(),
	}
	b.applyBaseURL()
	b.applyArchAndOS()
	b.applyProxyConfigs()
	b.applyBearerToken()
	b.applyListers()
	b.applyAuth()
}
