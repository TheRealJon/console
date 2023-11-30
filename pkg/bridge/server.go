package bridge

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/openshift/console/pkg/flags"
	"github.com/openshift/console/pkg/handler"
	"github.com/openshift/library-go/pkg/crypto"
	"k8s.io/klog"
)

func (b *Bridge) buildServer() {
	b.Handler = &handler.Handler{
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
	b.Server = &http.Server{
		Addr:    b.Listen.Host,
		Handler: b.Handler.HTTPHandler(),
		// Disable HTTP/2, which breaks WebSockets.
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		TLSConfig:    crypto.SecureTLSConfig(&tls.Config{}),
	}
}

func (b *Bridge) ListenAndServe() {
	if b.RedirectPort != 0 {
		go func() {
			// Listen on passed port number to be redirected to the console
			redirectServer := http.NewServeMux()
			redirectServer.HandleFunc("/", func(res http.ResponseWriter, req *http.Request) {
				redirectURL := &flags.URL{
					Scheme:   b.Handler.BaseURL.Scheme,
					Host:     b.Handler.BaseURL.Host,
					RawQuery: req.URL.RawQuery,
					Path:     req.URL.Path,
				}
				http.Redirect(res, req, redirectURL.String(), http.StatusMovedPermanently)
			})
			redirectPort := fmt.Sprintf(":%d", b.RedirectPort)
			klog.Infof("Listening on %q for custom hostname redirect...", redirectPort)
			klog.Fatal(http.ListenAndServe(redirectPort, redirectServer))
		}()
	}

	klog.Infof("Binding to %s...", b.Server.Addr)
	if b.Listen.Scheme == "https" {
		klog.Info("using TLS")
		klog.Fatal(b.Server.ListenAndServeTLS(b.TlsCertFile.String(), b.TlsKeyFile.String()))
	} else {
		klog.Info("not using TLS")
		klog.Fatal(b.Server.ListenAndServe())
	}
}
