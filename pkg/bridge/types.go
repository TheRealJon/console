package bridge

import (
	"net/http"

	"github.com/openshift/console/pkg/flags"
	"github.com/openshift/console/pkg/handler"
)

type Bridge struct {
	// Bool flags
	CopiedCSVsDisabled             bool
	K8sModeOffClusterSkipVerifyTLS bool

	// Int flags
	LoadTestFactor int
	RedirectPort   int

	// String flags
	AlertmanagerTenancyHost      string
	AlertmanagerUserWorkloadHost string
	CustomProductName            string
	DevCatalogTypes              string
	K8sAuthBearerToken           string
	Perspectives                 string
	PluginProxy                  string
	ProjectAccessClusterRoles    string
	QuickStarts                  string
	ReleaseVersion               string
	StatuspageID                 string

	// JSON flags
	AddPage              flags.AddPage
	DevCatalogCategories flags.DeveloperCatalogCategories

	// File flags
	CaFile         flags.File
	CustomLogoFile flags.File
	PublicDir      flags.File
	ServiceCAFile  flags.File
	TlsCertFile    flags.File
	TlsKeyFile     flags.File

	// Unique string flags
	BasePath             flags.BasePath
	Branding             flags.Brand
	ControlPlaneTopology flags.ControlPlaneTopology
	K8sAuth              flags.K8sAuth
	K8sMode              flags.K8sMode
	UserSettingsLocation flags.UserSettingsLocation

	// URL flags
	AlermanagerPublicURL          flags.URL
	BaseAddress                   flags.URL
	DocumentationBaseURL          flags.URLWithTrailingSlash
	GrafanaPublicURL              flags.URL
	K8sModeOffClusterAlertmanager flags.URL
	K8sModeOffClusterEndpoint     flags.URL
	K8sModeOffClusterGitOps       flags.URL
	K8sModeOffClusterThanos       flags.URL
	K8sPublicEndpoint             flags.URL
	Listen                        flags.URL
	PrometheusPublicURL           flags.URL
	ThanosPublicURL               flags.URL

	// Slice flags
	I18nNamespaces       flags.Slice
	NodeArchitectures    flags.Slice
	NodeOperatingSystems flags.Slice

	// Map flags
	ConsolePluginsFlags flags.Map
	TelemetryFlags      flags.Map

	AuthOptions *AuthOptions
	Handler     *handler.Handler
	Server      *http.Server
}

type AuthOptions struct {
	AuthType                 flags.AuthType
	CAFile                   flags.File
	ClientID                 string
	ClientSecret             string
	ClientSecretFile         flags.File
	InactivityTimeoutSeconds int
	IssuerURL                flags.URL
	LogoutRedirect           flags.URL
}
