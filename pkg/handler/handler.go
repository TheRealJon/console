package handler

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/coreos/pkg/health"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"k8s.io/klog"

	"github.com/openshift/console/pkg/api"
	"github.com/openshift/console/pkg/auth"
	devconsoleProxy "github.com/openshift/console/pkg/devconsole/proxy"
	"github.com/openshift/console/pkg/devfile"
	"github.com/openshift/console/pkg/graphql/resolver"
	helmhandlerspkg "github.com/openshift/console/pkg/helm/handlers"
	"github.com/openshift/console/pkg/knative"
	"github.com/openshift/console/pkg/metrics"
	"github.com/openshift/console/pkg/plugins"
	"github.com/openshift/console/pkg/proxy"
	"github.com/openshift/console/pkg/serverconfig"
	"github.com/openshift/console/pkg/serverutils"
	"github.com/openshift/console/pkg/terminal"
	"github.com/openshift/console/pkg/usage"
	"github.com/openshift/console/pkg/usersettings"
	"github.com/openshift/console/pkg/version"

	graphql "github.com/graph-gophers/graphql-go"
	"github.com/graph-gophers/graphql-go/relay"
	"github.com/rawagner/graphql-transport-ws/graphqlws"
)

// Public constants
const (
	AuthLoginCallbackEndpoint = "/auth/callback"
	AuthLoginErrorEndpoint    = "/auth/error"
	AuthLoginSuccessEndpoint  = "/"
)

// Private constants
const (
	accountManagementEndpoint             = "/api/accounts_mgmt/"
	alertManagerProxyEndpoint             = "/api/alertmanager"
	alertManagerTenancyProxyEndpoint      = "/api/alertmanager-tenancy"
	alertmanagerUserWorkloadProxyEndpoint = "/api/alertmanager-user-workload"
	authLoginEndpoint                     = "/auth/login"
	authLogoutEndpoint                    = "/auth/logout"
	customLogoEndpoint                    = "/custom-logo"
	deleteOpenshiftTokenEndpoint          = "/api/openshift/delete-token"
	devfileEndpoint                       = "/api/devfile/"
	devfileSamplesEndpoint                = "/api/devfile/samples/"
	gitopsEndpoint                        = "/api/gitops/"
	graphQLEndpoint                       = "/api/graphql"
	helmChartRepoProxyEndpoint            = "/api/helm/charts/"
	indexPageTemplateName                 = "index.html"
	k8sProxyEndpoint                      = "/api/kubernetes/"
	knativeProxyEndpoint                  = "/api/console/knative/"
	devConsoleEndpoint                    = "/api/dev-console/"
	localesEndpoint                       = "/locales/resource.json"
	operandsListEndpoint                  = "/api/list-operands/"
	pluginAssetsEndpoint                  = "/api/plugins/"
	pluginProxyEndpoint                   = "/api/proxy/"
	prometheusProxyEndpoint               = "/api/prometheus"
	prometheusTenancyProxyEndpoint        = "/api/prometheus-tenancy"
	requestTokenEndpoint                  = "/api/request-token"
	sha256Prefix                          = "sha256~"
	tokenizerPageTemplateName             = "tokener.html"
	updatesEndpoint                       = "/api/check-updates"
)

type jsGlobals struct {
	AddPage                         string            `json:"addPage"`
	AlertManagerBaseURL             string            `json:"alertManagerBaseURL"`
	AlertManagerPublicURL           string            `json:"alertManagerPublicURL"`
	AlertmanagerUserWorkloadBaseURL string            `json:"alertmanagerUserWorkloadBaseURL"`
	AuthDisabled                    bool              `json:"authDisabled"`
	BasePath                        string            `json:"basePath"`
	Branding                        string            `json:"branding"`
	ConsolePlugins                  []string          `json:"consolePlugins"`
	ConsoleVersion                  string            `json:"consoleVersion"`
	ControlPlaneTopology            string            `json:"controlPlaneTopology"`
	CopiedCSVsDisabled              bool              `json:"copiedCSVsDisabled"`
	CustomLogoURL                   string            `json:"customLogoURL"`
	CustomProductName               string            `json:"customProductName"`
	DevCatalogCategories            string            `json:"developerCatalogCategories"`
	DevCatalogTypes                 string            `json:"developerCatalogTypes"`
	DocumentationBaseURL            string            `json:"documentationBaseURL"`
	GOARCH                          string            `json:"GOARCH"`
	GOOS                            string            `json:"GOOS"`
	GrafanaPublicURL                string            `json:"grafanaPublicURL"`
	GraphQLBaseURL                  string            `json:"graphqlBaseURL"`
	I18nNamespaces                  []string          `json:"i18nNamespaces"`
	InactivityTimeout               int               `json:"inactivityTimeout"`
	KubeAdminLogoutURL              string            `json:"kubeAdminLogoutURL"`
	KubeAPIServerURL                string            `json:"kubeAPIServerURL"`
	LoadTestFactor                  int               `json:"loadTestFactor"`
	LoginErrorURL                   string            `json:"loginErrorURL"`
	LoginSuccessURL                 string            `json:"loginSuccessURL"`
	LoginURL                        string            `json:"loginURL"`
	LogoutRedirect                  string            `json:"logoutRedirect"`
	LogoutURL                       string            `json:"logoutURL"`
	NodeArchitectures               []string          `json:"nodeArchitectures"`
	NodeOperatingSystems            []string          `json:"nodeOperatingSystems"`
	Perspectives                    string            `json:"perspectives"`
	ProjectAccessClusterRoles       string            `json:"projectAccessClusterRoles"`
	PrometheusBaseURL               string            `json:"prometheusBaseURL"`
	PrometheusPublicURL             string            `json:"prometheusPublicURL"`
	PrometheusTenancyBaseURL        string            `json:"prometheusTenancyBaseURL"`
	QuickStarts                     string            `json:"quickStarts"`
	ReleaseVersion                  string            `json:"releaseVersion"`
	StatuspageID                    string            `json:"statuspageID"`
	Telemetry                       map[string]string `json:"telemetry"`
	ThanosPublicURL                 string            `json:"thanosPublicURL"`
	UserSettingsLocation            string            `json:"userSettingsLocation"`
	K8sMode                         string            `json:"k8sMode"`
}

type Handler struct {
	AddPage                             string
	AlertManagerProxyConfig             *proxy.Config
	AlertManagerPublicURL               *url.URL
	AlertManagerTenancyHost             string
	AlertManagerTenancyProxyConfig      *proxy.Config
	AlertManagerUserWorkloadHost        string
	AlertManagerUserWorkloadProxyConfig *proxy.Config
	Authenticator                       *auth.Authenticator
	BaseURL                             *url.URL
	Branding                            string
	ClusterManagementProxyConfig        *proxy.Config
	ControlPlaneTopology                string
	CopiedCSVsDisabled                  bool
	CustomLogoFile                      string
	CustomProductName                   string
	DevCatalogCategories                string
	DevCatalogTypes                     string
	DocumentationBaseURL                *url.URL
	EnabledConsolePlugins               map[string]string
	GitOpsProxyConfig                   *proxy.Config
	GOARCH                              string
	GOOS                                string
	GrafanaPublicURL                    *url.URL
	I18nNamespaces                      []string
	InactivityTimeout                   int
	K8sClient                           *http.Client
	K8sMode                             string
	K8sProxyConfig                      *proxy.Config
	KnativeChannelCRDLister             ResourceLister
	KnativeEventSourceCRDLister         ResourceLister
	KubeAPIServerURL                    string
	KubeVersion                         string
	LoadTestFactor                      int
	LogoutRedirect                      *url.URL
	MonitoringDashboardConfigMapLister  ResourceLister
	NodeArchitectures                   []string
	NodeOperatingSystems                []string
	Perspectives                        string
	PluginProxy                         string
	PluginsProxyTLSConfig               *tls.Config
	ProjectAccessClusterRoles           string
	PrometheusPublicURL                 *url.URL
	PublicDir                           string
	QuickStarts                         string
	ReleaseVersion                      string
	ServiceAccountToken                 string
	ServiceClient                       *http.Client
	StaticUser                          *auth.User
	StatuspageID                        string
	TectonicVersion                     string
	Telemetry                           map[string]string
	TerminalProxyTLSConfig              *tls.Config
	ThanosProxyConfig                   *proxy.Config
	ThanosPublicURL                     *url.URL
	ThanosTenancyProxyConfig            *proxy.Config
	ThanosTenancyProxyForRulesConfig    *proxy.Config
	UserSettingsLocation                string
}

func disableDirectoryListing(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If the request is for a directory, return a 404.
		// Directory path is expected to end with a slash or be empty,
		// since we are stripping the '/static/' prefix from the path.
		if strings.HasSuffix(r.URL.Path, "/") || r.URL.Path == "" {

			http.NotFound(w, r)
			return
		}
		handler.ServeHTTP(w, r)
	})
}

func (h *Handler) authDisabled() bool {
	return h.Authenticator == nil
}

func (h *Handler) prometheusProxyEnabled() bool {
	return h.ThanosProxyConfig != nil && h.ThanosTenancyProxyConfig != nil && h.ThanosTenancyProxyForRulesConfig != nil
}

func (h *Handler) alertManagerProxyEnabled() bool {
	return h.AlertManagerProxyConfig != nil && h.AlertManagerTenancyProxyConfig != nil
}

func (h *Handler) gitopsProxyEnabled() bool {
	return h.GitOpsProxyConfig != nil
}

func (h *Handler) HTTPHandler() http.Handler {
	mux := http.NewServeMux()
	k8sProxy := proxy.NewProxy(h.K8sProxyConfig)
	handle := func(path string, handler http.Handler) {
		mux.Handle(proxy.SingleJoiningSlash(h.BaseURL.Path, path), handler)
	}

	handleFunc := func(path string, handler http.HandlerFunc) { handle(path, handler) }

	fn := func(loginInfo auth.LoginJSON, successURL string, w http.ResponseWriter) {
		jsg := struct {
			auth.LoginJSON    `json:",inline"`
			LoginSuccessURL   string `json:"loginSuccessURL"`
			Branding          string `json:"branding"`
			CustomProductName string `json:"customProductName"`
		}{
			LoginJSON:         loginInfo,
			LoginSuccessURL:   successURL,
			Branding:          h.Branding,
			CustomProductName: h.CustomProductName,
		}

		tpl := template.New(tokenizerPageTemplateName)
		tpl.Delims("[[", "]]")
		tpls, err := tpl.ParseFiles(path.Join(h.PublicDir, tokenizerPageTemplateName))
		if err != nil {
			fmt.Printf("%v not found in configured public-dir path: %v", tokenizerPageTemplateName, err)
			os.Exit(1)
		}

		if err := tpls.ExecuteTemplate(w, tokenizerPageTemplateName, jsg); err != nil {
			fmt.Printf("%v", err)
			os.Exit(1)
		}
	}

	authHandler := func(hf http.HandlerFunc) http.HandlerFunc {
		return authMiddleware(h.Authenticator, hf)
	}

	authHandlerWithUser := func(hf HandlerWithUser) http.HandlerFunc {
		return authMiddlewareWithUser(h.Authenticator, hf)
	}

	if h.authDisabled() {
		authHandler = func(hf http.HandlerFunc) http.HandlerFunc {
			return hf
		}
		authHandlerWithUser = func(hf HandlerWithUser) http.HandlerFunc {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hf(h.StaticUser, w, r)
			})
		}
	}

	authHandlerWithHeader := func(h http.HandlerFunc) http.HandlerFunc {
		return authHandlerWithUser(func(u *auth.User, w http.ResponseWriter, r *http.Request) {
			r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", u.Token))
			h(w, r)
		})
	}

	if !h.authDisabled() {
		handleFunc(authLoginEndpoint, h.Authenticator.LoginFunc)
		handleFunc(authLogoutEndpoint, allowMethod(http.MethodPost, h.handleLogout))
		handleFunc(AuthLoginCallbackEndpoint, h.Authenticator.CallbackFunc(fn))
		handle(requestTokenEndpoint, authHandler(h.handleClusterTokenURL))
		handleFunc(deleteOpenshiftTokenEndpoint, allowMethod(http.MethodPost, authHandlerWithUser(h.handleOpenShiftTokenDeletion)))
	}

	handleFunc("/api/", notFoundHandler)

	staticHandler := http.StripPrefix(proxy.SingleJoiningSlash(h.BaseURL.Path, "/static/"), disableDirectoryListing(http.FileServer(http.Dir(h.PublicDir))))
	handle("/static/", gzipHandler(securityHeadersMiddleware(staticHandler)))

	if h.CustomLogoFile != "" {
		handleFunc(customLogoEndpoint, func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, h.CustomLogoFile)
		})
	}

	// Scope of Service Worker needs to be higher than the requests it is intercepting (https://stackoverflow.com/a/35780776/6909941)
	handleFunc("/load-test.sw.js", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, path.Join(h.PublicDir, "load-test.sw.js"))
	})

	handleFunc("/health", health.Checker{
		Checks: []health.Checkable{},
	}.ServeHTTP)

	handle(k8sProxyEndpoint, http.StripPrefix(
		proxy.SingleJoiningSlash(h.BaseURL.Path, k8sProxyEndpoint),
		authHandlerWithHeader(k8sProxy.ServeHTTP),
	))

	handleFunc(devfileEndpoint, devfile.DevfileHandler)
	handleFunc(devfileSamplesEndpoint, devfile.DevfileSamplesHandler)

	terminalProxy := terminal.NewProxy(
		h.TerminalProxyTLSConfig,
		h.K8sProxyConfig.TLSClientConfig,
		h.K8sProxyConfig.Endpoint)

	handle(terminal.ProxyEndpoint, authHandlerWithUser(terminalProxy.HandleProxy))
	handleFunc(terminal.AvailableEndpoint, terminalProxy.HandleProxyEnabled)
	handleFunc(terminal.InstalledNamespaceEndpoint, terminalProxy.HandleTerminalInstalledNamespace)

	graphQLSchema, err := ioutil.ReadFile("pkg/graphql/schema.graphql")
	if err != nil {
		panic(err)
	}
	opts := []graphql.SchemaOpt{graphql.UseFieldResolvers()}
	k8sResolver := resolver.K8sResolver{K8sProxy: k8sProxy}
	rootResolver := resolver.RootResolver{K8sResolver: &k8sResolver}
	schema := graphql.MustParseSchema(string(graphQLSchema), &rootResolver, opts...)
	handler := graphqlws.NewHandler()
	handler.InitPayload = resolver.InitPayload
	graphQLHandler := handler.NewHandlerFunc(schema, &relay.Handler{Schema: schema})
	handle("/api/graphql", authHandlerWithUser(func(user *auth.User, w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(context.Background(), resolver.HeadersKey, map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", user.Token),
		})
		graphQLHandler(w, r.WithContext(ctx))
	}))

	if h.prometheusProxyEnabled() {
		// Only proxy requests to the Prometheus API, not the UI.
		var (
			labelSourcePath             = prometheusProxyEndpoint + "/api/v1/label/"
			rulesSourcePath             = prometheusProxyEndpoint + "/api/v1/rules"
			querySourcePath             = prometheusProxyEndpoint + "/api/v1/query"
			queryRangeSourcePath        = prometheusProxyEndpoint + "/api/v1/query_range"
			targetsSourcePath           = prometheusProxyEndpoint + "/api/v1/targets"
			metadataSourcePath          = prometheusProxyEndpoint + "/api/v1/metadata"
			seriesSourcePath            = prometheusProxyEndpoint + "/api/v1/series"
			labelsSourcePath            = prometheusProxyEndpoint + "/api/v1/labels"
			targetAPIPath               = prometheusProxyEndpoint + "/api/"
			tenancyQuerySourcePath      = prometheusTenancyProxyEndpoint + "/api/v1/query"
			tenancyQueryRangeSourcePath = prometheusTenancyProxyEndpoint + "/api/v1/query_range"
			tenancyRulesSourcePath      = prometheusTenancyProxyEndpoint + "/api/v1/rules"
			tenancyTargetAPIPath        = prometheusTenancyProxyEndpoint + "/api/"
			thanosProxy                 = proxy.NewProxy(h.ThanosProxyConfig)
			thanosTenancyProxy          = proxy.NewProxy(h.ThanosTenancyProxyConfig)
			thanosTenancyForRulesProxy  = proxy.NewProxy(h.ThanosTenancyProxyForRulesConfig)
		)

		handleThanosRequest := http.StripPrefix(
			proxy.SingleJoiningSlash(h.BaseURL.Path, targetAPIPath),
			authHandlerWithHeader(thanosProxy.ServeHTTP),
		)

		handleThanosTenancyRequest := http.StripPrefix(
			proxy.SingleJoiningSlash(h.BaseURL.Path, tenancyTargetAPIPath),
			authHandlerWithHeader(thanosTenancyProxy.ServeHTTP),
		)

		handleThanosTenancyForRulesRequest := http.StripPrefix(
			proxy.SingleJoiningSlash(h.BaseURL.Path, tenancyTargetAPIPath),
			authHandlerWithHeader(thanosTenancyForRulesProxy.ServeHTTP))

		// global label, query, and query_range requests have to be proxied via thanos
		handle(querySourcePath, handleThanosRequest)
		handle(queryRangeSourcePath, handleThanosRequest)
		handle(labelSourcePath, handleThanosRequest)
		handle(targetsSourcePath, handleThanosRequest)
		handle(metadataSourcePath, handleThanosRequest)
		handle(seriesSourcePath, handleThanosRequest)
		handle(labelsSourcePath, handleThanosRequest)

		// alerting (rules) are being proxied via thanos querier
		// such that both in-cluster and user workload alerts appear in console.
		handle(rulesSourcePath, handleThanosRequest)

		// tenancy queries and query ranges have to be proxied via thanos
		handle(tenancyQuerySourcePath, handleThanosTenancyRequest)
		handle(tenancyQueryRangeSourcePath, handleThanosTenancyRequest)

		// tenancy rules have to be proxied via thanos
		handle(tenancyRulesSourcePath, handleThanosTenancyForRulesRequest)
	}

	if h.alertManagerProxyEnabled() {
		var (
			alertManagerProxyAPIPath             = alertManagerProxyEndpoint + "/api/"
			alertManagerUserWorkloadProxyAPIPath = alertmanagerUserWorkloadProxyEndpoint + "/api/"
			alertManagerTenancyProxyAPIPath      = alertManagerTenancyProxyEndpoint + "/api/"

			alertManagerProxy             = proxy.NewProxy(h.AlertManagerProxyConfig)
			alertManagerUserWorkloadProxy = proxy.NewProxy(h.AlertManagerUserWorkloadProxyConfig)
			alertManagerTenancyProxy      = proxy.NewProxy(h.AlertManagerTenancyProxyConfig)
		)

		handle(alertManagerProxyAPIPath, http.StripPrefix(
			proxy.SingleJoiningSlash(h.BaseURL.Path, alertManagerProxyAPIPath),
			authHandlerWithHeader(alertManagerProxy.ServeHTTP),
		))

		handle(alertManagerUserWorkloadProxyAPIPath, http.StripPrefix(
			proxy.SingleJoiningSlash(h.BaseURL.Path, alertManagerUserWorkloadProxyAPIPath),
			authHandlerWithHeader(alertManagerUserWorkloadProxy.ServeHTTP),
		))

		handle(alertManagerTenancyProxyAPIPath, http.StripPrefix(
			proxy.SingleJoiningSlash(h.BaseURL.Path, alertManagerTenancyProxyAPIPath),
			authHandlerWithHeader(alertManagerTenancyProxy.ServeHTTP),
		))
	}

	clusterManagementProxy := proxy.NewProxy(h.ClusterManagementProxyConfig)
	handle(accountManagementEndpoint, http.StripPrefix(
		h.BaseURL.Path,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clusterManagementProxy.ServeHTTP(w, r)
		})),
	)

	// List operator operands endpoint
	operandsListHandler := &OperandsListHandler{
		APIServerURL: h.KubeAPIServerURL,
		Client:       h.K8sClient,
	}

	handle(operandsListEndpoint, http.StripPrefix(
		proxy.SingleJoiningSlash(h.BaseURL.Path, operandsListEndpoint),
		authHandlerWithUser(func(user *auth.User, w http.ResponseWriter, r *http.Request) {
			operandsListHandler.OperandsListHandler(user, w, r)
		}),
	))

	handle("/api/console/monitoring-dashboard-config", authHandler(h.handleMonitoringDashboardConfigmaps))
	// Knative
	trimURLPrefix := proxy.SingleJoiningSlash(h.BaseURL.Path, knativeProxyEndpoint)
	knativeHandler := knative.NewKnativeHandler(trimURLPrefix,
		h.K8sClient,
		h.K8sProxyConfig.Endpoint.String())
	handle(knativeProxyEndpoint, authHandlerWithUser(knativeHandler.Handle))
	// TODO: move the knative-event-sources and knative-channels handler into the knative module.
	handle("/api/console/knative-event-sources", authHandler(h.handleKnativeEventSourceCRDs))
	handle("/api/console/knative-channels", authHandler(h.handleKnativeChannelCRDs))

	// Dev-Console Proxy
	handle(devConsoleEndpoint, http.StripPrefix(
		proxy.SingleJoiningSlash(h.BaseURL.Path, devConsoleEndpoint),
		authHandlerWithUser(func(user *auth.User, w http.ResponseWriter, r *http.Request) {
			devconsoleProxy.Handler(w, r)
		})),
	)

	// User settings
	userSettingHandler := usersettings.UserSettingsHandler{
		Client:              h.K8sClient,
		Endpoint:            h.K8sProxyConfig.Endpoint.String(),
		ServiceAccountToken: h.ServiceAccountToken,
	}
	handle("/api/console/user-settings", authHandlerWithUser(userSettingHandler.HandleUserSettings))

	// Helm
	helmHandlers := helmhandlerspkg.New(h.K8sProxyConfig.Endpoint.String(), h.K8sClient.Transport, h)
	verifierHandler := helmhandlerspkg.NewVerifierHandler(h.K8sProxyConfig.Endpoint.String(), h.K8sClient.Transport, h)
	handle("/api/helm/verify", authHandlerWithUser(func(user *auth.User, w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			verifierHandler.HandleChartVerifier(user, w, r)
		default:
			w.Header().Set("Allow", "POST")
			serverutils.SendResponse(w, http.StatusMethodNotAllowed, serverutils.ApiError{Err: "Unsupported method, supported methods are POST"})
		}
	}))

	// Plugins
	pluginsHandler := plugins.NewPluginsHandler(
		&http.Client{
			// 120 seconds matches the webpack require timeout.
			// Plugins are loaded asynchronously, so this doesn't block page load.
			Timeout:   120 * time.Second,
			Transport: &http.Transport{TLSClientConfig: h.PluginsProxyTLSConfig},
		},
		h.EnabledConsolePlugins,
		h.PublicDir,
	)

	handleFunc(localesEndpoint, func(w http.ResponseWriter, r *http.Request) {
		pluginsHandler.HandleI18nResources(w, r)
	})

	handle(pluginAssetsEndpoint, http.StripPrefix(
		proxy.SingleJoiningSlash(h.BaseURL.Path, pluginAssetsEndpoint),
		authHandler(func(w http.ResponseWriter, r *http.Request) {
			pluginsHandler.HandlePluginAssets(w, r)
		}),
	))

	if len(h.PluginProxy) != 0 {
		proxyConfig, err := plugins.ParsePluginProxyConfig(h.PluginProxy)
		if err != nil {
			klog.Fatalf("Error parsing plugin proxy config: %s", err)
			os.Exit(1)
		}
		proxyServiceHandlers, err := plugins.GetPluginProxyServiceHandlers(proxyConfig, h.PluginsProxyTLSConfig, pluginProxyEndpoint)
		if err != nil {
			klog.Fatalf("Error getting plugin proxy handlers: %s", err)
			os.Exit(1)
		}
		if len(proxyServiceHandlers) != 0 {
			klog.Infoln("The following console endpoints are now proxied to these services:")
		}
		for _, proxyServiceHandler := range proxyServiceHandlers {
			klog.Infof(" - %s -> %s\n", proxyServiceHandler.ConsoleEndpoint, proxyServiceHandler.ProxyConfig.Endpoint)
			serviceProxy := proxy.NewProxy(proxyServiceHandler.ProxyConfig)
			f := func(w http.ResponseWriter, r *http.Request) {
				serviceProxy.ServeHTTP(w, r)
			}
			var handler http.Handler
			if proxyServiceHandler.Authorize {
				handler = authHandler(f)
			} else {
				handler = http.HandlerFunc(f)
			}
			handle(proxyServiceHandler.ConsoleEndpoint, http.StripPrefix(
				proxy.SingleJoiningSlash(h.BaseURL.Path, proxyServiceHandler.ConsoleEndpoint),
				handler,
			))
		}
	}

	handle(updatesEndpoint, authHandler(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.Header().Set("Allow", "GET")
			serverutils.SendResponse(w, http.StatusMethodNotAllowed, serverutils.ApiError{Err: "Method unsupported, the only supported methods is GET"})
			return
		}
		serverutils.SendResponse(w, http.StatusOK, struct {
			ConsoleCommit string   `json:"consoleCommit"`
			Plugins       []string `json:"plugins"`
		}{
			ConsoleCommit: os.Getenv("SOURCE_GIT_COMMIT"),
			Plugins:       pluginsHandler.GetPluginsList(),
		})
	}))

	// Metrics
	config := &api.Config{
		Plugins: h.EnabledConsolePlugins,
		Customization: api.Customization{
			Perspectives: []api.Perspective{},
		},
	}
	if len(h.Perspectives) > 0 {
		err := json.Unmarshal([]byte(h.Perspectives), &config.Customization.Perspectives)
		if err != nil {
			klog.Errorf("Unable to parse perspective JSON: %v", err)
		}
	}
	serverconfigMetrics := serverconfig.NewMetrics(config)
	serverconfigMetrics.MonitorPlugins(
		h.K8sClient,
		h.K8sProxyConfig.Endpoint.String(),
		h.ServiceAccountToken,
	)
	usageMetrics := usage.NewMetrics()
	usageMetrics.MonitorUsers(
		h.K8sClient,
		h.K8sProxyConfig.Endpoint.String(),
		h.ServiceAccountToken,
	)
	prometheus.MustRegister(serverconfigMetrics.GetCollectors()...)
	prometheus.MustRegister(usageMetrics.GetCollectors()...)
	handle("/metrics", metrics.AddHeaderAsCookieMiddleware(
		authHandler(func(w http.ResponseWriter, r *http.Request) {
			promhttp.Handler().ServeHTTP(w, r)
		}),
	))
	handleFunc("/metrics/usage", func(w http.ResponseWriter, r *http.Request) {
		usage.Handle(usageMetrics, w, r)
	})

	handle("/api/helm/template", authHandlerWithUser(helmHandlers.HandleHelmRenderManifests))
	handle("/api/helm/releases", authHandlerWithUser(helmHandlers.HandleHelmList))
	handle("/api/helm/chart", authHandlerWithUser(helmHandlers.HandleChartGet))
	handle("/api/helm/release/history", authHandlerWithUser(helmHandlers.HandleGetReleaseHistory))
	handle("/api/helm/charts/index.yaml", authHandlerWithUser(helmHandlers.HandleIndexFile))

	handle("/api/helm/release", authHandlerWithUser(func(user *auth.User, w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			helmHandlers.HandleGetRelease(user, w, r)
		case http.MethodPost:
			helmHandlers.HandleHelmInstall(user, w, r)
		case http.MethodDelete:
			helmHandlers.HandleUninstallRelease(user, w, r)
		case http.MethodPatch:
			helmHandlers.HandleRollbackRelease(user, w, r)
		case http.MethodPut:
			helmHandlers.HandleUpgradeRelease(user, w, r)
		default:
			w.Header().Set("Allow", "GET, POST, PATCH, PUT, DELETE")
			serverutils.SendResponse(w, http.StatusMethodNotAllowed, serverutils.ApiError{Err: "Unsupported method, supported methods are GET, POST, PATCH, PUT, DELETE"})
		}
	}))

	handle("/api/helm/release/async", authHandlerWithUser(func(user *auth.User, w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			helmHandlers.HandleHelmInstallAsync(user, w, r)
		case http.MethodPut:
			helmHandlers.HandleUpgradeReleaseAsync(user, w, r)
		case http.MethodDelete:
			helmHandlers.HandleUninstallReleaseAsync(user, w, r)
		default:
			w.Header().Set("Allow", "POST, PUT , DELETE")
			serverutils.SendResponse(w, http.StatusMethodNotAllowed, serverutils.ApiError{Err: "Unsupported method, supported methods are POST, PUT , DELETE"})
		}
	}))

	// GitOps proxy endpoints
	if h.gitopsProxyEnabled() {
		gitopsProxy := proxy.NewProxy(h.GitOpsProxyConfig)
		handle(gitopsEndpoint, http.StripPrefix(
			proxy.SingleJoiningSlash(h.BaseURL.Path, gitopsEndpoint),
			authHandlerWithHeader(gitopsProxy.ServeHTTP),
		))
	}

	handle("/api/console/version", authHandler(h.versionHandler))

	mux.HandleFunc(h.BaseURL.Path, h.indexHandler)

	return securityHeadersMiddleware(http.Handler(mux))
}

func (h *Handler) handleMonitoringDashboardConfigmaps(w http.ResponseWriter, r *http.Request) {
	h.MonitoringDashboardConfigMapLister.HandleResources(w, r)
}

func (h *Handler) handleKnativeEventSourceCRDs(w http.ResponseWriter, r *http.Request) {
	h.KnativeEventSourceCRDLister.HandleResources(w, r)
}

func (h *Handler) handleKnativeChannelCRDs(w http.ResponseWriter, r *http.Request) {
	h.KnativeChannelCRDLister.HandleResources(w, r)
}

func (h *Handler) indexHandler(w http.ResponseWriter, r *http.Request) {
	if serverutils.IsUnsupportedBrowser(r) {
		serverutils.SendUnsupportedBrowserResponse(w, h.Branding)
		return
	}

	plugins := make([]string, 0, len(h.EnabledConsolePlugins))
	for plugin := range h.EnabledConsolePlugins {
		plugins = append(plugins, plugin)
	}

	jsg := &jsGlobals{
		ConsoleVersion:            version.Version,
		AuthDisabled:              h.authDisabled(),
		BasePath:                  h.BaseURL.Path,
		LoginURL:                  proxy.SingleJoiningSlash(h.BaseURL.String(), authLoginEndpoint),
		LoginSuccessURL:           proxy.SingleJoiningSlash(h.BaseURL.String(), AuthLoginSuccessEndpoint),
		LoginErrorURL:             proxy.SingleJoiningSlash(h.BaseURL.String(), AuthLoginErrorEndpoint),
		LogoutURL:                 proxy.SingleJoiningSlash(h.BaseURL.String(), authLogoutEndpoint),
		KubeAPIServerURL:          h.KubeAPIServerURL,
		Branding:                  h.Branding,
		CustomProductName:         h.CustomProductName,
		ControlPlaneTopology:      h.ControlPlaneTopology,
		StatuspageID:              h.StatuspageID,
		InactivityTimeout:         h.InactivityTimeout,
		DocumentationBaseURL:      h.DocumentationBaseURL.String(),
		AlertManagerPublicURL:     h.AlertManagerPublicURL.String(),
		GrafanaPublicURL:          h.GrafanaPublicURL.String(),
		PrometheusPublicURL:       h.PrometheusPublicURL.String(),
		ThanosPublicURL:           h.ThanosPublicURL.String(),
		GOARCH:                    h.GOARCH,
		GOOS:                      h.GOOS,
		LoadTestFactor:            h.LoadTestFactor,
		GraphQLBaseURL:            proxy.SingleJoiningSlash(h.BaseURL.Path, graphQLEndpoint),
		DevCatalogCategories:      h.DevCatalogCategories,
		DevCatalogTypes:           h.DevCatalogTypes,
		UserSettingsLocation:      h.UserSettingsLocation,
		ConsolePlugins:            plugins,
		I18nNamespaces:            h.I18nNamespaces,
		QuickStarts:               h.QuickStarts,
		AddPage:                   h.AddPage,
		ProjectAccessClusterRoles: h.ProjectAccessClusterRoles,
		Perspectives:              h.Perspectives,
		Telemetry:                 h.Telemetry,
		ReleaseVersion:            h.ReleaseVersion,
		NodeArchitectures:         h.NodeArchitectures,
		NodeOperatingSystems:      h.NodeOperatingSystems,
		CopiedCSVsDisabled:        h.CopiedCSVsDisabled,
		K8sMode:                   h.K8sMode,
	}

	if h.LogoutRedirect != nil {
		jsg.LogoutRedirect = h.LogoutRedirect.String()
	}

	if !h.authDisabled() {
		specialAuthURLs := h.Authenticator.GetSpecialURLs()
		jsg.KubeAdminLogoutURL = specialAuthURLs.KubeAdminLogout
	}

	if h.prometheusProxyEnabled() {
		jsg.PrometheusBaseURL = proxy.SingleJoiningSlash(h.BaseURL.Path, prometheusProxyEndpoint)
		jsg.PrometheusTenancyBaseURL = proxy.SingleJoiningSlash(h.BaseURL.Path, prometheusTenancyProxyEndpoint)
	}

	if h.alertManagerProxyEnabled() {
		jsg.AlertManagerBaseURL = proxy.SingleJoiningSlash(h.BaseURL.Path, alertManagerProxyEndpoint)
		jsg.AlertmanagerUserWorkloadBaseURL = proxy.SingleJoiningSlash(h.BaseURL.Path, alertmanagerUserWorkloadProxyEndpoint)
	}

	if !h.authDisabled() {
		h.Authenticator.SetCSRFCookie(h.BaseURL.Path, &w)
	}

	if h.CustomLogoFile != "" {
		jsg.CustomLogoURL = proxy.SingleJoiningSlash(h.BaseURL.Path, customLogoEndpoint)
	}

	tpl := template.New(indexPageTemplateName)
	tpl.Delims("[[", "]]")
	tpls, err := tpl.ParseFiles(path.Join(h.PublicDir, indexPageTemplateName))
	if err != nil {
		fmt.Printf("index.html not found in configured public-dir path: %v", err)
		os.Exit(1)
	}

	if err := tpls.ExecuteTemplate(w, indexPageTemplateName, jsg); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *Handler) versionHandler(w http.ResponseWriter, r *http.Request) {
	serverutils.SendResponse(w, http.StatusOK, struct {
		Version string `json:"version"`
	}{
		Version: version.Version,
	})
}

func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte("not found"))
}

func (h *Handler) handleClusterTokenURL(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		serverutils.SendResponse(w, http.StatusMethodNotAllowed, serverutils.ApiError{Err: "Invalid method: only GET is allowed"})
		return
	}
	requestTokenURL := h.Authenticator.GetSpecialURLs().RequestToken
	serverutils.SendResponse(w, http.StatusOK, struct {
		RequestTokenURL string `json:"requestTokenURL"`
	}{
		RequestTokenURL: requestTokenURL,
	})
}

func (h *Handler) handleOpenShiftTokenDeletion(user *auth.User, w http.ResponseWriter, r *http.Request) {
	tokenName := user.Token
	if strings.HasPrefix(tokenName, sha256Prefix) {
		tokenName = tokenToObjectName(tokenName)
	}

	path := "/apis/oauth.openshift.io/v1/oauthaccesstokens/" + tokenName
	// Delete the OpenShift OAuthAccessToken.
	url := proxy.SingleJoiningSlash(h.K8sProxyConfig.Endpoint.String(), path)
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		serverutils.SendResponse(w, http.StatusInternalServerError, serverutils.ApiError{Err: fmt.Sprintf("Failed to create token DELETE request: %v", err)})
		return
	}

	r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", user.Token))
	resp, err := h.K8sClient.Do(req)
	if err != nil {
		serverutils.SendResponse(w, http.StatusBadGateway, serverutils.ApiError{Err: fmt.Sprintf("Failed to delete token: %v", err)})
		return
	}
	h.Authenticator.DeleteCookie(w, r)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
	resp.Body.Close()
}

func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	verifyCSRF(h.Authenticator, h.Authenticator.LogoutFunc).ServeHTTP(w, r)
}

// tokenToObjectName returns the oauthaccesstokens object name for the given raw token,
// i.e. the sha256 hash prefixed with "sha256~".
// TODO this should be a member function of the User type
func tokenToObjectName(token string) string {
	name := strings.TrimPrefix(token, sha256Prefix)
	hash := sha256.Sum256([]byte(name))
	return sha256Prefix + base64.RawURLEncoding.EncodeToString(hash[0:])
}
