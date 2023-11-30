package bridge

import "net/url"

const (
	k8sInClusterCA          = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	k8sInClusterBearerToken = "/var/run/secrets/kubernetes.io/serviceaccount/token"

	// Well-known location of the tenant aware Thanos service for OpenShift exposing the query and query_range endpoints. This is only accessible in-cluster.
	// Thanos proxies requests to both cluster monitoring and user workload monitoring prometheus instances.
	openshiftThanosTenancyHost = "thanos-querier.openshift-monitoring.svc:9092"

	// Well-known location of the tenant aware Thanos service for OpenShift exposing the rules endpoint. This is only accessible in-cluster.
	// Thanos proxies requests to the cluster monitoring and user workload monitoring prometheus instances as well as Thanos ruler instances.
	openshiftThanosTenancyForRulesHost = "thanos-querier.openshift-monitoring.svc:9093"

	// Well-known location of the Thanos service for OpenShift. This is only accessible in-cluster.
	// This is used for non-tenant global query requests
	// proxying to both cluster monitoring and user workload monitoring prometheus instances.
	openshiftThanosHost = "thanos-querier.openshift-monitoring.svc:9091"

	// Well-known location of Alert Manager service for OpenShift. This is only accessible in-cluster.
	openshiftAlertManagerHost = "alertmanager-main.openshift-monitoring.svc:9094"

	// Default location of the tenant aware Alert Manager service for OpenShift. This is only accessible in-cluster.
	openshiftAlertManagerTenancyHost = "alertmanager-main.openshift-monitoring.svc:9092"

	// Well-known location of the GitOps service. This is only accessible in-cluster
	openshiftGitOpsHost = "cluster.openshift-gitops.svc:8080"

	// Well-known location of the cluster proxy service. This is only accessible in-cluster
	openshiftClusterProxyHost = "cluster-proxy-addon-user.multicluster-engine.svc:9092"

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
	inClusterK8sEndpoint                   = &url.URL{Scheme: "https", Host: "kubernetes.default.svc"}
	inClusterThanosEndpoint                = &url.URL{Scheme: "https", Host: openshiftThanosHost, Path: "/api"}
	inClusterThanosTenancyEndpoint         = &url.URL{Scheme: "https", Host: openshiftThanosTenancyHost, Path: "/api"}
	inClusterThanosTenancyForRulesEndpoint = &url.URL{Scheme: "https", Host: openshiftThanosTenancyForRulesHost, Path: "/api"}
	inClusterAlertManagerEndpoint          = &url.URL{Scheme: "https", Host: openshiftAlertManagerHost, Path: "/api"}
	inClusterGitOpsEndpoint                = &url.URL{Scheme: "https", Host: openshiftGitOpsHost}
)
