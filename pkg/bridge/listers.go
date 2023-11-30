package bridge

import (
	"net/http"
	"net/url"

	"github.com/openshift/console/pkg/flags"
	"github.com/openshift/console/pkg/knative"
	"github.com/openshift/console/pkg/server"
)

func (b *Bridge) applyMonitoringDashboardLister() {
	monitoringDashboardHttpClientTransport := &http.Transport{
		TLSClientConfig: b.Server.K8sProxyConfig.TLSClientConfig,
	}
	if b.K8sMode == flags.K8sModeInCluster {
		monitoringDashboardHttpClientTransport.Proxy = http.ProxyFromEnvironment
	}
	b.Server.MonitoringDashboardConfigMapLister = server.NewResourceLister(
		b.Server.ServiceAccountToken,
		&url.URL{
			Scheme: b.Server.K8sProxyConfig.Endpoint.Scheme,
			Host:   b.Server.K8sProxyConfig.Endpoint.Host,
			Path:   b.Server.K8sProxyConfig.Endpoint.Path + "/api/v1/namespaces/openshift-config-managed/configmaps",
			RawQuery: url.Values{
				"labelSelector": {"console.openshift.io/dashboard=true"},
			}.Encode(),
		},
		&http.Client{
			Transport: monitoringDashboardHttpClientTransport,
		},
		nil,
	)
}

func (b *Bridge) applyKnativeEventSourceLister() {
	b.Server.KnativeEventSourceCRDLister = server.NewResourceLister(
		b.Server.ServiceAccountToken,
		&url.URL{
			Scheme: b.Server.K8sProxyConfig.Endpoint.Scheme,
			Host:   b.Server.K8sProxyConfig.Endpoint.Host,
			Path:   b.Server.K8sProxyConfig.Endpoint.Path + "/apis/apiextensions.k8s.io/v1/customresourcedefinitions",
			RawQuery: url.Values{
				"labelSelector": {"duck.knative.dev/source=true"},
			}.Encode(),
		},
		&http.Client{
			Transport: &http.Transport{
				TLSClientConfig: b.Server.K8sProxyConfig.TLSClientConfig,
			},
		},
		knative.EventSourceFilter,
	)
}

func (b *Bridge) applyKnativeChannelCRDLister() {
	b.Server.KnativeChannelCRDLister = server.NewResourceLister(
		b.Server.ServiceAccountToken,
		&url.URL{
			Scheme: b.Server.K8sProxyConfig.Endpoint.Scheme,
			Host:   b.Server.K8sProxyConfig.Endpoint.Host,
			Path:   b.Server.K8sProxyConfig.Endpoint.Path + "/apis/apiextensions.k8s.io/v1/customresourcedefinitions",
			RawQuery: url.Values{
				"labelSelector": {"duck.knative.dev/addressable=true,messaging.knative.dev/subscribable=true"},
			}.Encode(),
		},
		&http.Client{
			Transport: &http.Transport{
				TLSClientConfig: b.Server.K8sProxyConfig.TLSClientConfig,
			},
		},
		knative.ChannelFilter,
	)
}

func (b *Bridge) applyListers() {
	b.applyMonitoringDashboardLister()
	b.applyKnativeEventSourceLister()
	b.applyKnativeChannelCRDLister()
}
