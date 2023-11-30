package bridge

import (
	"net/http"
	"net/url"

	"github.com/openshift/console/pkg/flags"
	"github.com/openshift/console/pkg/handler"
	"github.com/openshift/console/pkg/knative"
)

func (b *Bridge) applyMonitoringDashboardLister() {
	monitoringDashboardHttpClientTransport := &http.Transport{
		TLSClientConfig: b.Handler.K8sProxyConfig.TLSClientConfig,
	}
	if b.K8sMode == flags.K8sModeInCluster {
		monitoringDashboardHttpClientTransport.Proxy = http.ProxyFromEnvironment
	}
	b.Handler.MonitoringDashboardConfigMapLister = handler.NewResourceLister(
		b.Handler.ServiceAccountToken,
		&url.URL{
			Scheme: b.Handler.K8sProxyConfig.Endpoint.Scheme,
			Host:   b.Handler.K8sProxyConfig.Endpoint.Host,
			Path:   b.Handler.K8sProxyConfig.Endpoint.Path + "/api/v1/namespaces/openshift-config-managed/configmaps",
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
	b.Handler.KnativeEventSourceCRDLister = handler.NewResourceLister(
		b.Handler.ServiceAccountToken,
		&url.URL{
			Scheme: b.Handler.K8sProxyConfig.Endpoint.Scheme,
			Host:   b.Handler.K8sProxyConfig.Endpoint.Host,
			Path:   b.Handler.K8sProxyConfig.Endpoint.Path + "/apis/apiextensions.k8s.io/v1/customresourcedefinitions",
			RawQuery: url.Values{
				"labelSelector": {"duck.knative.dev/source=true"},
			}.Encode(),
		},
		&http.Client{
			Transport: &http.Transport{
				TLSClientConfig: b.Handler.K8sProxyConfig.TLSClientConfig,
			},
		},
		knative.EventSourceFilter,
	)
}

func (b *Bridge) applyKnativeChannelCRDLister() {
	b.Handler.KnativeChannelCRDLister = handler.NewResourceLister(
		b.Handler.ServiceAccountToken,
		&url.URL{
			Scheme: b.Handler.K8sProxyConfig.Endpoint.Scheme,
			Host:   b.Handler.K8sProxyConfig.Endpoint.Host,
			Path:   b.Handler.K8sProxyConfig.Endpoint.Path + "/apis/apiextensions.k8s.io/v1/customresourcedefinitions",
			RawQuery: url.Values{
				"labelSelector": {"duck.knative.dev/addressable=true,messaging.knative.dev/subscribable=true"},
			}.Encode(),
		},
		&http.Client{
			Transport: &http.Transport{
				TLSClientConfig: b.Handler.K8sProxyConfig.TLSClientConfig,
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
