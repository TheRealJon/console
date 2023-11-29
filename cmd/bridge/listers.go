package main

import (
	"net/http"
	"net/url"

	"github.com/openshift/console/pkg/flags"
	"github.com/openshift/console/pkg/knative"
	"github.com/openshift/console/pkg/server"
)

func applyMonitoringDashboardLister(srv *server.Server) {
	monitoringDashboardHttpClientTransport := &http.Transport{
		TLSClientConfig: srv.K8sProxyConfig.TLSClientConfig,
	}
	if k8sMode == flags.K8sModeInCluster {
		monitoringDashboardHttpClientTransport.Proxy = http.ProxyFromEnvironment
	}
	srv.MonitoringDashboardConfigMapLister = server.NewResourceLister(
		srv.ServiceAccountToken,
		&url.URL{
			Scheme: srv.K8sProxyConfig.Endpoint.Scheme,
			Host:   srv.K8sProxyConfig.Endpoint.Host,
			Path:   srv.K8sProxyConfig.Endpoint.Path + "/api/v1/namespaces/openshift-config-managed/configmaps",
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

func applyKnativeEventSourceLister(srv *server.Server) {
	srv.KnativeEventSourceCRDLister = server.NewResourceLister(
		srv.ServiceAccountToken,
		&url.URL{
			Scheme: srv.K8sProxyConfig.Endpoint.Scheme,
			Host:   srv.K8sProxyConfig.Endpoint.Host,
			Path:   srv.K8sProxyConfig.Endpoint.Path + "/apis/apiextensions.k8s.io/v1/customresourcedefinitions",
			RawQuery: url.Values{
				"labelSelector": {"duck.knative.dev/source=true"},
			}.Encode(),
		},
		&http.Client{
			Transport: &http.Transport{
				TLSClientConfig: srv.K8sProxyConfig.TLSClientConfig,
			},
		},
		knative.EventSourceFilter,
	)
}

func applyKnativeChannelCRDLister(srv *server.Server) {
	srv.KnativeChannelCRDLister = server.NewResourceLister(
		srv.ServiceAccountToken,
		&url.URL{
			Scheme: srv.K8sProxyConfig.Endpoint.Scheme,
			Host:   srv.K8sProxyConfig.Endpoint.Host,
			Path:   srv.K8sProxyConfig.Endpoint.Path + "/apis/apiextensions.k8s.io/v1/customresourcedefinitions",
			RawQuery: url.Values{
				"labelSelector": {"duck.knative.dev/addressable=true,messaging.knative.dev/subscribable=true"},
			}.Encode(),
		},
		&http.Client{
			Transport: &http.Transport{
				TLSClientConfig: srv.K8sProxyConfig.TLSClientConfig,
			},
		},
		knative.ChannelFilter,
	)
}

func applyListers(srv *server.Server) {
	applyMonitoringDashboardLister(srv)
	applyKnativeEventSourceLister(srv)
	applyKnativeChannelCRDLister(srv)
}
