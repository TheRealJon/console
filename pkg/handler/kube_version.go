package handler

import (
	"errors"

	"k8s.io/client-go/discovery"
	"k8s.io/client-go/rest"
	"k8s.io/klog"
)

func (h *Handler) GetKubeVersion() string {
	if h.KubeVersion != "" {
		return h.KubeVersion
	}
	config := &rest.Config{
		Host:      h.K8sProxyConfig.Endpoint.String(),
		Transport: h.K8sClient.Transport,
	}

	kubeVersion, err := kubeVersion(config)
	if err != nil {
		kubeVersion = ""
		klog.Warningf("Failed to get cluster k8s version from api server %s", err.Error())
	}
	h.KubeVersion = kubeVersion
	return h.KubeVersion
}

func kubeVersion(config *rest.Config) (string, error) {
	client, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		return "", err
	}

	kubeVersion, err := client.ServerVersion()
	if err != nil {
		return "", err
	}

	if kubeVersion != nil {
		return kubeVersion.String(), nil
	}
	return "", errors.New("failed to get kubernetes version")
}
