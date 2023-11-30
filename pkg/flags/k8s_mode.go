package flags

import "fmt"

type K8sMode string

const (
	K8sModeInCluster  K8sMode = "in-cluster"
	K8sModeOffCluster K8sMode = "off-cluster"
)

func (k K8sMode) String() string {
	return string(k)
}

func (k *K8sMode) Set(value string) error {
	switch value {
	case string(K8sModeInCluster):
	case string(K8sModeOffCluster):
	default:
		return fmt.Errorf("K8sMode %s is not valid; valid options are in-cluster or off-cluster", value)
	}
	*k = K8sMode(value)
	return nil
}
