package flags

import (
	"fmt"

	configv1 "github.com/openshift/api/config/v1"
)

type ControlPlaneTopology configv1.TopologyMode

func (c ControlPlaneTopology) String() string {
	return string(c)
}

func (c *ControlPlaneTopology) Set(value string) error {
	switch value {
	case string(configv1.SingleReplicaTopologyMode):
	case string(configv1.HighlyAvailableTopologyMode):
	case string(configv1.ExternalTopologyMode):
	default:
		return fmt.Errorf("ControlPlaneTopologyMode %s is not valid; valid options are External, HighlyAvailable, or SingleReplica", value)
	}

	*c = ControlPlaneTopology(value)
	return nil
}
