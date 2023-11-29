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
	if value == "" {
		*c = ""
		return nil
	}

	if !(value == string(configv1.SingleReplicaTopologyMode) ||
		value == string(configv1.HighlyAvailableTopologyMode) ||
		value == string(configv1.ExternalTopologyMode)) {
		return fmt.Errorf("ControlPlaneTopologyMode %s is not valid; valid options are External, HighlyAvailable, or SingleReplica", value)
	}

	*c = ControlPlaneTopology(value)
	return nil
}
